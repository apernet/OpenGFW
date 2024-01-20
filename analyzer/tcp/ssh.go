package tcp

import (
	"strings"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

var _ analyzer.TCPAnalyzer = (*SSHAnalyzer)(nil)

type SSHAnalyzer struct{}

func (a *SSHAnalyzer) Name() string {
	return "ssh"
}

func (a *SSHAnalyzer) Limit() int {
	return 1024
}

func (a *SSHAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return newSSHStream(logger)
}

type sshStream struct {
	logger analyzer.Logger

	clientBuf     *utils.ByteBuffer
	clientMap     analyzer.PropMap
	clientUpdated bool
	clientLSM     *utils.LinearStateMachine
	clientDone    bool

	serverBuf     *utils.ByteBuffer
	serverMap     analyzer.PropMap
	serverUpdated bool
	serverLSM     *utils.LinearStateMachine
	serverDone    bool
}

func newSSHStream(logger analyzer.Logger) *sshStream {
	s := &sshStream{logger: logger, clientBuf: &utils.ByteBuffer{}, serverBuf: &utils.ByteBuffer{}}
	s.clientLSM = utils.NewLinearStateMachine(
		s.parseClientExchangeLine,
	)
	s.serverLSM = utils.NewLinearStateMachine(
		s.parseServerExchangeLine,
	)
	return s
}

func (s *sshStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
	if skip != 0 {
		return nil, true
	}
	if len(data) == 0 {
		return nil, false
	}
	var update *analyzer.PropUpdate
	var cancelled bool
	if rev {
		s.serverBuf.Append(data)
		s.serverUpdated = false
		cancelled, s.serverDone = s.serverLSM.Run()
		if s.serverUpdated {
			update = &analyzer.PropUpdate{
				Type: analyzer.PropUpdateMerge,
				M:    analyzer.PropMap{"server": s.serverMap},
			}
			s.serverUpdated = false
		}
	} else {
		s.clientBuf.Append(data)
		s.clientUpdated = false
		cancelled, s.clientDone = s.clientLSM.Run()
		if s.clientUpdated {
			update = &analyzer.PropUpdate{
				Type: analyzer.PropUpdateMerge,
				M:    analyzer.PropMap{"client": s.clientMap},
			}
			s.clientUpdated = false
		}
	}
	return update, cancelled || (s.clientDone && s.serverDone)
}

// parseExchangeLine parses the SSH Protocol Version Exchange string.
// See RFC 4253, section 4.2.
// "SSH-protoversion-softwareversion SP comments CR LF"
// The "comments" part (along with the SP) is optional.
func (s *sshStream) parseExchangeLine(buf *utils.ByteBuffer) (utils.LSMAction, analyzer.PropMap) {
	// Find the end of the line
	line, ok := buf.GetUntil([]byte("\r\n"), true, true)
	if !ok {
		// No end of line yet, but maybe we just need more data
		return utils.LSMActionPause, nil
	}
	if !strings.HasPrefix(string(line), "SSH-") {
		// Not SSH
		return utils.LSMActionCancel, nil
	}
	fields := strings.Fields(string(line[:len(line)-2])) // Strip \r\n
	if len(fields) < 1 || len(fields) > 2 {
		// Invalid line
		return utils.LSMActionCancel, nil
	}
	sshFields := strings.SplitN(fields[0], "-", 3)
	if len(sshFields) != 3 {
		// Invalid SSH version format
		return utils.LSMActionCancel, nil
	}
	sMap := analyzer.PropMap{
		"protocol": sshFields[1],
		"software": sshFields[2],
	}
	if len(fields) == 2 {
		sMap["comments"] = fields[1]
	}
	return utils.LSMActionNext, sMap
}

func (s *sshStream) parseClientExchangeLine() utils.LSMAction {
	action, sMap := s.parseExchangeLine(s.clientBuf)
	if action == utils.LSMActionNext {
		s.clientMap = sMap
		s.clientUpdated = true
	}
	return action
}

func (s *sshStream) parseServerExchangeLine() utils.LSMAction {
	action, sMap := s.parseExchangeLine(s.serverBuf)
	if action == utils.LSMActionNext {
		s.serverMap = sMap
		s.serverUpdated = true
	}
	return action
}

func (s *sshStream) Close(limited bool) *analyzer.PropUpdate {
	s.clientBuf.Reset()
	s.serverBuf.Reset()
	s.clientMap = nil
	s.serverMap = nil
	return nil
}
