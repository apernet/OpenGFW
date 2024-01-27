package tcp

import (
	"net"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

const (
	Socks4Version = 0x04
	Socks4ReplyVN = 0x00

	Socks4CmdTCPConnect = 0x01
	Socks4CmdTCPBind    = 0x02

	Socks4ReqGranted        = 0x5A
	Socks4ReqRejectOrFailed = 0x5B
	Socks4ReqRejectIdentd   = 0x5C
	Socks4ReqRejectUser     = 0x5D
)

var _ analyzer.Analyzer = (*Socks4Analyzer)(nil)

type Socks4Analyzer struct{}

func (a *Socks4Analyzer) Name() string {
	return "socks4"
}

func (a *Socks4Analyzer) Limit() int {
	// TODO: should set a value to avoid buffer overflow attack
	//   ref: https://www.tenable.com/plugins/nessus/11126
	return 0
}

func (a *Socks4Analyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return newSocks4Stream(logger)
}

type socks4Stream struct {
	logger analyzer.Logger

	reqBuf     *utils.ByteBuffer
	reqMap     analyzer.PropMap
	reqUpdated bool
	reqLSM     *utils.LinearStateMachine
	reqDone    bool

	respBuf     *utils.ByteBuffer
	respMap     analyzer.PropMap
	respUpdated bool
	respLSM     *utils.LinearStateMachine
	respDone    bool

	isSocks4a bool
}

func newSocks4Stream(logger analyzer.Logger) *socks4Stream {
	s := &socks4Stream{logger: logger, reqBuf: &utils.ByteBuffer{}, respBuf: &utils.ByteBuffer{}}
	s.reqLSM = utils.NewLinearStateMachine(
		s.parseReqIpAndPort,
		s.parseReqUserId,
		s.parseReqHostname,
	)
	s.respLSM = utils.NewLinearStateMachine(
		s.parseRespPacket,
	)
	return s
}

func (s *socks4Stream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, d bool) {
	if skip != 0 {
		return nil, true
	}
	if len(data) == 0 {
		return nil, false
	}
	var update *analyzer.PropUpdate
	var cancelled bool
	if rev {
		s.respBuf.Append(data)
		s.respUpdated = false
		cancelled, s.respDone = s.respLSM.Run()
		if s.respUpdated {
			update = &analyzer.PropUpdate{
				Type: analyzer.PropUpdateMerge,
				M:    analyzer.PropMap{"resp": s.respMap},
			}
			s.respUpdated = false
		}
	} else {
		s.reqBuf.Append(data)
		s.reqUpdated = false
		cancelled, s.reqDone = s.reqLSM.Run()
		if s.reqUpdated {
			update = &analyzer.PropUpdate{
				Type: analyzer.PropUpdateMerge,
				M:    analyzer.PropMap{"req": s.reqMap},
			}
			s.reqUpdated = false
		}
	}
	return update, cancelled || (s.reqDone && s.respDone)
}

func (s *socks4Stream) Close(limited bool) *analyzer.PropUpdate {
	s.reqBuf.Reset()
	s.respBuf.Reset()
	s.reqMap = nil
	s.respMap = nil
	return nil
}

func (s *socks4Stream) parseReqIpAndPort() utils.LSMAction {
	/* Following field will be parsed in this state:
	+-----+-----+----------+--------+
	| VER | CMD | DST.PORT | DST.IP |
	+-----+-----+----------+--------+
	*/
	pkt, ok := s.reqBuf.Get(8, true)
	if !ok {
		return utils.LSMActionPause
	}
	if pkt[0] != Socks4Version {
		return utils.LSMActionCancel
	}
	if pkt[1] != Socks4CmdTCPConnect && pkt[1] != Socks4CmdTCPBind {
		return utils.LSMActionCancel
	}

	dstPort := uint16(pkt[2])<<8 | uint16(pkt[3])
	dstIp := net.IPv4(pkt[4], pkt[5], pkt[6], pkt[7]).String()

	// Socks4a extension
	s.isSocks4a = pkt[4] == 0 && pkt[5] == 0 && pkt[6] == 0

	s.reqMap = analyzer.PropMap{
		"cmd":  pkt[1],
		"ip":   dstIp,
		"port": dstPort,
	}
	s.reqUpdated = true
	return utils.LSMActionNext
}

func (s *socks4Stream) parseReqUserId() utils.LSMAction {
	userIdSlice, ok := s.reqBuf.GetUntil([]byte("\x00"), true, true)
	if !ok {
		return utils.LSMActionPause
	}
	userId := string(userIdSlice[:len(userIdSlice)-1])
	s.reqMap["user_id"] = userId
	s.reqUpdated = true
	return utils.LSMActionNext
}

func (s *socks4Stream) parseReqHostname() utils.LSMAction {
	// Only Socks4a support hostname
	if !s.isSocks4a {
		return utils.LSMActionNext
	}
	hostnameSlice, ok := s.reqBuf.GetUntil([]byte("\x00"), true, true)
	if !ok {
		return utils.LSMActionPause
	}
	hostname := string(hostnameSlice[:len(hostnameSlice)-1])
	s.reqMap["hostname"] = hostname
	s.reqUpdated = true
	return utils.LSMActionNext
}

func (s *socks4Stream) parseRespPacket() utils.LSMAction {
	pkt, ok := s.respBuf.Get(8, true)
	if !ok {
		return utils.LSMActionPause
	}
	if pkt[0] != Socks4ReplyVN {
		return utils.LSMActionCancel
	}
	if pkt[1] != Socks4ReqGranted &&
		pkt[1] != Socks4ReqRejectOrFailed &&
		pkt[1] != Socks4ReqRejectIdentd &&
		pkt[1] != Socks4ReqRejectUser {
		return utils.LSMActionCancel
	}
	dstPort := uint16(pkt[2])<<8 | uint16(pkt[3])
	dstIp := net.IPv4(pkt[4], pkt[5], pkt[6], pkt[7]).String()
	s.respMap = analyzer.PropMap{
		"rep":  pkt[1],
		"ip":   dstIp,
		"port": dstPort,
	}
	s.respUpdated = true
	return utils.LSMActionNext
}
