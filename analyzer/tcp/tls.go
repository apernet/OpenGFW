package tcp

import (
	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/internal"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

var _ analyzer.TCPAnalyzer = (*TLSAnalyzer)(nil)

type TLSAnalyzer struct{}

func (a *TLSAnalyzer) Name() string {
	return "tls"
}

func (a *TLSAnalyzer) Limit() int {
	return 8192
}

func (a *TLSAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return newTLSStream(logger)
}

type tlsStream struct {
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

	clientHelloLen int
	serverHelloLen int
}

func newTLSStream(logger analyzer.Logger) *tlsStream {
	s := &tlsStream{logger: logger, reqBuf: &utils.ByteBuffer{}, respBuf: &utils.ByteBuffer{}}
	s.reqLSM = utils.NewLinearStateMachine(
		s.tlsClientHelloSanityCheck,
		s.parseClientHello,
	)
	s.respLSM = utils.NewLinearStateMachine(
		s.tlsServerHelloSanityCheck,
		s.parseServerHello,
	)
	return s
}

func (s *tlsStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
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

func (s *tlsStream) tlsClientHelloSanityCheck() utils.LSMAction {
	data, ok := s.reqBuf.Get(9, true)
	if !ok {
		return utils.LSMActionPause
	}
	if data[0] != 0x16 || data[5] != 0x01 {
		// Not a TLS handshake, or not a client hello
		return utils.LSMActionCancel
	}
	s.clientHelloLen = int(data[6])<<16 | int(data[7])<<8 | int(data[8])
	if s.clientHelloLen < 41 {
		// 2 (Protocol Version) +
		// 32 (Random) +
		// 1 (Session ID Length) +
		// 2 (Cipher Suites Length) +_ws.col.protocol == "TLSv1.3"
		// 2 (Cipher Suite) +
		// 1 (Compression Methods Length) +
		// 1 (Compression Method) +
		// No extensions
		// This should be the bare minimum for a client hello
		return utils.LSMActionCancel
	}
	return utils.LSMActionNext
}

func (s *tlsStream) tlsServerHelloSanityCheck() utils.LSMAction {
	data, ok := s.respBuf.Get(9, true)
	if !ok {
		return utils.LSMActionPause
	}
	if data[0] != 0x16 || data[5] != 0x02 {
		// Not a TLS handshake, or not a server hello
		return utils.LSMActionCancel
	}
	s.serverHelloLen = int(data[6])<<16 | int(data[7])<<8 | int(data[8])
	if s.serverHelloLen < 38 {
		// 2 (Protocol Version) +
		// 32 (Random) +
		// 1 (Session ID Length) +
		// 2 (Cipher Suite) +
		// 1 (Compression Method) +
		// No extensions
		// This should be the bare minimum for a server hello
		return utils.LSMActionCancel
	}
	return utils.LSMActionNext
}

func (s *tlsStream) parseClientHello() utils.LSMAction {
	chBuf, ok := s.reqBuf.GetSubBuffer(s.clientHelloLen, true)
	if !ok {
		// Not a full client hello yet
		return utils.LSMActionPause
	}
	m := internal.ParseTLSClientHello(chBuf)
	if m == nil {
		return utils.LSMActionCancel
	} else {
		s.reqUpdated = true
		s.reqMap = m
		return utils.LSMActionNext
	}
}

func (s *tlsStream) parseServerHello() utils.LSMAction {
	shBuf, ok := s.respBuf.GetSubBuffer(s.serverHelloLen, true)
	if !ok {
		// Not a full server hello yet
		return utils.LSMActionPause
	}
	m := internal.ParseTLSServerHello(shBuf)
	if m == nil {
		return utils.LSMActionCancel
	} else {
		s.respUpdated = true
		s.respMap = m
		return utils.LSMActionNext
	}
}

func (s *tlsStream) Close(limited bool) *analyzer.PropUpdate {
	s.reqBuf.Reset()
	s.respBuf.Reset()
	s.reqMap = nil
	s.respMap = nil
	return nil
}
