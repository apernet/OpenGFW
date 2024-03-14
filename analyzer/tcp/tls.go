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
		s.tlsClientHelloPreprocess,
		s.parseClientHelloData,
	)
	s.respLSM = utils.NewLinearStateMachine(
		s.tlsServerHelloPreprocess,
		s.parseServerHelloData,
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

// tlsClientHelloPreprocess validates ClientHello message.
//
// During validation, message header and first handshake header may be removed
// from `s.reqBuf`.
func (s *tlsStream) tlsClientHelloPreprocess() utils.LSMAction {
	// headers size: content type (1 byte) + legacy protocol version (2 bytes) +
	//   + content length (2 bytes) + message type (1 byte) +
	//   + handshake length (3 bytes)
	const headersSize = 9

	// minimal data size: protocol version (2 bytes) + random (32 bytes) +
	//   + session ID (1 byte) + cipher suites (4 bytes) +
	//   + compression methods (2 bytes) + no extensions
	const minDataSize = 41

	header, ok := s.reqBuf.Get(headersSize, true)
	if !ok {
		// not a full header yet
		return utils.LSMActionPause
	}

	if header[0] != internal.RecordTypeHandshake || header[5] != internal.TypeClientHello {
		return utils.LSMActionCancel
	}

	s.clientHelloLen = int(header[6])<<16 | int(header[7])<<8 | int(header[8])
	if s.clientHelloLen < minDataSize {
		return utils.LSMActionCancel
	}

	// TODO: something is missing. See:
	//   const messageHeaderSize = 4
	//   fullMessageLen := int(header[3])<<8 | int(header[4])
	//   msgNo := fullMessageLen / int(messageHeaderSize+s.serverHelloLen)
	//   if msgNo != 1 {
	// 	   // what here?
	//   }
	//   if messageNo != int(messageNo) {
	// 	   // what here?
	//   }

	return utils.LSMActionNext
}

// tlsServerHelloPreprocess validates ServerHello message.
//
// During validation, message header and first handshake header may be removed
// from `s.reqBuf`.
func (s *tlsStream) tlsServerHelloPreprocess() utils.LSMAction {
	// header size: content type (1 byte) + legacy protocol version (2 byte) +
	//   + content length (2 byte) + message type (1 byte) +
	//   + handshake length (3 byte)
	const headersSize = 9

	// minimal data size: server version (2 byte) + random (32 byte) +
	//	 + session ID (>=1 byte) + cipher suite (2 byte) +
	//	 + compression method (1 byte) + no extensions
	const minDataSize = 38

	header, ok := s.respBuf.Get(headersSize, true)
	if !ok {
		// not a full header yet
		return utils.LSMActionPause
	}

	if header[0] != internal.RecordTypeHandshake || header[5] != internal.TypeServerHello {
		return utils.LSMActionCancel
	}

	s.serverHelloLen = int(header[6])<<16 | int(header[7])<<8 | int(header[8])
	if s.serverHelloLen < minDataSize {
		return utils.LSMActionCancel
	}

	// TODO: something is missing. See example:
	//   const messageHeaderSize = 4
	//   fullMessageLen := int(header[3])<<8 | int(header[4])
	//   msgNo := fullMessageLen / int(messageHeaderSize+s.serverHelloLen)
	//   if msgNo != 1 {
	// 	   // what here?
	//   }
	//   if messageNo != int(messageNo) {
	// 	   // what here?
	//   }

	return utils.LSMActionNext
}

// parseClientHelloData converts valid ClientHello message data (without
// headers) into `analyzer.PropMap`.
//
// Parsing error may leave `s.reqBuf` in an unusable state.
func (s *tlsStream) parseClientHelloData() utils.LSMAction {
	chBuf, ok := s.reqBuf.GetSubBuffer(s.clientHelloLen, true)
	if !ok {
		// Not a full client hello yet
		return utils.LSMActionPause
	}
	m := internal.ParseTLSClientHelloMsgData(chBuf)
	if m == nil {
		return utils.LSMActionCancel
	} else {
		s.reqUpdated = true
		s.reqMap = m
		return utils.LSMActionNext
	}
}

// parseServerHelloData converts valid ServerHello message data (without
// headers) into `analyzer.PropMap`.
//
// Parsing error may leave `s.respBuf` in an unusable state.
func (s *tlsStream) parseServerHelloData() utils.LSMAction {
	shBuf, ok := s.respBuf.GetSubBuffer(s.serverHelloLen, true)
	if !ok {
		// Not a full server hello yet
		return utils.LSMActionPause
	}
	m := internal.ParseTLSServerHelloMsgData(shBuf)
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
