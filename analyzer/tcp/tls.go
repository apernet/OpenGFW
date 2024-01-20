package tcp

import (
	"github.com/apernet/OpenGFW/analyzer"
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
	s.reqUpdated = true
	s.reqMap = make(analyzer.PropMap)
	// Version, random & session ID length combined are within 35 bytes,
	// so no need for bounds checking
	s.reqMap["version"], _ = chBuf.GetUint16(false, true)
	s.reqMap["random"], _ = chBuf.Get(32, true)
	sessionIDLen, _ := chBuf.GetByte(true)
	s.reqMap["session"], ok = chBuf.Get(int(sessionIDLen), true)
	if !ok {
		// Not enough data for session ID
		return utils.LSMActionCancel
	}
	cipherSuitesLen, ok := chBuf.GetUint16(false, true)
	if !ok {
		// Not enough data for cipher suites length
		return utils.LSMActionCancel
	}
	if cipherSuitesLen%2 != 0 {
		// Cipher suites are 2 bytes each, so must be even
		return utils.LSMActionCancel
	}
	ciphers := make([]uint16, cipherSuitesLen/2)
	for i := range ciphers {
		ciphers[i], ok = chBuf.GetUint16(false, true)
		if !ok {
			return utils.LSMActionCancel
		}
	}
	s.reqMap["ciphers"] = ciphers
	compressionMethodsLen, ok := chBuf.GetByte(true)
	if !ok {
		// Not enough data for compression methods length
		return utils.LSMActionCancel
	}
	// Compression methods are 1 byte each, we just put a byte slice here
	s.reqMap["compression"], ok = chBuf.Get(int(compressionMethodsLen), true)
	if !ok {
		// Not enough data for compression methods
		return utils.LSMActionCancel
	}
	extsLen, ok := chBuf.GetUint16(false, true)
	if !ok {
		// No extensions, I guess it's possible?
		return utils.LSMActionNext
	}
	extBuf, ok := chBuf.GetSubBuffer(int(extsLen), true)
	if !ok {
		// Not enough data for extensions
		return utils.LSMActionCancel
	}
	for extBuf.Len() > 0 {
		extType, ok := extBuf.GetUint16(false, true)
		if !ok {
			// Not enough data for extension type
			return utils.LSMActionCancel
		}
		extLen, ok := extBuf.GetUint16(false, true)
		if !ok {
			// Not enough data for extension length
			return utils.LSMActionCancel
		}
		extDataBuf, ok := extBuf.GetSubBuffer(int(extLen), true)
		if !ok || !s.handleExtensions(extType, extDataBuf, s.reqMap) {
			// Not enough data for extension data, or invalid extension
			return utils.LSMActionCancel
		}
	}
	return utils.LSMActionNext
}

func (s *tlsStream) parseServerHello() utils.LSMAction {
	shBuf, ok := s.respBuf.GetSubBuffer(s.serverHelloLen, true)
	if !ok {
		// Not a full server hello yet
		return utils.LSMActionPause
	}
	s.respUpdated = true
	s.respMap = make(analyzer.PropMap)
	// Version, random & session ID length combined are within 35 bytes,
	// so no need for bounds checking
	s.respMap["version"], _ = shBuf.GetUint16(false, true)
	s.respMap["random"], _ = shBuf.Get(32, true)
	sessionIDLen, _ := shBuf.GetByte(true)
	s.respMap["session"], ok = shBuf.Get(int(sessionIDLen), true)
	if !ok {
		// Not enough data for session ID
		return utils.LSMActionCancel
	}
	cipherSuite, ok := shBuf.GetUint16(false, true)
	if !ok {
		// Not enough data for cipher suite
		return utils.LSMActionCancel
	}
	s.respMap["cipher"] = cipherSuite
	compressionMethod, ok := shBuf.GetByte(true)
	if !ok {
		// Not enough data for compression method
		return utils.LSMActionCancel
	}
	s.respMap["compression"] = compressionMethod
	extsLen, ok := shBuf.GetUint16(false, true)
	if !ok {
		// No extensions, I guess it's possible?
		return utils.LSMActionNext
	}
	extBuf, ok := shBuf.GetSubBuffer(int(extsLen), true)
	if !ok {
		// Not enough data for extensions
		return utils.LSMActionCancel
	}
	for extBuf.Len() > 0 {
		extType, ok := extBuf.GetUint16(false, true)
		if !ok {
			// Not enough data for extension type
			return utils.LSMActionCancel
		}
		extLen, ok := extBuf.GetUint16(false, true)
		if !ok {
			// Not enough data for extension length
			return utils.LSMActionCancel
		}
		extDataBuf, ok := extBuf.GetSubBuffer(int(extLen), true)
		if !ok || !s.handleExtensions(extType, extDataBuf, s.respMap) {
			// Not enough data for extension data, or invalid extension
			return utils.LSMActionCancel
		}
	}
	return utils.LSMActionNext
}

func (s *tlsStream) handleExtensions(extType uint16, extDataBuf *utils.ByteBuffer, m analyzer.PropMap) bool {
	switch extType {
	case 0x0000: // SNI
		ok := extDataBuf.Skip(2) // Ignore list length, we only care about the first entry for now
		if !ok {
			// Not enough data for list length
			return false
		}
		sniType, ok := extDataBuf.GetByte(true)
		if !ok || sniType != 0 {
			// Not enough data for SNI type, or not hostname
			return false
		}
		sniLen, ok := extDataBuf.GetUint16(false, true)
		if !ok {
			// Not enough data for SNI length
			return false
		}
		m["sni"], ok = extDataBuf.GetString(int(sniLen), true)
		if !ok {
			// Not enough data for SNI
			return false
		}
	case 0x0010: // ALPN
		ok := extDataBuf.Skip(2) // Ignore list length, as we read until the end
		if !ok {
			// Not enough data for list length
			return false
		}
		var alpnList []string
		for extDataBuf.Len() > 0 {
			alpnLen, ok := extDataBuf.GetByte(true)
			if !ok {
				// Not enough data for ALPN length
				return false
			}
			alpn, ok := extDataBuf.GetString(int(alpnLen), true)
			if !ok {
				// Not enough data for ALPN
				return false
			}
			alpnList = append(alpnList, alpn)
		}
		m["alpn"] = alpnList
	case 0x002b: // Supported Versions
		if extDataBuf.Len() == 2 {
			// Server only selects one version
			m["supported_versions"], _ = extDataBuf.GetUint16(false, true)
		} else {
			// Client sends a list of versions
			ok := extDataBuf.Skip(1) // Ignore list length, as we read until the end
			if !ok {
				// Not enough data for list length
				return false
			}
			var versions []uint16
			for extDataBuf.Len() > 0 {
				ver, ok := extDataBuf.GetUint16(false, true)
				if !ok {
					// Not enough data for version
					return false
				}
				versions = append(versions, ver)
			}
			m["supported_versions"] = versions
		}
	case 0xfe0d: // ECH
		// We can't parse ECH for now, just set a flag
		m["ech"] = true
	}
	return true
}

func (s *tlsStream) Close(limited bool) *analyzer.PropUpdate {
	s.reqBuf.Reset()
	s.respBuf.Reset()
	s.reqMap = nil
	s.respMap = nil
	return nil
}
