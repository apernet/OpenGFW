package tcp

import (
	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/utils"
	"net"
)

const (
	Socks5Version = 0x05

	CmdTCPConnect   = 0x01
	CmdTCPBind      = 0x02
	CmdUDPAssociate = 0x03

	AuthNotRequired      = 0x00
	AuthPassword         = 0x02
	AuthNoMatchingMethod = 0xFF

	AuthSuccess = 0x00
	AuthFailure = 0x01

	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6   = 0x04
)

var _ analyzer.Analyzer = (*Socks5Analyzer)(nil)

type Socks5Analyzer struct{}

func (a *Socks5Analyzer) Name() string {
	return "socks5"
}

func (a *Socks5Analyzer) Limit() int {
	// TODO: more precise calculate
	return 0
}

func (a *Socks5Analyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return newSocksStream(logger)
}

type socks5Stream struct {
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

	authReqMethod int
	authUsername  string
	authPassword  string

	authRespMethod int
}

func newSocksStream(logger analyzer.Logger) *socks5Stream {
	s := &socks5Stream{logger: logger, reqBuf: &utils.ByteBuffer{}, respBuf: &utils.ByteBuffer{}}
	s.reqLSM = utils.NewLinearStateMachine(
		s.parseSocks5ReqVersion,
		s.parseSocks5ReqMethod,
		s.parseSocks5ReqAuth,
		s.parseSocks5ReqConnInfo,
	)
	s.respLSM = utils.NewLinearStateMachine(
		s.parseSocks5RespVerAndMethod,
		s.parseSocks5RespAuth,
		s.parseSocks5RespConnInfo,
	)
	return s
}

func (s *socks5Stream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, d bool) {
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

func (s *socks5Stream) Close(limited bool) *analyzer.PropUpdate {
	s.reqBuf.Reset()
	s.respBuf.Reset()
	s.reqMap = nil
	s.respMap = nil
	return nil
}

func (s *socks5Stream) parseSocks5ReqVersion() utils.LSMAction {
	socksVer, ok := s.reqBuf.GetByte(true)
	if !ok {
		return utils.LSMActionPause
	}
	if socksVer != Socks5Version {
		return utils.LSMActionCancel
	}
	return utils.LSMActionNext
}

func (s *socks5Stream) parseSocks5ReqMethod() utils.LSMAction {
	nMethods, ok := s.reqBuf.GetByte(false)
	if !ok {
		return utils.LSMActionPause
	}
	methods, ok := s.reqBuf.Get(int(nMethods)+1, true)
	if !ok {
		return utils.LSMActionPause
	}

	// For convenience, we only take the first method we can process
	s.authReqMethod = AuthNoMatchingMethod
	for _, method := range methods[1:] {
		switch method {
		case AuthNotRequired:
			s.authReqMethod = AuthNotRequired
			break
		case AuthPassword:
			s.authReqMethod = AuthPassword
			break
		default:
			// TODO: more auth method to support
		}
	}
	s.reqMap = make(analyzer.PropMap)
	return utils.LSMActionNext
}

func (s *socks5Stream) parseSocks5ReqAuth() utils.LSMAction {
	switch s.authReqMethod {
	case AuthNotRequired:
		s.reqMap["auth"] = analyzer.PropMap{"method": s.authReqMethod}
	case AuthPassword:
		meta, ok := s.reqBuf.Get(2, false)
		if !ok {
			return utils.LSMActionPause
		}
		if meta[0] != 0x01 {
			return utils.LSMActionCancel
		}
		usernameLen := int(meta[1])
		meta, ok = s.reqBuf.Get(usernameLen+3, false)
		if !ok {
			return utils.LSMActionPause
		}
		passwordLen := int(meta[usernameLen+2])
		meta, ok = s.reqBuf.Get(usernameLen+passwordLen+3, true)
		if !ok {
			return utils.LSMActionPause
		}
		s.authUsername = string(meta[2 : usernameLen+2])
		s.authPassword = string(meta[usernameLen+3:])
		s.reqMap["auth"] = analyzer.PropMap{
			"method":   s.authReqMethod,
			"username": s.authUsername,
			"password": s.authPassword,
		}
	default:
		return utils.LSMActionCancel
	}
	s.reqUpdated = true
	return utils.LSMActionNext
}

func (s *socks5Stream) parseSocks5ReqConnInfo() utils.LSMAction {
	/* preInfo struct
	+----+-----+-------+------+-------------+
	|VER | CMD |  RSV  | ATYP | DST.ADDR(1) |
	+----+-----+-------+------+-------------+
	*/
	preInfo, ok := s.reqBuf.Get(5, false)
	if !ok {
		return utils.LSMActionPause
	}

	// verify socks version
	if preInfo[0] != 0x05 {
		return utils.LSMActionCancel
	}

	var pktLen int
	switch int(preInfo[3]) {
	case AddrTypeIPv4:
		pktLen = 10
	case AddrTypeDomain:
		domainLen := int(preInfo[4])
		pktLen = 7 + domainLen
	case AddrTypeIPv6:
		pktLen = 22
	default:
		return utils.LSMActionCancel
	}

	pkt, ok := s.reqBuf.Get(pktLen, true)
	if !ok {
		return utils.LSMActionPause
	}

	// parse cmd
	cmd := int(pkt[1])
	if cmd != CmdTCPConnect && cmd != CmdTCPBind && cmd != CmdUDPAssociate {
		return utils.LSMActionCancel
	}
	s.reqMap["cmd"] = cmd

	// parse addr type
	addrType := int(pkt[3])
	var addr string
	switch addrType {
	case AddrTypeIPv4:
		addr = net.IPv4(pkt[4], pkt[5], pkt[6], pkt[7]).String()
	case AddrTypeDomain:
		addr = string(pkt[5 : 5+pkt[4]])
	case AddrTypeIPv6:
		addr = net.IP(pkt[4 : 4+net.IPv6len]).String()
	default:
		return utils.LSMActionCancel
	}
	s.reqMap["addr_type"] = addrType
	s.reqMap["addr"] = addr

	// parse port
	port := int(pkt[pktLen-2])<<8 | int(pkt[pktLen-1])
	s.reqMap["port"] = port
	s.reqUpdated = true
	return utils.LSMActionNext
}

func (s *socks5Stream) parseSocks5RespVerAndMethod() utils.LSMAction {
	verAndMethod, ok := s.respBuf.Get(2, true)
	if !ok {
		return utils.LSMActionPause
	}
	if verAndMethod[0] != Socks5Version {
		return utils.LSMActionCancel
	}
	s.authRespMethod = int(verAndMethod[1])
	s.respMap = make(analyzer.PropMap)
	return utils.LSMActionNext
}

func (s *socks5Stream) parseSocks5RespAuth() utils.LSMAction {
	switch s.authRespMethod {
	case AuthNotRequired:
		s.respMap["auth"] = analyzer.PropMap{"method": s.authRespMethod}
	case AuthPassword:
		authResp, ok := s.respBuf.Get(2, true)
		if !ok {
			return utils.LSMActionPause
		}
		if authResp[0] != 0x01 {
			return utils.LSMActionCancel
		}
		authStatus := int(authResp[1])
		s.respMap["auth"] = analyzer.PropMap{
			"method": s.authRespMethod,
			"status": authStatus,
		}
	default:
		return utils.LSMActionCancel
	}
	s.respUpdated = true
	return utils.LSMActionNext
}

func (s *socks5Stream) parseSocks5RespConnInfo() utils.LSMAction {
	/* preInfo struct
	+----+-----+-------+------+-------------+
	|VER | REP |  RSV  | ATYP | BND.ADDR(1) |
	+----+-----+-------+------+-------------+
	*/
	preInfo, ok := s.respBuf.Get(5, false)
	if !ok {
		return utils.LSMActionPause
	}

	// verify socks version
	if preInfo[0] != Socks5Version {
		return utils.LSMActionCancel
	}

	var pktLen int
	switch int(preInfo[3]) {
	case AddrTypeIPv4:
		pktLen = 10
	case AddrTypeDomain:
		domainLen := int(preInfo[4])
		pktLen = 7 + domainLen
	case AddrTypeIPv6:
		pktLen = 22
	default:
		return utils.LSMActionCancel
	}

	pkt, ok := s.respBuf.Get(pktLen, true)
	if !ok {
		return utils.LSMActionPause
	}

	// parse rep
	rep := int(pkt[1])
	s.respMap["rep"] = rep

	// parse addr type
	addrType := int(pkt[3])
	var addr string
	switch addrType {
	case AddrTypeIPv4:
		addr = net.IPv4(pkt[4], pkt[5], pkt[6], pkt[7]).String()
	case AddrTypeDomain:
		addr = string(pkt[5 : 5+pkt[4]])
	case AddrTypeIPv6:
		addr = net.IP(pkt[4 : 4+net.IPv6len]).String()
	default:
		return utils.LSMActionCancel
	}
	s.respMap["addr_type"] = addrType
	s.respMap["addr"] = addr

	// parse port
	port := int(pkt[pktLen-2])<<8 | int(pkt[pktLen-1])
	s.respMap["port"] = port
	s.respUpdated = true
	return utils.LSMActionNext
}
