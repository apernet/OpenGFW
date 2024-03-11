package tcp

import (
	"net"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

const (
	SocksInvalid = iota
	Socks4
	Socks4A
	Socks5

	Socks4Version = 0x04
	Socks5Version = 0x05

	Socks4ReplyVN = 0x00

	Socks4CmdTCPConnect = 0x01
	Socks4CmdTCPBind    = 0x02

	Socks4ReqGranted        = 0x5A
	Socks4ReqRejectOrFailed = 0x5B
	Socks4ReqRejectIdentd   = 0x5C
	Socks4ReqRejectUser     = 0x5D

	Socks5CmdTCPConnect   = 0x01
	Socks5CmdTCPBind      = 0x02
	Socks5CmdUDPAssociate = 0x03

	Socks5AuthNotRequired      = 0x00
	Socks5AuthPassword         = 0x02
	Socks5AuthNoMatchingMethod = 0xFF

	Socks5AuthSuccess = 0x00
	Socks5AuthFailure = 0x01

	Socks5AddrTypeIPv4   = 0x01
	Socks5AddrTypeDomain = 0x03
	Socks5AddrTypeIPv6   = 0x04
)

var _ analyzer.Analyzer = (*SocksAnalyzer)(nil)

type SocksAnalyzer struct{}

func (a *SocksAnalyzer) Name() string {
	return "socks"
}

func (a *SocksAnalyzer) Limit() int {
	// Socks4 length limit cannot be predicted
	return 0
}

func (a *SocksAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return newSocksStream(logger)
}

type socksStream struct {
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

	version int

	authReqMethod int
	authUsername  string
	authPassword  string

	authRespMethod int
}

func newSocksStream(logger analyzer.Logger) *socksStream {
	s := &socksStream{logger: logger, reqBuf: &utils.ByteBuffer{}, respBuf: &utils.ByteBuffer{}}
	s.reqLSM = utils.NewLinearStateMachine(
		s.parseSocksReqVersion,
	)
	s.respLSM = utils.NewLinearStateMachine(
		s.parseSocksRespVersion,
	)
	return s
}

func (s *socksStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, d bool) {
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
				M: analyzer.PropMap{
					"version": s.socksVersion(),
					"req":     s.reqMap,
				},
			}
			s.reqUpdated = false
		}
	}

	return update, cancelled || (s.reqDone && s.respDone)
}

func (s *socksStream) Close(limited bool) *analyzer.PropUpdate {
	s.reqBuf.Reset()
	s.respBuf.Reset()
	s.reqMap = nil
	s.respMap = nil
	return nil
}

func (s *socksStream) parseSocksReqVersion() utils.LSMAction {
	socksVer, ok := s.reqBuf.GetByte(true)
	if !ok {
		return utils.LSMActionPause
	}
	if socksVer != Socks4Version && socksVer != Socks5Version {
		return utils.LSMActionCancel
	}
	s.reqMap = make(analyzer.PropMap)
	s.reqUpdated = true
	if socksVer == Socks4Version {
		s.version = Socks4
		s.reqLSM.AppendSteps(
			s.parseSocks4ReqIpAndPort,
			s.parseSocks4ReqUserId,
			s.parseSocks4ReqHostname,
		)
	} else {
		s.version = Socks5
		s.reqLSM.AppendSteps(
			s.parseSocks5ReqMethod,
			s.parseSocks5ReqAuth,
			s.parseSocks5ReqConnInfo,
		)
	}
	return utils.LSMActionNext
}

func (s *socksStream) parseSocksRespVersion() utils.LSMAction {
	socksVer, ok := s.respBuf.GetByte(true)
	if !ok {
		return utils.LSMActionPause
	}
	if (s.version == Socks4 || s.version == Socks4A) && socksVer != Socks4ReplyVN ||
		s.version == Socks5 && socksVer != Socks5Version || s.version == SocksInvalid {
		return utils.LSMActionCancel
	}
	if socksVer == Socks4ReplyVN {
		s.respLSM.AppendSteps(
			s.parseSocks4RespPacket,
		)
	} else {
		s.respLSM.AppendSteps(
			s.parseSocks5RespMethod,
			s.parseSocks5RespAuth,
			s.parseSocks5RespConnInfo,
		)
	}
	return utils.LSMActionNext
}

func (s *socksStream) parseSocks5ReqMethod() utils.LSMAction {
	nMethods, ok := s.reqBuf.GetByte(false)
	if !ok {
		return utils.LSMActionPause
	}
	methods, ok := s.reqBuf.Get(int(nMethods)+1, true)
	if !ok {
		return utils.LSMActionPause
	}

	// For convenience, we only take the first method we can process
	s.authReqMethod = Socks5AuthNoMatchingMethod
	for _, method := range methods[1:] {
		switch method {
		case Socks5AuthNotRequired:
			s.authReqMethod = Socks5AuthNotRequired
			return utils.LSMActionNext
		case Socks5AuthPassword:
			s.authReqMethod = Socks5AuthPassword
			return utils.LSMActionNext
		default:
			// TODO: more auth method to support
		}
	}
	return utils.LSMActionNext
}

func (s *socksStream) parseSocks5ReqAuth() utils.LSMAction {
	switch s.authReqMethod {
	case Socks5AuthNotRequired:
		s.reqMap["auth"] = analyzer.PropMap{"method": s.authReqMethod}
	case Socks5AuthPassword:
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

func (s *socksStream) parseSocks5ReqConnInfo() utils.LSMAction {
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
	if preInfo[0] != Socks5Version {
		return utils.LSMActionCancel
	}

	var pktLen int
	switch int(preInfo[3]) {
	case Socks5AddrTypeIPv4:
		pktLen = 10
	case Socks5AddrTypeDomain:
		domainLen := int(preInfo[4])
		pktLen = 7 + domainLen
	case Socks5AddrTypeIPv6:
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
	if cmd != Socks5CmdTCPConnect && cmd != Socks5CmdTCPBind && cmd != Socks5CmdUDPAssociate {
		return utils.LSMActionCancel
	}
	s.reqMap["cmd"] = cmd

	// parse addr type
	addrType := int(pkt[3])
	var addr string
	switch addrType {
	case Socks5AddrTypeIPv4:
		addr = net.IPv4(pkt[4], pkt[5], pkt[6], pkt[7]).String()
	case Socks5AddrTypeDomain:
		addr = string(pkt[5 : 5+pkt[4]])
	case Socks5AddrTypeIPv6:
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

func (s *socksStream) parseSocks5RespMethod() utils.LSMAction {
	method, ok := s.respBuf.Get(1, true)
	if !ok {
		return utils.LSMActionPause
	}
	s.authRespMethod = int(method[0])
	s.respMap = make(analyzer.PropMap)
	return utils.LSMActionNext
}

func (s *socksStream) parseSocks5RespAuth() utils.LSMAction {
	switch s.authRespMethod {
	case Socks5AuthNotRequired:
		s.respMap["auth"] = analyzer.PropMap{"method": s.authRespMethod}
	case Socks5AuthPassword:
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

func (s *socksStream) parseSocks5RespConnInfo() utils.LSMAction {
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
	case Socks5AddrTypeIPv4:
		pktLen = 10
	case Socks5AddrTypeDomain:
		domainLen := int(preInfo[4])
		pktLen = 7 + domainLen
	case Socks5AddrTypeIPv6:
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
	case Socks5AddrTypeIPv4:
		addr = net.IPv4(pkt[4], pkt[5], pkt[6], pkt[7]).String()
	case Socks5AddrTypeDomain:
		addr = string(pkt[5 : 5+pkt[4]])
	case Socks5AddrTypeIPv6:
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

func (s *socksStream) parseSocks4ReqIpAndPort() utils.LSMAction {
	/* Following field will be parsed in this state:
	+-----+----------+--------+
	| CMD | DST.PORT | DST.IP |
	+-----+----------+--------+
	*/
	pkt, ok := s.reqBuf.Get(7, true)
	if !ok {
		return utils.LSMActionPause
	}
	if pkt[0] != Socks4CmdTCPConnect && pkt[0] != Socks4CmdTCPBind {
		return utils.LSMActionCancel
	}

	dstPort := uint16(pkt[1])<<8 | uint16(pkt[2])
	dstIp := net.IPv4(pkt[3], pkt[4], pkt[5], pkt[6]).String()

	// Socks4a extension
	if pkt[3] == 0 && pkt[4] == 0 && pkt[5] == 0 {
		s.version = Socks4A
	}

	s.reqMap["cmd"] = pkt[0]
	s.reqMap["addr"] = dstIp
	s.reqMap["addr_type"] = Socks5AddrTypeIPv4
	s.reqMap["port"] = dstPort
	s.reqUpdated = true
	return utils.LSMActionNext
}

func (s *socksStream) parseSocks4ReqUserId() utils.LSMAction {
	userIdSlice, ok := s.reqBuf.GetUntil([]byte("\x00"), true, true)
	if !ok {
		return utils.LSMActionPause
	}
	userId := string(userIdSlice[:len(userIdSlice)-1])
	s.reqMap["auth"] = analyzer.PropMap{
		"user_id": userId,
	}
	s.reqUpdated = true
	return utils.LSMActionNext
}

func (s *socksStream) parseSocks4ReqHostname() utils.LSMAction {
	// Only Socks4a support hostname
	if s.version != Socks4A {
		return utils.LSMActionNext
	}
	hostnameSlice, ok := s.reqBuf.GetUntil([]byte("\x00"), true, true)
	if !ok {
		return utils.LSMActionPause
	}
	hostname := string(hostnameSlice[:len(hostnameSlice)-1])
	s.reqMap["addr"] = hostname
	s.reqMap["addr_type"] = Socks5AddrTypeDomain
	s.reqUpdated = true
	return utils.LSMActionNext
}

func (s *socksStream) parseSocks4RespPacket() utils.LSMAction {
	pkt, ok := s.respBuf.Get(7, true)
	if !ok {
		return utils.LSMActionPause
	}
	if pkt[0] != Socks4ReqGranted &&
		pkt[0] != Socks4ReqRejectOrFailed &&
		pkt[0] != Socks4ReqRejectIdentd &&
		pkt[0] != Socks4ReqRejectUser {
		return utils.LSMActionCancel
	}
	dstPort := uint16(pkt[1])<<8 | uint16(pkt[2])
	dstIp := net.IPv4(pkt[3], pkt[4], pkt[5], pkt[6]).String()
	s.respMap = analyzer.PropMap{
		"rep":       pkt[0],
		"addr":      dstIp,
		"addr_type": Socks5AddrTypeIPv4,
		"port":      dstPort,
	}
	s.respUpdated = true
	return utils.LSMActionNext
}

func (s *socksStream) socksVersion() int {
	switch s.version {
	case Socks4, Socks4A:
		return Socks4Version
	case Socks5:
		return Socks5Version
	default:
		return SocksInvalid
	}
}
