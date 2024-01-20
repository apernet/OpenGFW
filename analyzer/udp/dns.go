package udp

import (
	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/utils"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	dnsUDPInvalidCountThreshold = 4
)

// DNSAnalyzer is for both DNS over UDP and TCP.
var (
	_ analyzer.UDPAnalyzer = (*DNSAnalyzer)(nil)
	_ analyzer.TCPAnalyzer = (*DNSAnalyzer)(nil)
)

type DNSAnalyzer struct{}

func (a *DNSAnalyzer) Name() string {
	return "dns"
}

func (a *DNSAnalyzer) Limit() int {
	// DNS is a stateless protocol, with unlimited amount
	// of back-and-forth exchanges. Don't limit it here.
	return 0
}

func (a *DNSAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return &dnsUDPStream{logger: logger}
}

func (a *DNSAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	s := &dnsTCPStream{logger: logger, reqBuf: &utils.ByteBuffer{}, respBuf: &utils.ByteBuffer{}}
	s.reqLSM = utils.NewLinearStateMachine(
		s.getReqMessageLength,
		s.getReqMessage,
	)
	s.respLSM = utils.NewLinearStateMachine(
		s.getRespMessageLength,
		s.getRespMessage,
	)
	return s
}

type dnsUDPStream struct {
	logger       analyzer.Logger
	invalidCount int
}

func (s *dnsUDPStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	m := parseDNSMessage(data)
	// To allow non-DNS UDP traffic to get offloaded,
	// we consider a UDP stream invalid and "done" if
	// it has more than a certain number of consecutive
	// packets that are not valid DNS messages.
	if m == nil {
		s.invalidCount++
		return nil, s.invalidCount >= dnsUDPInvalidCountThreshold
	}
	s.invalidCount = 0 // Reset invalid count on valid DNS message
	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateReplace,
		M:    m,
	}, false
}

func (s *dnsUDPStream) Close(limited bool) *analyzer.PropUpdate {
	return nil
}

type dnsTCPStream struct {
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

	reqMsgLen  int
	respMsgLen int
}

func (s *dnsTCPStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
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
				Type: analyzer.PropUpdateReplace,
				M:    s.respMap,
			}
			s.respUpdated = false
		}
	} else {
		s.reqBuf.Append(data)
		s.reqUpdated = false
		cancelled, s.reqDone = s.reqLSM.Run()
		if s.reqUpdated {
			update = &analyzer.PropUpdate{
				Type: analyzer.PropUpdateReplace,
				M:    s.reqMap,
			}
			s.reqUpdated = false
		}
	}
	return update, cancelled || (s.reqDone && s.respDone)
}

func (s *dnsTCPStream) Close(limited bool) *analyzer.PropUpdate {
	s.reqBuf.Reset()
	s.respBuf.Reset()
	s.reqMap = nil
	s.respMap = nil
	return nil
}

func (s *dnsTCPStream) getReqMessageLength() utils.LSMAction {
	bs, ok := s.reqBuf.Get(2, true)
	if !ok {
		return utils.LSMActionPause
	}
	s.reqMsgLen = int(bs[0])<<8 | int(bs[1])
	return utils.LSMActionNext
}

func (s *dnsTCPStream) getRespMessageLength() utils.LSMAction {
	bs, ok := s.respBuf.Get(2, true)
	if !ok {
		return utils.LSMActionPause
	}
	s.respMsgLen = int(bs[0])<<8 | int(bs[1])
	return utils.LSMActionNext
}

func (s *dnsTCPStream) getReqMessage() utils.LSMAction {
	bs, ok := s.reqBuf.Get(s.reqMsgLen, true)
	if !ok {
		return utils.LSMActionPause
	}
	m := parseDNSMessage(bs)
	if m == nil {
		// Invalid DNS message
		return utils.LSMActionCancel
	}
	s.reqMap = m
	s.reqUpdated = true
	return utils.LSMActionReset
}

func (s *dnsTCPStream) getRespMessage() utils.LSMAction {
	bs, ok := s.respBuf.Get(s.respMsgLen, true)
	if !ok {
		return utils.LSMActionPause
	}
	m := parseDNSMessage(bs)
	if m == nil {
		// Invalid DNS message
		return utils.LSMActionCancel
	}
	s.respMap = m
	s.respUpdated = true
	return utils.LSMActionReset
}

func parseDNSMessage(msg []byte) analyzer.PropMap {
	dns := &layers.DNS{}
	err := dns.DecodeFromBytes(msg, gopacket.NilDecodeFeedback)
	if err != nil {
		// Not a DNS packet
		return nil
	}
	m := analyzer.PropMap{
		"id":     dns.ID,
		"qr":     dns.QR,
		"opcode": dns.OpCode,
		"aa":     dns.AA,
		"tc":     dns.TC,
		"rd":     dns.RD,
		"ra":     dns.RA,
		"z":      dns.Z,
		"rcode":  dns.ResponseCode,
	}
	if len(dns.Questions) > 0 {
		mQuestions := make([]analyzer.PropMap, len(dns.Questions))
		for i, q := range dns.Questions {
			mQuestions[i] = analyzer.PropMap{
				"name":  string(q.Name),
				"type":  q.Type,
				"class": q.Class,
			}
		}
		m["questions"] = mQuestions
	}
	if len(dns.Answers) > 0 {
		mAnswers := make([]analyzer.PropMap, len(dns.Answers))
		for i, rr := range dns.Answers {
			mAnswers[i] = dnsRRToPropMap(rr)
		}
		m["answers"] = mAnswers
	}
	if len(dns.Authorities) > 0 {
		mAuthorities := make([]analyzer.PropMap, len(dns.Authorities))
		for i, rr := range dns.Authorities {
			mAuthorities[i] = dnsRRToPropMap(rr)
		}
		m["authorities"] = mAuthorities
	}
	if len(dns.Additionals) > 0 {
		mAdditionals := make([]analyzer.PropMap, len(dns.Additionals))
		for i, rr := range dns.Additionals {
			mAdditionals[i] = dnsRRToPropMap(rr)
		}
		m["additionals"] = mAdditionals
	}
	return m
}

func dnsRRToPropMap(rr layers.DNSResourceRecord) analyzer.PropMap {
	m := analyzer.PropMap{
		"name":  string(rr.Name),
		"type":  rr.Type,
		"class": rr.Class,
		"ttl":   rr.TTL,
	}
	switch rr.Type {
	// These are not everything, but is
	// all we decided to support for now.
	case layers.DNSTypeA:
		m["a"] = rr.IP.String()
	case layers.DNSTypeAAAA:
		m["aaaa"] = rr.IP.String()
	case layers.DNSTypeNS:
		m["ns"] = string(rr.NS)
	case layers.DNSTypeCNAME:
		m["cname"] = string(rr.CNAME)
	case layers.DNSTypePTR:
		m["ptr"] = string(rr.PTR)
	case layers.DNSTypeTXT:
		m["txt"] = utils.ByteSlicesToStrings(rr.TXTs)
	case layers.DNSTypeMX:
		m["mx"] = string(rr.MX.Name)
	}
	return m
}
