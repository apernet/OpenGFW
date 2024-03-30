package udp

import (
	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

var _ analyzer.UDPAnalyzer = (*OpenVpnAnalyzer)(nil)
var _ analyzer.TCPAnalyzer = (*OpenVpnAnalyzer)(nil)

var _ analyzer.UDPStream = (*openVpnUdpStream)(nil)
var _ analyzer.TCPStream = (*openVpnTcpStream)(nil)

// Ref paper:
// https://www.usenix.org/system/files/sec22fall_xue-diwen.pdf

// OpenVPN Opcodes definitions from:
// https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/ssl_pkt.h
const (
	OpenVpnControlHardResetClientV1 = 1
	OpenVpnControlHardResetServerV1 = 2
	OpenVpnControlSoftResetV1       = 3
	OpenVpnControlV1                = 4
	OpenVpnAckV1                    = 5
	OpenVpnDataV1                   = 6
	OpenVpnControlHardResetClientV2 = 7
	OpenVpnControlHardResetServerV2 = 8
	OpenVpnDataV2                   = 9
	OpenVpnControlHardResetClientV3 = 10
	OpenVpnControlWkcV1             = 11
)

const (
	OpenVpnMinPktLen          = 6
	OpenVpnTcpPktDefaultLimit = 256
	OpenVpnUdpPktDefaultLimit = 256
)

type OpenVpnAnalyzer struct{}

func (a *OpenVpnAnalyzer) Name() string {
	return "openvpn"
}

func (a *OpenVpnAnalyzer) Limit() int {
	return 0
}

func (a *OpenVpnAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return newOpenVpnUdpStream(logger)
}

func (a *OpenVpnAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return newOpenVpnTcpStream(logger)
}

type openVpnPkt struct {
	pktLen uint16 // 16 bits, TCP proto only
	opcode byte   // 5 bits
	_keyId byte   // 3 bits, not used

	// We don't care about the rest of the packet
	// payload []byte
}

type openVpnStream struct {
	logger analyzer.Logger

	reqUpdated bool
	reqLSM     *utils.LinearStateMachine
	reqDone    bool

	respUpdated bool
	respLSM     *utils.LinearStateMachine
	respDone    bool

	rxPktCnt int
	txPktCnt int
	pktLimit int

	reqPktParse  func() (*openVpnPkt, utils.LSMAction)
	respPktParse func() (*openVpnPkt, utils.LSMAction)

	lastOpcode byte
}

func (o *openVpnStream) parseCtlHardResetClient() utils.LSMAction {
	pkt, action := o.reqPktParse()
	if action != utils.LSMActionNext {
		return action
	}

	if pkt.opcode != OpenVpnControlHardResetClientV1 &&
		pkt.opcode != OpenVpnControlHardResetClientV2 &&
		pkt.opcode != OpenVpnControlHardResetClientV3 {
		return utils.LSMActionCancel
	}
	o.lastOpcode = pkt.opcode

	return utils.LSMActionNext
}

func (o *openVpnStream) parseCtlHardResetServer() utils.LSMAction {
	if o.lastOpcode != OpenVpnControlHardResetClientV1 &&
		o.lastOpcode != OpenVpnControlHardResetClientV2 &&
		o.lastOpcode != OpenVpnControlHardResetClientV3 {
		return utils.LSMActionCancel
	}

	pkt, action := o.respPktParse()
	if action != utils.LSMActionNext {
		return action
	}

	if pkt.opcode != OpenVpnControlHardResetServerV1 &&
		pkt.opcode != OpenVpnControlHardResetServerV2 {
		return utils.LSMActionCancel
	}
	o.lastOpcode = pkt.opcode

	return utils.LSMActionNext
}

func (o *openVpnStream) parseReq() utils.LSMAction {
	pkt, action := o.reqPktParse()
	if action != utils.LSMActionNext {
		return action
	}

	if pkt.opcode != OpenVpnControlSoftResetV1 &&
		pkt.opcode != OpenVpnControlV1 &&
		pkt.opcode != OpenVpnAckV1 &&
		pkt.opcode != OpenVpnDataV1 &&
		pkt.opcode != OpenVpnDataV2 &&
		pkt.opcode != OpenVpnControlWkcV1 {
		return utils.LSMActionCancel
	}

	o.txPktCnt += 1
	o.reqUpdated = true

	return utils.LSMActionPause
}

func (o *openVpnStream) parseResp() utils.LSMAction {
	pkt, action := o.respPktParse()
	if action != utils.LSMActionNext {
		return action
	}

	if pkt.opcode != OpenVpnControlSoftResetV1 &&
		pkt.opcode != OpenVpnControlV1 &&
		pkt.opcode != OpenVpnAckV1 &&
		pkt.opcode != OpenVpnDataV1 &&
		pkt.opcode != OpenVpnDataV2 &&
		pkt.opcode != OpenVpnControlWkcV1 {
		return utils.LSMActionCancel
	}

	o.rxPktCnt += 1
	o.respUpdated = true

	return utils.LSMActionPause
}

type openVpnUdpStream struct {
	openVpnStream
	curPkt []byte
	// We don't introduce `invalidCount` here to decrease the false positive rate
	// invalidCount int
}

func newOpenVpnUdpStream(logger analyzer.Logger) *openVpnUdpStream {
	s := &openVpnUdpStream{
		openVpnStream: openVpnStream{
			logger:   logger,
			pktLimit: OpenVpnUdpPktDefaultLimit,
		},
	}
	s.respPktParse = s.parsePkt
	s.reqPktParse = s.parsePkt
	s.reqLSM = utils.NewLinearStateMachine(
		s.parseCtlHardResetClient,
		s.parseReq,
	)
	s.respLSM = utils.NewLinearStateMachine(
		s.parseCtlHardResetServer,
		s.parseResp,
	)
	return s
}

func (o *openVpnUdpStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, d bool) {
	if len(data) == 0 {
		return nil, false
	}
	var update *analyzer.PropUpdate
	var cancelled bool
	o.curPkt = data
	if rev {
		o.respUpdated = false
		cancelled, o.respDone = o.respLSM.Run()
		if o.respUpdated {
			update = &analyzer.PropUpdate{
				Type: analyzer.PropUpdateMerge,
				M:    analyzer.PropMap{"rx_pkt_cnt": o.rxPktCnt},
			}
			o.respUpdated = false
		}
	} else {
		o.reqUpdated = false
		cancelled, o.reqDone = o.reqLSM.Run()
		if o.reqUpdated {
			update = &analyzer.PropUpdate{
				Type: analyzer.PropUpdateMerge,
				M:    analyzer.PropMap{"tx_pkt_cnt": o.txPktCnt},
			}
			o.reqUpdated = false
		}
	}

	return update, cancelled || (o.reqDone && o.respDone) || o.rxPktCnt+o.txPktCnt > o.pktLimit
}

func (o *openVpnUdpStream) Close(limited bool) *analyzer.PropUpdate {
	return nil
}

// Parse OpenVpn UDP packet.
func (o *openVpnUdpStream) parsePkt() (p *openVpnPkt, action utils.LSMAction) {
	if o.curPkt == nil {
		return nil, utils.LSMActionPause
	}

	if !OpenVpnCheckForValidOpcode(o.curPkt[0] >> 3) {
		return nil, utils.LSMActionCancel
	}

	// Parse packet header
	p = &openVpnPkt{}
	p.opcode = o.curPkt[0] >> 3
	p._keyId = o.curPkt[0] & 0x07

	o.curPkt = nil
	return p, utils.LSMActionNext
}

type openVpnTcpStream struct {
	openVpnStream
	reqBuf  *utils.ByteBuffer
	respBuf *utils.ByteBuffer
}

func newOpenVpnTcpStream(logger analyzer.Logger) *openVpnTcpStream {
	s := &openVpnTcpStream{
		openVpnStream: openVpnStream{
			logger:   logger,
			pktLimit: OpenVpnTcpPktDefaultLimit,
		},
		reqBuf:  &utils.ByteBuffer{},
		respBuf: &utils.ByteBuffer{},
	}
	s.respPktParse = func() (*openVpnPkt, utils.LSMAction) {
		return s.parsePkt(true)
	}
	s.reqPktParse = func() (*openVpnPkt, utils.LSMAction) {
		return s.parsePkt(false)
	}
	s.reqLSM = utils.NewLinearStateMachine(
		s.parseCtlHardResetClient,
		s.parseReq,
	)
	s.respLSM = utils.NewLinearStateMachine(
		s.parseCtlHardResetServer,
		s.parseResp,
	)
	return s
}

func (o *openVpnTcpStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, d bool) {
	if skip != 0 {
		return nil, true
	}
	if len(data) == 0 {
		return nil, false
	}
	var update *analyzer.PropUpdate
	var cancelled bool
	if rev {
		o.respBuf.Append(data)
		o.respUpdated = false
		cancelled, o.respDone = o.respLSM.Run()
		if o.respUpdated {
			update = &analyzer.PropUpdate{
				Type: analyzer.PropUpdateMerge,
				M:    analyzer.PropMap{"rx_pkt_cnt": o.rxPktCnt},
			}
			o.respUpdated = false
		}
	} else {
		o.reqBuf.Append(data)
		o.reqUpdated = false
		cancelled, o.reqDone = o.reqLSM.Run()
		if o.reqUpdated {
			update = &analyzer.PropUpdate{
				Type: analyzer.PropUpdateMerge,
				M:    analyzer.PropMap{"tx_pkt_cnt": o.txPktCnt},
			}
			o.reqUpdated = false
		}
	}

	return update, cancelled || (o.reqDone && o.respDone) || o.rxPktCnt+o.txPktCnt > o.pktLimit
}

func (o *openVpnTcpStream) Close(limited bool) *analyzer.PropUpdate {
	o.reqBuf.Reset()
	o.respBuf.Reset()
	return nil
}

// Parse OpenVpn TCP packet.
func (o *openVpnTcpStream) parsePkt(rev bool) (p *openVpnPkt, action utils.LSMAction) {
	var buffer *utils.ByteBuffer
	if rev {
		buffer = o.respBuf
	} else {
		buffer = o.reqBuf
	}

	// Parse packet length
	pktLen, ok := buffer.GetUint16(false, false)
	if !ok {
		return nil, utils.LSMActionPause
	}

	if pktLen < OpenVpnMinPktLen {
		return nil, utils.LSMActionCancel
	}

	pktOp, ok := buffer.Get(3, false)
	if !ok {
		return nil, utils.LSMActionPause
	}
	if !OpenVpnCheckForValidOpcode(pktOp[2] >> 3) {
		return nil, utils.LSMActionCancel
	}

	pkt, ok := buffer.Get(int(pktLen)+2, true)
	if !ok {
		return nil, utils.LSMActionPause
	}
	pkt = pkt[2:]

	// Parse packet header
	p = &openVpnPkt{}
	p.pktLen = pktLen
	p.opcode = pkt[0] >> 3
	p._keyId = pkt[0] & 0x07

	return p, utils.LSMActionNext
}

func OpenVpnCheckForValidOpcode(opcode byte) bool {
	switch opcode {
	case OpenVpnControlHardResetClientV1,
		OpenVpnControlHardResetServerV1,
		OpenVpnControlSoftResetV1,
		OpenVpnControlV1,
		OpenVpnAckV1,
		OpenVpnDataV1,
		OpenVpnControlHardResetClientV2,
		OpenVpnControlHardResetServerV2,
		OpenVpnDataV2,
		OpenVpnControlHardResetClientV3,
		OpenVpnControlWkcV1:
		return true
	}
	return false
}
