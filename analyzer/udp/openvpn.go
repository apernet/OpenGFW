package udp

import (
	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

var (
	_ analyzer.UDPAnalyzer = (*OpenVPNAnalyzer)(nil)
	_ analyzer.TCPAnalyzer = (*OpenVPNAnalyzer)(nil)
)

var (
	_ analyzer.UDPStream = (*openvpnUDPStream)(nil)
	_ analyzer.TCPStream = (*openvpnTCPStream)(nil)
)

// Ref paper:
// https://www.usenix.org/system/files/sec22fall_xue-diwen.pdf

// OpenVPN Opcodes definitions from:
// https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/ssl_pkt.h
const (
	OpenVPNControlHardResetClientV1 = 1
	OpenVPNControlHardResetServerV1 = 2
	OpenVPNControlSoftResetV1       = 3
	OpenVPNControlV1                = 4
	OpenVPNAckV1                    = 5
	OpenVPNDataV1                   = 6
	OpenVPNControlHardResetClientV2 = 7
	OpenVPNControlHardResetServerV2 = 8
	OpenVPNDataV2                   = 9
	OpenVPNControlHardResetClientV3 = 10
	OpenVPNControlWkcV1             = 11
)

const (
	OpenVPNMinPktLen          = 6
	OpenVPNTCPPktDefaultLimit = 256
	OpenVPNUDPPktDefaultLimit = 256
)

type OpenVPNAnalyzer struct{}

func (a *OpenVPNAnalyzer) Name() string {
	return "openvpn"
}

func (a *OpenVPNAnalyzer) Limit() int {
	return 0
}

func (a *OpenVPNAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return newOpenVPNUDPStream(logger)
}

func (a *OpenVPNAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return newOpenVPNTCPStream(logger)
}

type openvpnPkt struct {
	pktLen uint16 // 16 bits, TCP proto only
	opcode byte   // 5 bits
	_keyId byte   // 3 bits, not used

	// We don't care about the rest of the packet
	// payload []byte
}

type openvpnStream struct {
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

	reqPktParse  func() (*openvpnPkt, utils.LSMAction)
	respPktParse func() (*openvpnPkt, utils.LSMAction)

	lastOpcode byte
}

func (o *openvpnStream) parseCtlHardResetClient() utils.LSMAction {
	pkt, action := o.reqPktParse()
	if action != utils.LSMActionNext {
		return action
	}

	if pkt.opcode != OpenVPNControlHardResetClientV1 &&
		pkt.opcode != OpenVPNControlHardResetClientV2 &&
		pkt.opcode != OpenVPNControlHardResetClientV3 {
		return utils.LSMActionCancel
	}
	o.lastOpcode = pkt.opcode

	return utils.LSMActionNext
}

func (o *openvpnStream) parseCtlHardResetServer() utils.LSMAction {
	if o.lastOpcode != OpenVPNControlHardResetClientV1 &&
		o.lastOpcode != OpenVPNControlHardResetClientV2 &&
		o.lastOpcode != OpenVPNControlHardResetClientV3 {
		return utils.LSMActionCancel
	}

	pkt, action := o.respPktParse()
	if action != utils.LSMActionNext {
		return action
	}

	if pkt.opcode != OpenVPNControlHardResetServerV1 &&
		pkt.opcode != OpenVPNControlHardResetServerV2 {
		return utils.LSMActionCancel
	}
	o.lastOpcode = pkt.opcode

	return utils.LSMActionNext
}

func (o *openvpnStream) parseReq() utils.LSMAction {
	pkt, action := o.reqPktParse()
	if action != utils.LSMActionNext {
		return action
	}

	if pkt.opcode != OpenVPNControlSoftResetV1 &&
		pkt.opcode != OpenVPNControlV1 &&
		pkt.opcode != OpenVPNAckV1 &&
		pkt.opcode != OpenVPNDataV1 &&
		pkt.opcode != OpenVPNDataV2 &&
		pkt.opcode != OpenVPNControlWkcV1 {
		return utils.LSMActionCancel
	}

	o.txPktCnt += 1
	o.reqUpdated = true

	return utils.LSMActionPause
}

func (o *openvpnStream) parseResp() utils.LSMAction {
	pkt, action := o.respPktParse()
	if action != utils.LSMActionNext {
		return action
	}

	if pkt.opcode != OpenVPNControlSoftResetV1 &&
		pkt.opcode != OpenVPNControlV1 &&
		pkt.opcode != OpenVPNAckV1 &&
		pkt.opcode != OpenVPNDataV1 &&
		pkt.opcode != OpenVPNDataV2 &&
		pkt.opcode != OpenVPNControlWkcV1 {
		return utils.LSMActionCancel
	}

	o.rxPktCnt += 1
	o.respUpdated = true

	return utils.LSMActionPause
}

type openvpnUDPStream struct {
	openvpnStream
	curPkt []byte
	// We don't introduce `invalidCount` here to decrease the false positive rate
	// invalidCount int
}

func newOpenVPNUDPStream(logger analyzer.Logger) *openvpnUDPStream {
	s := &openvpnUDPStream{
		openvpnStream: openvpnStream{
			logger:   logger,
			pktLimit: OpenVPNUDPPktDefaultLimit,
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

func (o *openvpnUDPStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, d bool) {
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
				Type: analyzer.PropUpdateReplace,
				M:    analyzer.PropMap{"rx_pkt_cnt": o.rxPktCnt, "tx_pkt_cnt": o.txPktCnt},
			}
			o.respUpdated = false
		}
	} else {
		o.reqUpdated = false
		cancelled, o.reqDone = o.reqLSM.Run()
		if o.reqUpdated {
			update = &analyzer.PropUpdate{
				Type: analyzer.PropUpdateReplace,
				M:    analyzer.PropMap{"rx_pkt_cnt": o.rxPktCnt, "tx_pkt_cnt": o.txPktCnt},
			}
			o.reqUpdated = false
		}
	}

	return update, cancelled || (o.reqDone && o.respDone) || o.rxPktCnt+o.txPktCnt > o.pktLimit
}

func (o *openvpnUDPStream) Close(limited bool) *analyzer.PropUpdate {
	return nil
}

// Parse OpenVPN UDP packet.
func (o *openvpnUDPStream) parsePkt() (p *openvpnPkt, action utils.LSMAction) {
	if o.curPkt == nil {
		return nil, utils.LSMActionPause
	}

	if !OpenVPNCheckForValidOpcode(o.curPkt[0] >> 3) {
		return nil, utils.LSMActionCancel
	}

	// Parse packet header
	p = &openvpnPkt{}
	p.opcode = o.curPkt[0] >> 3
	p._keyId = o.curPkt[0] & 0x07

	o.curPkt = nil
	return p, utils.LSMActionNext
}

type openvpnTCPStream struct {
	openvpnStream
	reqBuf  *utils.ByteBuffer
	respBuf *utils.ByteBuffer
}

func newOpenVPNTCPStream(logger analyzer.Logger) *openvpnTCPStream {
	s := &openvpnTCPStream{
		openvpnStream: openvpnStream{
			logger:   logger,
			pktLimit: OpenVPNTCPPktDefaultLimit,
		},
		reqBuf:  &utils.ByteBuffer{},
		respBuf: &utils.ByteBuffer{},
	}
	s.respPktParse = func() (*openvpnPkt, utils.LSMAction) {
		return s.parsePkt(true)
	}
	s.reqPktParse = func() (*openvpnPkt, utils.LSMAction) {
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

func (o *openvpnTCPStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, d bool) {
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
				Type: analyzer.PropUpdateReplace,
				M:    analyzer.PropMap{"rx_pkt_cnt": o.rxPktCnt, "tx_pkt_cnt": o.txPktCnt},
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
				M:    analyzer.PropMap{"rx_pkt_cnt": o.rxPktCnt, "tx_pkt_cnt": o.txPktCnt},
			}
			o.reqUpdated = false
		}
	}

	return update, cancelled || (o.reqDone && o.respDone) || o.rxPktCnt+o.txPktCnt > o.pktLimit
}

func (o *openvpnTCPStream) Close(limited bool) *analyzer.PropUpdate {
	o.reqBuf.Reset()
	o.respBuf.Reset()
	return nil
}

// Parse OpenVPN TCP packet.
func (o *openvpnTCPStream) parsePkt(rev bool) (p *openvpnPkt, action utils.LSMAction) {
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

	if pktLen < OpenVPNMinPktLen {
		return nil, utils.LSMActionCancel
	}

	pktOp, ok := buffer.Get(3, false)
	if !ok {
		return nil, utils.LSMActionPause
	}
	if !OpenVPNCheckForValidOpcode(pktOp[2] >> 3) {
		return nil, utils.LSMActionCancel
	}

	pkt, ok := buffer.Get(int(pktLen)+2, true)
	if !ok {
		return nil, utils.LSMActionPause
	}
	pkt = pkt[2:]

	// Parse packet header
	p = &openvpnPkt{}
	p.pktLen = pktLen
	p.opcode = pkt[0] >> 3
	p._keyId = pkt[0] & 0x07

	return p, utils.LSMActionNext
}

func OpenVPNCheckForValidOpcode(opcode byte) bool {
	switch opcode {
	case OpenVPNControlHardResetClientV1,
		OpenVPNControlHardResetServerV1,
		OpenVPNControlSoftResetV1,
		OpenVPNControlV1,
		OpenVPNAckV1,
		OpenVPNDataV1,
		OpenVPNControlHardResetClientV2,
		OpenVPNControlHardResetServerV2,
		OpenVPNDataV2,
		OpenVPNControlHardResetClientV3,
		OpenVPNControlWkcV1:
		return true
	}
	return false
}
