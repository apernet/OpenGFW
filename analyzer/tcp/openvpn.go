package tcp

import (
	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/internal"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

var _ analyzer.TCPAnalyzer = (*OpenVpnAnalyzer)(nil)
var _ analyzer.TCPStream = (*openVpnStream)(nil)

type OpenVpnAnalyzer struct{}

func (a *OpenVpnAnalyzer) Name() string {
	return "openvpn_tcp"
}

func (a *OpenVpnAnalyzer) Limit() int {
	return 0
}

func (a *OpenVpnAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return newOpenVpnTCPStream(logger)
}

type openVpnStream struct {
	logger analyzer.Logger

	reqBuf     *utils.ByteBuffer
	reqUpdated bool
	reqLSM     *utils.LinearStateMachine
	reqDone    bool

	respBuf     *utils.ByteBuffer
	respUpdated bool
	respLSM     *utils.LinearStateMachine
	respDone    bool

	rxPktCnt int
	txPktCnt int
	pktLimit int

	lastOpcode byte
}

type openVpnTcpPkt struct {
	pktLen uint16
	opcode byte // 5 bits
	_keyId byte // 3 bits, not used

	// We don't care about the rest of the packet
	// payload []byte
}

func newOpenVpnTCPStream(logger analyzer.Logger) *openVpnStream {
	s := &openVpnStream{
		logger:   logger,
		reqBuf:   &utils.ByteBuffer{},
		respBuf:  &utils.ByteBuffer{},
		pktLimit: internal.OpenVpnTcpPktDefaultLimit,
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

func (o *openVpnStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, d bool) {
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

func (o *openVpnStream) Close(limited bool) *analyzer.PropUpdate {
	o.reqBuf.Reset()
	o.respBuf.Reset()
	return nil
}

func (o *openVpnStream) parseCtlHardResetClient() utils.LSMAction {
	pkt, action := o.parsePkt(false)
	if action != utils.LSMActionNext {
		return action
	}

	if pkt.opcode != internal.OpenVpnControlHardResetClientV1 &&
		pkt.opcode != internal.OpenVpnControlHardResetClientV2 &&
		pkt.opcode != internal.OpenVpnControlHardResetClientV3 {
		return utils.LSMActionCancel
	}
	o.lastOpcode = pkt.opcode

	return utils.LSMActionNext
}

func (o *openVpnStream) parseCtlHardResetServer() utils.LSMAction {
	if o.lastOpcode != internal.OpenVpnControlHardResetClientV1 &&
		o.lastOpcode != internal.OpenVpnControlHardResetClientV2 &&
		o.lastOpcode != internal.OpenVpnControlHardResetClientV3 {
		return utils.LSMActionCancel
	}

	pkt, action := o.parsePkt(true)
	if action != utils.LSMActionNext {
		return action
	}

	if pkt.opcode != internal.OpenVpnControlHardResetServerV1 &&
		pkt.opcode != internal.OpenVpnControlHardResetServerV2 {
		return utils.LSMActionCancel
	}
	o.lastOpcode = pkt.opcode

	return utils.LSMActionNext
}

func (o *openVpnStream) parseReq() utils.LSMAction {
	pkt, action := o.parsePkt(false)
	if action != utils.LSMActionNext {
		return action
	}

	if pkt.opcode != internal.OpenVpnControlSoftResetV1 &&
		pkt.opcode != internal.OpenVpnControlV1 &&
		pkt.opcode != internal.OpenVpnAckV1 &&
		pkt.opcode != internal.OpenVpnDataV1 &&
		pkt.opcode != internal.OpenVpnDataV2 &&
		pkt.opcode != internal.OpenVpnControlWkcV1 {
		return utils.LSMActionCancel
	}

	o.txPktCnt += 1
	o.reqUpdated = true

	return utils.LSMActionPause
}

func (o *openVpnStream) parseResp() utils.LSMAction {
	pkt, action := o.parsePkt(true)
	if action != utils.LSMActionNext {
		return action
	}

	if pkt.opcode != internal.OpenVpnControlSoftResetV1 &&
		pkt.opcode != internal.OpenVpnControlV1 &&
		pkt.opcode != internal.OpenVpnAckV1 &&
		pkt.opcode != internal.OpenVpnDataV1 &&
		pkt.opcode != internal.OpenVpnDataV2 &&
		pkt.opcode != internal.OpenVpnControlWkcV1 {
		return utils.LSMActionCancel
	}

	o.rxPktCnt += 1
	o.respUpdated = true

	return utils.LSMActionPause
}

// Parse OpenVpn packet header but not consume buffer.
func (o *openVpnStream) parsePkt(rev bool) (p *openVpnTcpPkt, action utils.LSMAction) {
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

	if pktLen < internal.OpenVpnMinPktLen {
		return nil, utils.LSMActionCancel
	}

	pktOp, ok := buffer.Get(3, false)
	if !ok {
		return nil, utils.LSMActionPause
	}
	if !internal.OpenVpnCheckForValidOpcode(pktOp[2] >> 3) {
		return nil, utils.LSMActionCancel
	}

	pkt, ok := buffer.Get(int(pktLen)+2, true)
	if !ok {
		return nil, utils.LSMActionPause
	}
	pkt = pkt[2:]

	// Parse packet header
	p = &openVpnTcpPkt{}
	p.pktLen = pktLen
	p.opcode = pkt[0] >> 3
	p._keyId = pkt[0] & 0x07

	return p, utils.LSMActionNext
}
