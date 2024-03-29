package udp

import (
	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/internal"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

var _ analyzer.UDPAnalyzer = (*OpenVpnAnalyzer)(nil)
var _ analyzer.UDPStream = (*openVpnStream)(nil)

type OpenVpnAnalyzer struct{}

func (a *OpenVpnAnalyzer) Name() string {
	return "openvpn_udp"
}

func (a *OpenVpnAnalyzer) Limit() int {
	return 0
}

func (a *OpenVpnAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return newOpenVPNTCPStream(logger)
}

type openVpnStream struct {
	logger analyzer.Logger
	// We don't introduce `invalidCount` here to decrease the false positive rate
	// invalidCount int

	curPkt []byte

	reqUpdated bool
	reqLSM     *utils.LinearStateMachine
	reqDone    bool

	respUpdated bool
	respLSM     *utils.LinearStateMachine
	respDone    bool

	rxPktCnt int
	txPktCnt int
	pktLimit int

	lastOpcode byte
}

type openVpnUdpPkt struct {
	opcode byte // 5 bits
	_keyId byte // 3 bits, not used

	// We don't care about the rest of the packet
	// payload []byte
}

func newOpenVPNTCPStream(logger analyzer.Logger) *openVpnStream {
	s := &openVpnStream{
		logger:   logger,
		pktLimit: internal.OpenVpnUdpPktDefaultLimit,
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

func (o *openVpnStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, d bool) {
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

func (o *openVpnStream) Close(limited bool) *analyzer.PropUpdate {
	return nil
}

func (o *openVpnStream) parseCtlHardResetClient() utils.LSMAction {
	pkt, action := o.parsePkt()
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

	pkt, action := o.parsePkt()
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
	pkt, action := o.parsePkt()
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
	pkt, action := o.parsePkt()
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
func (o *openVpnStream) parsePkt() (p *openVpnUdpPkt, action utils.LSMAction) {
	if o.curPkt == nil {
		return nil, utils.LSMActionPause
	}

	if !internal.OpenVpnCheckForValidOpcode(o.curPkt[0] >> 3) {
		return nil, utils.LSMActionCancel
	}

	// Parse packet header
	p = &openVpnUdpPkt{}
	p.opcode = o.curPkt[0] >> 3
	p._keyId = o.curPkt[0] & 0x07

	o.curPkt = nil
	return p, utils.LSMActionNext
}
