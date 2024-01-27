package io

import (
	"context"
	"encoding/binary"
	"errors"
	"strconv"

	"github.com/coreos/go-iptables/iptables"
	"github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
)

const (
	nfqueueNum              = 100
	nfqueueMaxPacketLen     = 0xFFFF
	nfqueueDefaultQueueSize = 128

	nfqueueConnMarkAccept = 1001
	nfqueueConnMarkDrop   = 1002
)

var iptRulesForward = []iptRule{
	{"filter", "FORWARD", []string{"-m", "connmark", "--mark", strconv.Itoa(nfqueueConnMarkAccept), "-j", "ACCEPT"}},
	{"filter", "FORWARD", []string{"-m", "connmark", "--mark", strconv.Itoa(nfqueueConnMarkDrop), "-j", "DROP"}},
	{"filter", "FORWARD", []string{"-j", "NFQUEUE", "--queue-num", strconv.Itoa(nfqueueNum), "--queue-bypass"}},
}

var iptRulesLocal = []iptRule{
	{"filter", "INPUT", []string{"-m", "connmark", "--mark", strconv.Itoa(nfqueueConnMarkAccept), "-j", "ACCEPT"}},
	{"filter", "INPUT", []string{"-m", "connmark", "--mark", strconv.Itoa(nfqueueConnMarkDrop), "-j", "DROP"}},
	{"filter", "INPUT", []string{"-j", "NFQUEUE", "--queue-num", strconv.Itoa(nfqueueNum), "--queue-bypass"}},

	{"filter", "OUTPUT", []string{"-m", "connmark", "--mark", strconv.Itoa(nfqueueConnMarkAccept), "-j", "ACCEPT"}},
	{"filter", "OUTPUT", []string{"-m", "connmark", "--mark", strconv.Itoa(nfqueueConnMarkDrop), "-j", "DROP"}},
	{"filter", "OUTPUT", []string{"-j", "NFQUEUE", "--queue-num", strconv.Itoa(nfqueueNum), "--queue-bypass"}},
}

var _ PacketIO = (*nfqueuePacketIO)(nil)

var errNotNFQueuePacket = errors.New("not an NFQueue packet")

type nfqueuePacketIO struct {
	n     *nfqueue.Nfqueue
	local bool
	ipt4  *iptables.IPTables
	ipt6  *iptables.IPTables
}

type NFQueuePacketIOConfig struct {
	QueueSize uint32
	Local     bool
}

func NewNFQueuePacketIO(config NFQueuePacketIOConfig) (PacketIO, error) {
	if config.QueueSize == 0 {
		config.QueueSize = nfqueueDefaultQueueSize
	}
	ipt4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, err
	}
	ipt6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return nil, err
	}
	n, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      nfqueueNum,
		MaxPacketLen: nfqueueMaxPacketLen,
		MaxQueueLen:  config.QueueSize,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagConntrack,
	})
	if err != nil {
		return nil, err
	}
	io := &nfqueuePacketIO{
		n:     n,
		local: config.Local,
		ipt4:  ipt4,
		ipt6:  ipt6,
	}
	err = io.setupIpt(config.Local, false)
	if err != nil {
		_ = n.Close()
		return nil, err
	}
	return io, nil
}

func (n *nfqueuePacketIO) Register(ctx context.Context, cb PacketCallback) error {
	return n.n.RegisterWithErrorFunc(ctx,
		func(a nfqueue.Attribute) int {
			if a.PacketID == nil || a.Ct == nil || a.Payload == nil || len(*a.Payload) < 20 {
				// Invalid packet, ignore
				// 20 is the minimum possible size of an IP packet
				return 0
			}
			p := &nfqueuePacket{
				id:       *a.PacketID,
				streamID: ctIDFromCtBytes(*a.Ct),
				data:     *a.Payload,
			}
			return okBoolToInt(cb(p, nil))
		},
		func(e error) int {
			return okBoolToInt(cb(nil, e))
		})
}

func (n *nfqueuePacketIO) SetVerdict(p Packet, v Verdict, newPacket []byte) error {
	nP, ok := p.(*nfqueuePacket)
	if !ok {
		return &ErrInvalidPacket{Err: errNotNFQueuePacket}
	}
	switch v {
	case VerdictAccept:
		return n.n.SetVerdict(nP.id, nfqueue.NfAccept)
	case VerdictAcceptModify:
		return n.n.SetVerdictModPacket(nP.id, nfqueue.NfAccept, newPacket)
	case VerdictAcceptStream:
		return n.n.SetVerdictWithConnMark(nP.id, nfqueue.NfAccept, nfqueueConnMarkAccept)
	case VerdictDrop:
		return n.n.SetVerdict(nP.id, nfqueue.NfDrop)
	case VerdictDropStream:
		return n.n.SetVerdictWithConnMark(nP.id, nfqueue.NfDrop, nfqueueConnMarkDrop)
	default:
		// Invalid verdict, ignore for now
		return nil
	}
}

func (n *nfqueuePacketIO) setupIpt(local, remove bool) error {
	var rules []iptRule
	if local {
		rules = iptRulesLocal
	} else {
		rules = iptRulesForward
	}
	var err error
	if remove {
		err = iptsBatchDeleteIfExists([]*iptables.IPTables{n.ipt4, n.ipt6}, rules)
	} else {
		err = iptsBatchAppendUnique([]*iptables.IPTables{n.ipt4, n.ipt6}, rules)
	}
	if err != nil {
		return err
	}
	return nil
}

func (n *nfqueuePacketIO) Close() error {
	err := n.setupIpt(n.local, true)
	_ = n.n.Close()
	return err
}

var _ Packet = (*nfqueuePacket)(nil)

type nfqueuePacket struct {
	id       uint32
	streamID uint32
	data     []byte
}

func (p *nfqueuePacket) StreamID() uint32 {
	return p.streamID
}

func (p *nfqueuePacket) Data() []byte {
	return p.data
}

func okBoolToInt(ok bool) int {
	if ok {
		return 0
	} else {
		return 1
	}
}

type iptRule struct {
	Table, Chain string
	RuleSpec     []string
}

func iptsBatchAppendUnique(ipts []*iptables.IPTables, rules []iptRule) error {
	for _, r := range rules {
		for _, ipt := range ipts {
			err := ipt.AppendUnique(r.Table, r.Chain, r.RuleSpec...)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func iptsBatchDeleteIfExists(ipts []*iptables.IPTables, rules []iptRule) error {
	for _, r := range rules {
		for _, ipt := range ipts {
			err := ipt.DeleteIfExists(r.Table, r.Chain, r.RuleSpec...)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func ctIDFromCtBytes(ct []byte) uint32 {
	ctAttrs, err := netlink.UnmarshalAttributes(ct)
	if err != nil {
		return 0
	}
	for _, attr := range ctAttrs {
		if attr.Type == 12 { // CTA_ID
			return binary.BigEndian.Uint32(attr.Data)
		}
	}
	return 0
}
