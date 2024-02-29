package io

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	nfqueueNum              = 100
	nfqueueMaxPacketLen     = 0xFFFF
	nfqueueDefaultQueueSize = 128

	nfqueueConnMarkAccept = 1001
	nfqueueConnMarkDrop   = 1002

	nftFamily = "inet"
	nftTable  = "opengfw"
)

var nftRulesForward = fmt.Sprintf(`
define ACCEPT_CTMARK=%d
define DROP_CTMARK=%d
define QUEUE_NUM=%d

table %s %s {
  chain FORWARD {
    type filter hook forward priority filter; policy accept;

    ct mark $ACCEPT_CTMARK counter accept
    ct mark $DROP_CTMARK counter drop
    counter queue num $QUEUE_NUM bypass
  }
}
`, nfqueueConnMarkAccept, nfqueueConnMarkDrop, nfqueueNum, nftFamily, nftTable)

var nftRulesLocal = fmt.Sprintf(`
define ACCEPT_CTMARK=%d
define DROP_CTMARK=%d
define QUEUE_NUM=%d

table %s %s {
  chain INPUT {
    type filter hook input priority filter; policy accept;

    ct mark $ACCEPT_CTMARK counter accept
    ct mark $DROP_CTMARK counter drop
    counter queue num $QUEUE_NUM bypass
  }
  chain OUTPUT {
    type filter hook output priority filter; policy accept;

    ct mark $ACCEPT_CTMARK counter accept
    ct mark $DROP_CTMARK counter drop
    counter queue num $QUEUE_NUM bypass
  }
}
`, nfqueueConnMarkAccept, nfqueueConnMarkDrop, nfqueueNum, nftFamily, nftTable)

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
	rSet  bool // whether the nftables/iptables rules have been set

	// iptables not nil = use iptables instead of nftables
	ipt4 *iptables.IPTables
	ipt6 *iptables.IPTables
}

type NFQueuePacketIOConfig struct {
	QueueSize   uint32
	ReadBuffer  int
	WriteBuffer int
	Local       bool
}

func NewNFQueuePacketIO(config NFQueuePacketIOConfig) (PacketIO, error) {
	if config.QueueSize == 0 {
		config.QueueSize = nfqueueDefaultQueueSize
	}
	var ipt4, ipt6 *iptables.IPTables
	var err error
	if nftCheck() != nil {
		// We prefer nftables, but if it's not available, fall back to iptables
		ipt4, err = iptables.NewWithProtocol(iptables.ProtocolIPv4)
		if err != nil {
			return nil, err
		}
		ipt6, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return nil, err
		}
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
	if config.ReadBuffer > 0 {
		err = n.Con.SetReadBuffer(config.ReadBuffer)
		if err != nil {
			_ = n.Close()
			return nil, err
		}
	}
	if config.WriteBuffer > 0 {
		err = n.Con.SetWriteBuffer(config.WriteBuffer)
		if err != nil {
			_ = n.Close()
			return nil, err
		}
	}
	return &nfqueuePacketIO{
		n:     n,
		local: config.Local,
		ipt4:  ipt4,
		ipt6:  ipt6,
	}, nil
}

func (n *nfqueuePacketIO) Register(ctx context.Context, cb PacketCallback) error {
	err := n.n.RegisterWithErrorFunc(ctx,
		func(a nfqueue.Attribute) int {
			if ok, verdict := n.packetAttributeSanityCheck(a); !ok {
				if a.PacketID != nil {
					_ = n.n.SetVerdict(*a.PacketID, verdict)
				}
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
			if opErr := (*netlink.OpError)(nil); errors.As(e, &opErr) {
				if errors.Is(opErr.Err, unix.ENOBUFS) {
					// Kernel buffer temporarily full, ignore
					return 0
				}
			}
			return okBoolToInt(cb(nil, e))
		})
	if err != nil {
		return err
	}
	if !n.rSet {
		if n.ipt4 != nil {
			err = n.setupIpt(n.local, false)
		} else {
			err = n.setupNft(n.local, false)
		}
		if err != nil {
			return err
		}
		n.rSet = true
	}
	return nil
}

func (n *nfqueuePacketIO) packetAttributeSanityCheck(a nfqueue.Attribute) (ok bool, verdict int) {
	if a.PacketID == nil {
		// Re-inject to NFQUEUE is actually not possible in this condition
		return false, -1
	}
	if a.Payload == nil || len(*a.Payload) < 20 {
		// 20 is the minimum possible size of an IP packet
		return false, nfqueue.NfDrop
	}
	if a.Ct == nil {
		// Multicast packets may not have a conntrack, but only appear in local mode
		if n.local {
			return false, nfqueue.NfAccept
		}
		return false, nfqueue.NfDrop
	}
	return true, -1
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

func (n *nfqueuePacketIO) Close() error {
	if n.rSet {
		if n.ipt4 != nil {
			_ = n.setupIpt(n.local, true)
		} else {
			_ = n.setupNft(n.local, true)
		}
		n.rSet = false
	}
	return n.n.Close()
}

func (n *nfqueuePacketIO) setupNft(local, remove bool) error {
	var rules string
	if local {
		rules = nftRulesLocal
	} else {
		rules = nftRulesForward
	}
	var err error
	if remove {
		err = nftDelete(nftFamily, nftTable)
	} else {
		// Delete first to make sure no leftover rules
		_ = nftDelete(nftFamily, nftTable)
		err = nftAdd(rules)
	}
	if err != nil {
		return err
	}
	return nil
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

func nftCheck() error {
	_, err := exec.LookPath("nft")
	if err != nil {
		return err
	}
	return nil
}

func nftAdd(input string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(input)
	return cmd.Run()
}

func nftDelete(family, table string) error {
	cmd := exec.Command("nft", "delete", "table", family, table)
	return cmd.Run()
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
