package io

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	nfqueueDefaultQueueNum  = 100
	nfqueueMaxPacketLen     = 0xFFFF
	nfqueueDefaultQueueSize = 128

	nfqueueDefaultConnMarkAccept = 1001

	nftFamily       = "inet"
	nftDefaultTable = "opengfw"
)

func (n *nfqueuePacketIO) generateNftRules() (*nftTableSpec, error) {
	if n.local && n.rst {
		return nil, errors.New("tcp rst is not supported in local mode")
	}
	table := &nftTableSpec{
		Family: nftFamily,
		Table:  n.table,
	}
	table.Defines = append(table.Defines, fmt.Sprintf("define ACCEPT_CTMARK=%d", n.connMarkAccept))
	table.Defines = append(table.Defines, fmt.Sprintf("define DROP_CTMARK=%d", n.connMarkDrop))
	table.Defines = append(table.Defines, fmt.Sprintf("define QUEUE_NUM=%d", n.queueNum))
	if n.local {
		table.Chains = []nftChainSpec{
			{Chain: "INPUT", Header: "type filter hook input priority filter; policy accept;"},
			{Chain: "OUTPUT", Header: "type filter hook output priority filter; policy accept;"},
		}
	} else {
		table.Chains = []nftChainSpec{
			{Chain: "FORWARD", Header: "type filter hook forward priority filter; policy accept;"},
		}
	}
	for i := range table.Chains {
		c := &table.Chains[i]
		c.Rules = append(c.Rules, "meta mark $ACCEPT_CTMARK ct mark set $ACCEPT_CTMARK") // Bypass protected connections
		c.Rules = append(c.Rules, "ct mark $ACCEPT_CTMARK counter accept")
		if n.rst {
			c.Rules = append(c.Rules, "ip protocol tcp ct mark $DROP_CTMARK counter reject with tcp reset")
		}
		c.Rules = append(c.Rules, "ct mark $DROP_CTMARK counter drop")
		c.Rules = append(c.Rules, "counter queue num $QUEUE_NUM bypass")
	}
	return table, nil
}

func (n *nfqueuePacketIO) generateIptRules() ([]iptRule, error) {
	if n.local && n.rst {
		return nil, errors.New("tcp rst is not supported in local mode")
	}
	var chains []string
	if n.local {
		chains = []string{"INPUT", "OUTPUT"}
	} else {
		chains = []string{"FORWARD"}
	}
	rules := make([]iptRule, 0, 4*len(chains))
	for _, chain := range chains {
		// Bypass protected connections
		rules = append(rules, iptRule{"filter", chain, []string{"-m", "mark", "--mark", strconv.Itoa(n.connMarkAccept), "-j", "CONNMARK", "--set-mark", strconv.Itoa(n.connMarkAccept)}})
		rules = append(rules, iptRule{"filter", chain, []string{"-m", "connmark", "--mark", strconv.Itoa(n.connMarkAccept), "-j", "ACCEPT"}})
		if n.rst {
			rules = append(rules, iptRule{"filter", chain, []string{"-p", "tcp", "-m", "connmark", "--mark", strconv.Itoa(n.connMarkDrop), "-j", "REJECT", "--reject-with", "tcp-reset"}})
		}
		rules = append(rules, iptRule{"filter", chain, []string{"-m", "connmark", "--mark", strconv.Itoa(n.connMarkDrop), "-j", "DROP"}})
		rules = append(rules, iptRule{"filter", chain, []string{"-j", "NFQUEUE", "--queue-num", strconv.Itoa(n.queueNum), "--queue-bypass"}})
	}

	return rules, nil
}

var _ PacketIO = (*nfqueuePacketIO)(nil)

var errNotNFQueuePacket = errors.New("not an NFQueue packet")

type nfqueuePacketIO struct {
	n              *nfqueue.Nfqueue
	local          bool
	rst            bool
	rSet           bool // whether the nftables/iptables rules have been set
	queueNum       int
	table          string // nftable name
	connMarkAccept int
	connMarkDrop   int

	// iptables not nil = use iptables instead of nftables
	ipt4 *iptables.IPTables
	ipt6 *iptables.IPTables

	protectedDialer *net.Dialer
}

type NFQueuePacketIOConfig struct {
	QueueSize      uint32
	QueueNum       *uint16
	Table          string
	ConnMarkAccept uint32
	ConnMarkDrop   uint32

	ReadBuffer  int
	WriteBuffer int
	Local       bool
	RST         bool
}

func NewNFQueuePacketIO(config NFQueuePacketIOConfig) (PacketIO, error) {
	if config.QueueSize == 0 {
		config.QueueSize = nfqueueDefaultQueueSize
	}
	if config.QueueNum == nil {
		queueNum := uint16(nfqueueDefaultQueueNum)
		config.QueueNum = &queueNum
	}
	if config.Table == "" {
		config.Table = nftDefaultTable
	}
	if config.ConnMarkAccept == 0 {
		config.ConnMarkAccept = nfqueueDefaultConnMarkAccept
	}
	if config.ConnMarkDrop == 0 {
		config.ConnMarkDrop = config.ConnMarkAccept + 1
		if config.ConnMarkDrop == 0 {
			// Overflow
			config.ConnMarkDrop = 1
		}
	}
	if config.ConnMarkAccept == config.ConnMarkDrop {
		return nil, errors.New("connMarkAccept and connMarkDrop cannot be the same")
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
		NfQueue:      *config.QueueNum,
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
		n:              n,
		local:          config.Local,
		rst:            config.RST,
		queueNum:       int(*config.QueueNum),
		table:          config.Table,
		connMarkAccept: int(config.ConnMarkAccept),
		connMarkDrop:   int(config.ConnMarkDrop),
		ipt4:           ipt4,
		ipt6:           ipt6,
		protectedDialer: &net.Dialer{
			Control: func(network, address string, c syscall.RawConn) error {
				var err error
				cErr := c.Control(func(fd uintptr) {
					err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(config.ConnMarkAccept))
				})
				if cErr != nil {
					return cErr
				}
				return err
			},
		},
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
			// Use timestamp from attribute if available, otherwise use current time as fallback
			if a.Timestamp != nil {
				p.timestamp = *a.Timestamp
			} else {
				p.timestamp = time.Now()
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
			err = n.setupIpt(false)
		} else {
			err = n.setupNft(false)
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
		return n.n.SetVerdictWithConnMark(nP.id, nfqueue.NfAccept, n.connMarkAccept)
	case VerdictDrop:
		return n.n.SetVerdict(nP.id, nfqueue.NfDrop)
	case VerdictDropStream:
		return n.n.SetVerdictWithConnMark(nP.id, nfqueue.NfDrop, n.connMarkDrop)
	default:
		// Invalid verdict, ignore for now
		return nil
	}
}

func (n *nfqueuePacketIO) ProtectedDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return n.protectedDialer.DialContext(ctx, network, address)
}

func (n *nfqueuePacketIO) Close() error {
	if n.rSet {
		if n.ipt4 != nil {
			_ = n.setupIpt(true)
		} else {
			_ = n.setupNft(true)
		}
		n.rSet = false
	}
	return n.n.Close()
}

// nfqueue IO does not issue shutdown
func (n *nfqueuePacketIO) SetCancelFunc(cancelFunc context.CancelFunc) error {
	return nil
}

func (n *nfqueuePacketIO) setupNft(remove bool) error {
	rules, err := n.generateNftRules()
	if err != nil {
		return err
	}
	rulesText := rules.String()
	if remove {
		err = nftDelete(nftFamily, n.table)
	} else {
		// Delete first to make sure no leftover rules
		_ = nftDelete(nftFamily, n.table)
		err = nftAdd(rulesText)
	}
	if err != nil {
		return err
	}
	return nil
}

func (n *nfqueuePacketIO) setupIpt(remove bool) error {
	rules, err := n.generateIptRules()
	if err != nil {
		return err
	}
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
	id        uint32
	streamID  uint32
	timestamp time.Time
	data      []byte
}

func (p *nfqueuePacket) StreamID() uint32 {
	return p.streamID
}

func (p *nfqueuePacket) Timestamp() time.Time {
	return p.timestamp
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

type nftTableSpec struct {
	Defines       []string
	Family, Table string
	Chains        []nftChainSpec
}

func (t *nftTableSpec) String() string {
	chains := make([]string, 0, len(t.Chains))
	for _, c := range t.Chains {
		chains = append(chains, c.String())
	}

	return fmt.Sprintf(`
%s

table %s %s {
%s
}
`, strings.Join(t.Defines, "\n"), t.Family, t.Table, strings.Join(chains, ""))
}

type nftChainSpec struct {
	Chain  string
	Header string
	Rules  []string
}

func (c *nftChainSpec) String() string {
	return fmt.Sprintf(`
  chain %s {
    %s
    %s
  }
`, c.Chain, c.Header, strings.Join(c.Rules, "\n\x20\x20\x20\x20"))
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
