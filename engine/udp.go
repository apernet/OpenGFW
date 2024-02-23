package engine

import (
	"errors"
	"net"
	"sync"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/io"
	"github.com/apernet/OpenGFW/modifier"
	"github.com/apernet/OpenGFW/ruleset"

	"github.com/bwmarrin/snowflake"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	lru "github.com/hashicorp/golang-lru/v2"
)

// udpVerdict is a subset of io.Verdict for UDP streams.
// For UDP, we support all verdicts.
type udpVerdict io.Verdict

const (
	udpVerdictAccept       = udpVerdict(io.VerdictAccept)
	udpVerdictAcceptModify = udpVerdict(io.VerdictAcceptModify)
	udpVerdictAcceptStream = udpVerdict(io.VerdictAcceptStream)
	udpVerdictDrop         = udpVerdict(io.VerdictDrop)
	udpVerdictDropStream   = udpVerdict(io.VerdictDropStream)
)

var errInvalidModifier = errors.New("invalid modifier")

type udpContext struct {
	Verdict udpVerdict
	Packet  []byte
}

type udpStreamFactory struct {
	WorkerID int
	Logger   Logger
	Node     *snowflake.Node

	RulesetMutex sync.RWMutex
	Ruleset      ruleset.Ruleset
}

func (f *udpStreamFactory) New(ipFlow, udpFlow gopacket.Flow, udp *layers.UDP, uc *udpContext) *udpStream {
	id := f.Node.Generate()
	ipSrc, ipDst := net.IP(ipFlow.Src().Raw()), net.IP(ipFlow.Dst().Raw())
	info := ruleset.StreamInfo{
		ID:       id.Int64(),
		Protocol: ruleset.ProtocolUDP,
		SrcIP:    ipSrc,
		DstIP:    ipDst,
		SrcPort:  uint16(udp.SrcPort),
		DstPort:  uint16(udp.DstPort),
		Props:    make(analyzer.CombinedPropMap),
	}
	f.Logger.UDPStreamNew(f.WorkerID, info)
	f.RulesetMutex.RLock()
	rs := f.Ruleset
	f.RulesetMutex.RUnlock()
	ans := analyzersToUDPAnalyzers(rs.Analyzers(info))
	// Create entries for each analyzer
	entries := make([]*udpStreamEntry, 0, len(ans))
	for _, a := range ans {
		entries = append(entries, &udpStreamEntry{
			Name: a.Name(),
			Stream: a.NewUDP(analyzer.UDPInfo{
				SrcIP:   ipSrc,
				DstIP:   ipDst,
				SrcPort: uint16(udp.SrcPort),
				DstPort: uint16(udp.DstPort),
			}, &analyzerLogger{
				StreamID: id.Int64(),
				Name:     a.Name(),
				Logger:   f.Logger,
			}),
			HasLimit: a.Limit() > 0,
			Quota:    a.Limit(),
		})
	}
	return &udpStream{
		info:          info,
		virgin:        true,
		logger:        f.Logger,
		ruleset:       rs,
		activeEntries: entries,
	}
}

func (f *udpStreamFactory) UpdateRuleset(r ruleset.Ruleset) error {
	f.RulesetMutex.Lock()
	defer f.RulesetMutex.Unlock()
	f.Ruleset = r
	return nil
}

type udpStreamManager struct {
	factory *udpStreamFactory
	streams *lru.Cache[uint32, *udpStreamValue]
}

type udpStreamValue struct {
	Stream  *udpStream
	IPFlow  gopacket.Flow
	UDPFlow gopacket.Flow
}

func (v *udpStreamValue) Match(ipFlow, udpFlow gopacket.Flow) (ok, rev bool) {
	fwd := v.IPFlow == ipFlow && v.UDPFlow == udpFlow
	rev = v.IPFlow == ipFlow.Reverse() && v.UDPFlow == udpFlow.Reverse()
	return fwd || rev, rev
}

func newUDPStreamManager(factory *udpStreamFactory, maxStreams int) (*udpStreamManager, error) {
	ss, err := lru.New[uint32, *udpStreamValue](maxStreams)
	if err != nil {
		return nil, err
	}
	return &udpStreamManager{
		factory: factory,
		streams: ss,
	}, nil
}

func (m *udpStreamManager) MatchWithContext(streamID uint32, ipFlow gopacket.Flow, udp *layers.UDP, uc *udpContext) {
	rev := false
	value, ok := m.streams.Get(streamID)
	if !ok {
		// New stream
		value = &udpStreamValue{
			Stream:  m.factory.New(ipFlow, udp.TransportFlow(), udp, uc),
			IPFlow:  ipFlow,
			UDPFlow: udp.TransportFlow(),
		}
		m.streams.Add(streamID, value)
	} else {
		// Stream ID exists, but is it really the same stream?
		ok, rev = value.Match(ipFlow, udp.TransportFlow())
		if !ok {
			// It's not - close the old stream & replace it with a new one
			value.Stream.Close()
			value = &udpStreamValue{
				Stream:  m.factory.New(ipFlow, udp.TransportFlow(), udp, uc),
				IPFlow:  ipFlow,
				UDPFlow: udp.TransportFlow(),
			}
			m.streams.Add(streamID, value)
		}
	}
	if value.Stream.Accept(udp, rev, uc) {
		value.Stream.Feed(udp, rev, uc)
	}
}

type udpStream struct {
	info          ruleset.StreamInfo
	virgin        bool // true if no packets have been processed
	logger        Logger
	ruleset       ruleset.Ruleset
	activeEntries []*udpStreamEntry
	doneEntries   []*udpStreamEntry
	lastVerdict   udpVerdict
}

type udpStreamEntry struct {
	Name     string
	Stream   analyzer.UDPStream
	HasLimit bool
	Quota    int
}

func (s *udpStream) Accept(udp *layers.UDP, rev bool, uc *udpContext) bool {
	if len(s.activeEntries) > 0 || s.virgin {
		// Make sure every stream matches against the ruleset at least once,
		// even if there are no activeEntries, as the ruleset may have built-in
		// properties that need to be matched.
		return true
	} else {
		uc.Verdict = s.lastVerdict
		return false
	}
}

func (s *udpStream) Feed(udp *layers.UDP, rev bool, uc *udpContext) {
	updated := false
	for i := len(s.activeEntries) - 1; i >= 0; i-- {
		// Important: reverse order so we can remove entries
		entry := s.activeEntries[i]
		update, closeUpdate, done := s.feedEntry(entry, rev, udp.Payload)
		up1 := processPropUpdate(s.info.Props, entry.Name, update)
		up2 := processPropUpdate(s.info.Props, entry.Name, closeUpdate)
		updated = updated || up1 || up2
		if done {
			s.activeEntries = append(s.activeEntries[:i], s.activeEntries[i+1:]...)
			s.doneEntries = append(s.doneEntries, entry)
		}
	}
	if updated || s.virgin {
		s.virgin = false
		s.logger.UDPStreamPropUpdate(s.info, false)
		// Match properties against ruleset
		result := s.ruleset.Match(s.info)
		action := result.Action
		if action == ruleset.ActionModify {
			// Call the modifier instance
			udpMI, ok := result.ModInstance.(modifier.UDPModifierInstance)
			if !ok {
				// Not for UDP, fallback to maybe
				s.logger.ModifyError(s.info, errInvalidModifier)
				action = ruleset.ActionMaybe
			} else {
				var err error
				uc.Packet, err = udpMI.Process(udp.Payload)
				if err != nil {
					// Modifier error, fallback to maybe
					s.logger.ModifyError(s.info, err)
					action = ruleset.ActionMaybe
				}
			}
		}
		if action != ruleset.ActionMaybe {
			verdict, final := actionToUDPVerdict(action)
			s.lastVerdict = verdict
			uc.Verdict = verdict
			s.logger.UDPStreamAction(s.info, action, false)
			if final {
				s.closeActiveEntries()
			}
		}
	}
	if len(s.activeEntries) == 0 && uc.Verdict == udpVerdictAccept {
		// All entries are done but no verdict issued, accept stream
		s.lastVerdict = udpVerdictAcceptStream
		uc.Verdict = udpVerdictAcceptStream
		s.logger.UDPStreamAction(s.info, ruleset.ActionAllow, true)
	}
}

func (s *udpStream) Close() {
	s.closeActiveEntries()
}

func (s *udpStream) closeActiveEntries() {
	// Signal close to all active entries & move them to doneEntries
	updated := false
	for _, entry := range s.activeEntries {
		update := entry.Stream.Close(false)
		up := processPropUpdate(s.info.Props, entry.Name, update)
		updated = updated || up
	}
	if updated {
		s.logger.UDPStreamPropUpdate(s.info, true)
	}
	s.doneEntries = append(s.doneEntries, s.activeEntries...)
	s.activeEntries = nil
}

func (s *udpStream) feedEntry(entry *udpStreamEntry, rev bool, data []byte) (update *analyzer.PropUpdate, closeUpdate *analyzer.PropUpdate, done bool) {
	update, done = entry.Stream.Feed(rev, data)
	if entry.HasLimit {
		entry.Quota -= len(data)
		if entry.Quota <= 0 {
			// Quota exhausted, signal close & move to doneEntries
			closeUpdate = entry.Stream.Close(true)
			done = true
		}
	}
	return
}

func analyzersToUDPAnalyzers(ans []analyzer.Analyzer) []analyzer.UDPAnalyzer {
	udpAns := make([]analyzer.UDPAnalyzer, 0, len(ans))
	for _, a := range ans {
		if udpM, ok := a.(analyzer.UDPAnalyzer); ok {
			udpAns = append(udpAns, udpM)
		}
	}
	return udpAns
}

func actionToUDPVerdict(a ruleset.Action) (v udpVerdict, final bool) {
	switch a {
	case ruleset.ActionMaybe:
		return udpVerdictAccept, false
	case ruleset.ActionAllow:
		return udpVerdictAcceptStream, true
	case ruleset.ActionBlock:
		return udpVerdictDropStream, true
	case ruleset.ActionDrop:
		return udpVerdictDrop, false
	case ruleset.ActionModify:
		return udpVerdictAcceptModify, false
	default:
		// Should never happen
		return udpVerdictAccept, false
	}
}
