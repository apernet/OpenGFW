package engine

import (
	"net"
	"sync"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/io"
	"github.com/apernet/OpenGFW/ruleset"

	"github.com/bwmarrin/snowflake"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

// tcpVerdict is a subset of io.Verdict for TCP streams.
// We don't allow modifying or dropping a single packet
// for TCP streams for now, as it doesn't make much sense.
type tcpVerdict io.Verdict

const (
	tcpVerdictAccept       = tcpVerdict(io.VerdictAccept)
	tcpVerdictAcceptStream = tcpVerdict(io.VerdictAcceptStream)
	tcpVerdictDropStream   = tcpVerdict(io.VerdictDropStream)
)

type tcpContext struct {
	*gopacket.PacketMetadata
	Verdict tcpVerdict
}

func (ctx *tcpContext) GetCaptureInfo() gopacket.CaptureInfo {
	return ctx.CaptureInfo
}

type tcpStreamFactory struct {
	WorkerID int
	Logger   Logger
	Node     *snowflake.Node

	RulesetMutex sync.RWMutex
	Ruleset      ruleset.Ruleset
}

func (f *tcpStreamFactory) New(ipFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	id := f.Node.Generate()
	ipSrc, ipDst := net.IP(ipFlow.Src().Raw()), net.IP(ipFlow.Dst().Raw())
	info := ruleset.StreamInfo{
		ID:       id.Int64(),
		Protocol: ruleset.ProtocolTCP,
		SrcIP:    ipSrc,
		DstIP:    ipDst,
		SrcPort:  uint16(tcp.SrcPort),
		DstPort:  uint16(tcp.DstPort),
		Props:    make(analyzer.CombinedPropMap),
	}
	f.Logger.TCPStreamNew(f.WorkerID, info)
	f.RulesetMutex.RLock()
	rs := f.Ruleset
	f.RulesetMutex.RUnlock()
	ans := analyzersToTCPAnalyzers(rs.Analyzers(info))
	// Create entries for each analyzer
	entries := make([]*tcpStreamEntry, 0, len(ans))
	for _, a := range ans {
		entries = append(entries, &tcpStreamEntry{
			Name: a.Name(),
			Stream: a.NewTCP(analyzer.TCPInfo{
				SrcIP:   ipSrc,
				DstIP:   ipDst,
				SrcPort: uint16(tcp.SrcPort),
				DstPort: uint16(tcp.DstPort),
			}, &analyzerLogger{
				StreamID: id.Int64(),
				Name:     a.Name(),
				Logger:   f.Logger,
			}),
			HasLimit: a.Limit() > 0,
			Quota:    a.Limit(),
		})
	}
	return &tcpStream{
		info:          info,
		virgin:        true,
		logger:        f.Logger,
		ruleset:       rs,
		activeEntries: entries,
	}
}

func (f *tcpStreamFactory) UpdateRuleset(r ruleset.Ruleset) error {
	f.RulesetMutex.Lock()
	defer f.RulesetMutex.Unlock()
	f.Ruleset = r
	return nil
}

type tcpStream struct {
	info          ruleset.StreamInfo
	virgin        bool // true if no packets have been processed
	logger        Logger
	ruleset       ruleset.Ruleset
	activeEntries []*tcpStreamEntry
	doneEntries   []*tcpStreamEntry
	lastVerdict   tcpVerdict
}

type tcpStreamEntry struct {
	Name     string
	Stream   analyzer.TCPStream
	HasLimit bool
	Quota    int
}

func (s *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	if len(s.activeEntries) > 0 || s.virgin {
		// Make sure every stream matches against the ruleset at least once,
		// even if there are no activeEntries, as the ruleset may have built-in
		// properties that need to be matched.
		return true
	} else {
		ctx := ac.(*tcpContext)
		ctx.Verdict = s.lastVerdict
		return false
	}
}

func (s *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, start, end, skip := sg.Info()
	rev := dir == reassembly.TCPDirServerToClient
	avail, _ := sg.Lengths()
	data := sg.Fetch(avail)
	updated := false
	for i := len(s.activeEntries) - 1; i >= 0; i-- {
		// Important: reverse order so we can remove entries
		entry := s.activeEntries[i]
		update, closeUpdate, done := s.feedEntry(entry, rev, start, end, skip, data)
		up1 := processPropUpdate(s.info.Props, entry.Name, update)
		up2 := processPropUpdate(s.info.Props, entry.Name, closeUpdate)
		updated = updated || up1 || up2
		if done {
			s.activeEntries = append(s.activeEntries[:i], s.activeEntries[i+1:]...)
			s.doneEntries = append(s.doneEntries, entry)
		}
	}
	ctx := ac.(*tcpContext)
	if updated || s.virgin {
		s.virgin = false
		s.logger.TCPStreamPropUpdate(s.info, false)
		// Match properties against ruleset
		result := s.ruleset.Match(s.info)
		action := result.Action
		if action != ruleset.ActionMaybe && action != ruleset.ActionModify {
			verdict := actionToTCPVerdict(action)
			s.lastVerdict = verdict
			ctx.Verdict = verdict
			s.logger.TCPStreamAction(s.info, action, false)
			// Verdict issued, no need to process any more packets
			s.closeActiveEntries()
		}
	}
	if len(s.activeEntries) == 0 && ctx.Verdict == tcpVerdictAccept {
		// All entries are done but no verdict issued, accept stream
		s.lastVerdict = tcpVerdictAcceptStream
		ctx.Verdict = tcpVerdictAcceptStream
		s.logger.TCPStreamAction(s.info, ruleset.ActionAllow, true)
	}
}

func (s *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	s.closeActiveEntries()
	return true
}

func (s *tcpStream) closeActiveEntries() {
	// Signal close to all active entries & move them to doneEntries
	updated := false
	for _, entry := range s.activeEntries {
		update := entry.Stream.Close(false)
		up := processPropUpdate(s.info.Props, entry.Name, update)
		updated = updated || up
	}
	if updated {
		s.logger.TCPStreamPropUpdate(s.info, true)
	}
	s.doneEntries = append(s.doneEntries, s.activeEntries...)
	s.activeEntries = nil
}

func (s *tcpStream) feedEntry(entry *tcpStreamEntry, rev, start, end bool, skip int, data []byte) (update *analyzer.PropUpdate, closeUpdate *analyzer.PropUpdate, done bool) {
	if !entry.HasLimit {
		update, done = entry.Stream.Feed(rev, start, end, skip, data)
	} else {
		qData := data
		if len(qData) > entry.Quota {
			qData = qData[:entry.Quota]
		}
		update, done = entry.Stream.Feed(rev, start, end, skip, qData)
		entry.Quota -= len(qData)
		if entry.Quota <= 0 {
			// Quota exhausted, signal close & move to doneEntries
			closeUpdate = entry.Stream.Close(true)
			done = true
		}
	}
	return
}

func analyzersToTCPAnalyzers(ans []analyzer.Analyzer) []analyzer.TCPAnalyzer {
	tcpAns := make([]analyzer.TCPAnalyzer, 0, len(ans))
	for _, a := range ans {
		if tcpM, ok := a.(analyzer.TCPAnalyzer); ok {
			tcpAns = append(tcpAns, tcpM)
		}
	}
	return tcpAns
}

func actionToTCPVerdict(a ruleset.Action) tcpVerdict {
	switch a {
	case ruleset.ActionMaybe, ruleset.ActionAllow, ruleset.ActionModify:
		return tcpVerdictAcceptStream
	case ruleset.ActionBlock, ruleset.ActionDrop:
		return tcpVerdictDropStream
	default:
		// Should never happen
		return tcpVerdictAcceptStream
	}
}
