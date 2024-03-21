package tcp

import (
	"bytes"

	"github.com/apernet/OpenGFW/analyzer"
)

var _ analyzer.TCPAnalyzer = (*TrojanAnalyzer)(nil)

// CCS stands for "Change Cipher Spec"
var ccsPattern = []byte{20, 3, 3, 0, 1, 1}

// TrojanAnalyzer uses length-based heuristics to detect Trojan traffic based on
// its "TLS-in-TLS" nature. The heuristics are trained using a decision tree with
// about 2000 samples. This is highly experimental and is known to have significant
// false positives (about 9% false positives & 3% false negatives).
// We do NOT recommend directly blocking all positive connections, as this is likely
// to break many normal TLS connections.
type TrojanAnalyzer struct{}

func (a *TrojanAnalyzer) Name() string {
	return "trojan"
}

func (a *TrojanAnalyzer) Limit() int {
	return 512000
}

func (a *TrojanAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return newTrojanStream(logger)
}

type trojanStream struct {
	logger   analyzer.Logger
	first    bool
	count    bool
	rev      bool
	seq      [3]int
	seqIndex int
}

func newTrojanStream(logger analyzer.Logger) *trojanStream {
	return &trojanStream{logger: logger}
}

func (s *trojanStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
	if skip != 0 {
		return nil, true
	}
	if len(data) == 0 {
		return nil, false
	}

	if s.first {
		s.first = false
		// Stop if it's not a valid TLS connection
		if !(!rev && len(data) >= 3 && data[0] >= 0x16 && data[0] <= 0x17 &&
			data[1] == 0x03 && data[2] <= 0x09) {
			return nil, true
		}
	}

	if !rev && !s.count && len(data) >= 6 && bytes.Equal(data[:6], ccsPattern) {
		// Client Change Cipher Spec encountered, start counting
		s.count = true
	}

	if s.count {
		if rev == s.rev {
			// Same direction as last time, just update the number
			s.seq[s.seqIndex] += len(data)
		} else {
			// Different direction, bump the index
			s.seqIndex += 1
			if s.seqIndex == 3 {
				// Time to evaluate
				yes := s.seq[0] >= 180 &&
					s.seq[1] <= 11000 &&
					s.seq[2] >= 40
				return &analyzer.PropUpdate{
					Type: analyzer.PropUpdateReplace,
					M: analyzer.PropMap{
						"seq": s.seq,
						"yes": yes,
					},
				}, true
			}
			s.seq[s.seqIndex] += len(data)
			s.rev = rev
		}
	}

	return nil, false
}

func (s *trojanStream) Close(limited bool) *analyzer.PropUpdate {
	return nil
}
