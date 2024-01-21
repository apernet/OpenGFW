package tcp

import (
	"bytes"

	"github.com/apernet/OpenGFW/analyzer"
)

var _ analyzer.TCPAnalyzer = (*TrojanAnalyzer)(nil)

// CCS stands for "Change Cipher Spec"
var trojanCCS = []byte{20, 3, 3, 0, 1, 1}

const (
	trojanUpLB    = 650
	trojanUpUB    = 1000
	trojanDownLB1 = 170
	trojanDownUB1 = 180
	trojanDownLB2 = 3000
	trojanDownUB2 = 7500
)

// TrojanAnalyzer uses a very simple packet length based check to determine
// if a TLS connection is actually the Trojan proxy protocol.
// The algorithm is from the following project, with small modifications:
// https://github.com/XTLS/Trojan-killer
// Warning: Experimental only. This method is known to have significant false positives and false negatives.
type TrojanAnalyzer struct{}

func (a *TrojanAnalyzer) Name() string {
	return "trojan"
}

func (a *TrojanAnalyzer) Limit() int {
	return 16384
}

func (a *TrojanAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return newTrojanStream(logger)
}

type trojanStream struct {
	logger    analyzer.Logger
	active    bool
	upCount   int
	downCount int
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
	if !rev && !s.active && len(data) >= 6 && bytes.Equal(data[:6], trojanCCS) {
		// Client CCS encountered, start counting
		s.active = true
	}
	if s.active {
		if rev {
			// Down direction
			s.downCount += len(data)
		} else {
			// Up direction
			if s.upCount >= trojanUpLB && s.upCount <= trojanUpUB &&
				((s.downCount >= trojanDownLB1 && s.downCount <= trojanDownUB1) ||
					(s.downCount >= trojanDownLB2 && s.downCount <= trojanDownUB2)) {
				return &analyzer.PropUpdate{
					Type: analyzer.PropUpdateReplace,
					M: analyzer.PropMap{
						"up":   s.upCount,
						"down": s.downCount,
						"yes":  true,
					},
				}, true
			}
			s.upCount += len(data)
		}
	}
	// Give up when either direction is over the limit
	return nil, s.upCount > trojanUpUB || s.downCount > trojanDownUB2
}

func (s *trojanStream) Close(limited bool) *analyzer.PropUpdate {
	return nil
}
