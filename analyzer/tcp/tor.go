package tcp

import (
	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/ruleset/builtins/tor"
)

var _ analyzer.TCPAnalyzer = (*TorAnalyzer)(nil)

type TorAnalyzer struct{
	directory tor.TorDirectory
}

func (a *TorAnalyzer) Init() error {
	var err error
	a.directory, err = tor.GetOnionooDirectory()
	return err
}

func (a *TorAnalyzer) Name() string {
	return "tor"
}

// For now only TCP metadata is needed
func (a *TorAnalyzer) Limit() int {
	return 1
}

func (a *TorAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	isRelay := a.directory.Query(info.DstIP, info.DstPort)
	return newTorStream(logger, isRelay)
}

type torStream struct {
	logger  analyzer.Logger
	isRelay bool   // Public relay identifier
}

func newTorStream(logger analyzer.Logger, isRelay bool) *torStream {
	return &torStream{logger: logger, isRelay: isRelay}
}

func (s *torStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
	if skip != 0 {
		return nil, true
	}
	if len(data) == 0 {
		return nil, false
	}

	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateReplace,
		M: analyzer.PropMap{
			"relay": s.isRelay,
		},
	}, true
}

func (s *torStream) Close(limited bool) *analyzer.PropUpdate {
	return nil
}
