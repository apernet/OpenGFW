package udp

import (
	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/internal"
	"github.com/apernet/OpenGFW/analyzer/udp/internal/quic"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

const (
	quicInvalidCountThreshold = 4
)

var (
	_ analyzer.UDPAnalyzer = (*QUICAnalyzer)(nil)
	_ analyzer.UDPStream   = (*quicStream)(nil)
)

type QUICAnalyzer struct{}

func (a *QUICAnalyzer) Name() string {
	return "quic"
}

func (a *QUICAnalyzer) Limit() int {
	return 0
}

func (a *QUICAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return &quicStream{logger: logger}
}

type quicStream struct {
	logger       analyzer.Logger
	invalidCount int
}

func (s *quicStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	if rev {
		// We don't support server direction for now
		s.invalidCount++
		return nil, s.invalidCount >= quicInvalidCountThreshold
	}
	pl, err := quic.ReadCryptoPayload(data)
	if err != nil || len(pl) < 4 {
		s.invalidCount++
		return nil, s.invalidCount >= quicInvalidCountThreshold
	}
	// Should be a TLS client hello
	if pl[0] != 0x01 {
		// Not a client hello
		s.invalidCount++
		return nil, s.invalidCount >= quicInvalidCountThreshold
	}
	chLen := int(pl[1])<<16 | int(pl[2])<<8 | int(pl[3])
	if chLen < 41 {
		// 2 (Protocol Version) +
		// 32 (Random) +
		// 1 (Session ID Length) +
		// 2 (Cipher Suites Length) +_ws.col.protocol == "TLSv1.3"
		// 2 (Cipher Suite) +
		// 1 (Compression Methods Length) +
		// 1 (Compression Method) +
		// No extensions
		// This should be the bare minimum for a client hello
		s.invalidCount++
		return nil, s.invalidCount >= quicInvalidCountThreshold
	}
	m := internal.ParseTLSClientHello(&utils.ByteBuffer{Buf: pl[4:]})
	if m == nil {
		s.invalidCount++
		return nil, s.invalidCount >= quicInvalidCountThreshold
	}
	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateMerge,
		M:    analyzer.PropMap{"req": m},
	}, true
}

func (s *quicStream) Close(limited bool) *analyzer.PropUpdate {
	return nil
}
