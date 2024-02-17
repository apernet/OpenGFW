package udp

import (
	"encoding/binary"
	"github.com/apernet/OpenGFW/analyzer"
)

const (
	OICQPacketStartFlag = 0x02
	OICQPacketEndFlag   = 0x03
)

// OICQAnalyzer OICQ is an IM Software protocol, Usually used by QQ
var _ analyzer.UDPAnalyzer = (*OICQAnalyzer)(nil)

type OICQAnalyzer struct{}

func (a *OICQAnalyzer) Name() string {
	return "oicq"
}

func (a *OICQAnalyzer) Limit() int {
	return 0
}

func (a *OICQAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return &OICQStream{logger: logger}
}

type OICQStream struct {
	logger analyzer.Logger
}

func (s *OICQStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	m := parseOICQMessage(data)
	if m == nil {
		return nil, true
	}
	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateReplace,
		M:    m,
	}, true
}

func (s *OICQStream) Close(limited bool) *analyzer.PropUpdate {
	return nil
}

func parseOICQMessage(data []byte) analyzer.PropMap {
	/* preInfo struct
	SFlag: 0x02        EFlag: 0x03
	+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
	|SFlag|  Version  | Command   | Sequence  |         Number        |
	+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
	|          ................Data................(Dynamic Len)|EFlag|
	+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
	*/
	// At least 12 bytes
	if len(data) < 12 {
		return nil
	}
	if data[0] != OICQPacketStartFlag || data[len(data)-1] != OICQPacketEndFlag { // OICQ Packet Start With 0x02
		return nil
	}
	data = data[1:] // Remove Start Flag
	m := analyzer.PropMap{
		"version": binary.BigEndian.Uint16(data[0:2]),  // OICQ Version (2 bytes)
		"command": binary.BigEndian.Uint16(data[2:4]),  // OICQ Command (2 bytes)
		"seq":     binary.BigEndian.Uint16(data[4:6]),  // OICQ Sequence (2 bytes)
		"number":  binary.BigEndian.Uint32(data[6:10]), // OICQ Number, Mostly QQ Number (4 bytes)
	}
	if m["number"] == 0 || m["command"] == 0 {
		return nil
	}
	// Valid OICQ packet with Number field
	return m
}
