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
var (
	_ analyzer.UDPAnalyzer = (*OICQAnalyzer)(nil)
)

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
	+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
	|Flag |  Version  | Command   | Sequence  |         Number        |
	+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
	|          ................Data................(Dynamic Len)	  |
	+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
	*/
	// At least 8 bytes
	if len(data) < 7 {
		return nil
	}
	if data[0] != OICQPacketStartFlag { // OICQ Packet Start With 0x02
		return nil
	}
	if data[len(data)-1] != OICQPacketEndFlag { // OICQ Packet End With 0x03
		return nil
	}
	data = data[1:]
	m := analyzer.PropMap{
		"version": binary.BigEndian.Uint16(data[0:2]),
		"command": binary.BigEndian.Uint16(data[2:4]),
		"seq":     binary.BigEndian.Uint16(data[4:6]),
		"number":  0,
	}
	data = data[6:]
	if len(data) < 5 {
		// Valid OICQ packet, but no Number field
		return m
	}
	m["number"] = binary.BigEndian.Uint32(data[0:4])
	// Valid OICQ packet with Number field
	return m
}
