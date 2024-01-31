package udp

import (
	"container/ring"
	"encoding/binary"
	"slices"
	"sync"

	"github.com/apernet/OpenGFW/analyzer"
)

var (
	_ analyzer.UDPAnalyzer = (*WireGuardAnalyzer)(nil)
	_ analyzer.UDPStream   = (*wireGuardUDPStream)(nil)
)

const (
	wireguardUDPInvalidCountThreshold = 4
	wireguardRememberedIndexCount     = 6
	wireguardPropKeyMessageType       = "message_type"
)

const (
	wireguardTypeHandshakeInitiation = 1
	wireguardTypeHandshakeResponse   = 2
	wireguardTypeData                = 4
	wireguardTypeCookieReply         = 3
)

const (
	wireguardSizeHandshakeInitiation = 148
	wireguardSizeHandshakeResponse   = 92
	wireguardMinSizePacketData       = 32 // 16 bytes header + 16 bytes AEAD overhead
	wireguardSizePacketCookieReply   = 64
)

type WireGuardAnalyzer struct{}

func (a *WireGuardAnalyzer) Name() string {
	return "wireguard"
}

func (a *WireGuardAnalyzer) Limit() int {
	return 0
}

func (a *WireGuardAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return newWireGuardUDPStream(logger)
}

type wireGuardUDPStream struct {
	logger                analyzer.Logger
	invalidCount          int
	rememberedIndexes     *ring.Ring
	rememberedIndexesLock sync.RWMutex
}

func newWireGuardUDPStream(logger analyzer.Logger) *wireGuardUDPStream {
	return &wireGuardUDPStream{
		logger:            logger,
		rememberedIndexes: ring.New(wireguardRememberedIndexCount),
	}
}

func (s *wireGuardUDPStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	m := s.parseWireGuardPacket(rev, data)
	if m == nil {
		s.invalidCount++
		return nil, s.invalidCount >= wireguardUDPInvalidCountThreshold
	}
	s.invalidCount = 0 // Reset invalid count on valid WireGuard packet
	messageType := m[wireguardPropKeyMessageType].(byte)
	propUpdateType := analyzer.PropUpdateMerge
	if messageType == wireguardTypeHandshakeInitiation {
		propUpdateType = analyzer.PropUpdateReplace
	}
	return &analyzer.PropUpdate{
		Type: propUpdateType,
		M:    m,
	}, false
}

func (s *wireGuardUDPStream) Close(limited bool) *analyzer.PropUpdate {
	return nil
}

func (s *wireGuardUDPStream) parseWireGuardPacket(rev bool, data []byte) analyzer.PropMap {
	if len(data) < 4 {
		return nil
	}
	if slices.Max(data[1:4]) != 0 {
		return nil
	}

	messageType := data[0]
	var propKey string
	var propValue analyzer.PropMap
	switch messageType {
	case wireguardTypeHandshakeInitiation:
		propKey = "handshake_initiation"
		propValue = s.parseWireGuardHandshakeInitiation(rev, data)
	case wireguardTypeHandshakeResponse:
		propKey = "handshake_response"
		propValue = s.parseWireGuardHandshakeResponse(rev, data)
	case wireguardTypeData:
		propKey = "packet_data"
		propValue = s.parseWireGuardPacketData(rev, data)
	case wireguardTypeCookieReply:
		propKey = "packet_cookie_reply"
		propValue = s.parseWireGuardPacketCookieReply(rev, data)
	}
	if propValue == nil {
		return nil
	}

	m := make(analyzer.PropMap)
	m[wireguardPropKeyMessageType] = messageType
	m[propKey] = propValue
	return m
}

func (s *wireGuardUDPStream) parseWireGuardHandshakeInitiation(rev bool, data []byte) analyzer.PropMap {
	if len(data) != wireguardSizeHandshakeInitiation {
		return nil
	}
	m := make(analyzer.PropMap)

	senderIndex := binary.LittleEndian.Uint32(data[4:8])
	m["sender_index"] = senderIndex
	s.putSenderIndex(rev, senderIndex)

	return m
}

func (s *wireGuardUDPStream) parseWireGuardHandshakeResponse(rev bool, data []byte) analyzer.PropMap {
	if len(data) != wireguardSizeHandshakeResponse {
		return nil
	}
	m := make(analyzer.PropMap)

	senderIndex := binary.LittleEndian.Uint32(data[4:8])
	m["sender_index"] = senderIndex
	s.putSenderIndex(rev, senderIndex)

	receiverIndex := binary.LittleEndian.Uint32(data[8:12])
	m["receiver_index"] = receiverIndex
	m["receiver_index_matched"] = s.matchReceiverIndex(rev, receiverIndex)

	return m
}

func (s *wireGuardUDPStream) parseWireGuardPacketData(rev bool, data []byte) analyzer.PropMap {
	if len(data) < wireguardMinSizePacketData {
		return nil
	}
	if len(data)%16 != 0 {
		// WireGuard zero padding the packet to make the length a multiple of 16
		return nil
	}
	m := make(analyzer.PropMap)

	receiverIndex := binary.LittleEndian.Uint32(data[4:8])
	m["receiver_index"] = receiverIndex
	m["receiver_index_matched"] = s.matchReceiverIndex(rev, receiverIndex)

	m["counter"] = binary.LittleEndian.Uint64(data[8:16])

	return m
}

func (s *wireGuardUDPStream) parseWireGuardPacketCookieReply(rev bool, data []byte) analyzer.PropMap {
	if len(data) != wireguardSizePacketCookieReply {
		return nil
	}
	m := make(analyzer.PropMap)

	receiverIndex := binary.LittleEndian.Uint32(data[4:8])
	m["receiver_index"] = receiverIndex
	m["receiver_index_matched"] = s.matchReceiverIndex(rev, receiverIndex)

	return m
}

type wireGuardIndex struct {
	SenderIndex uint32
	Reverse     bool
}

func (s *wireGuardUDPStream) putSenderIndex(rev bool, senderIndex uint32) {
	s.rememberedIndexesLock.Lock()
	defer s.rememberedIndexesLock.Unlock()

	s.rememberedIndexes.Value = &wireGuardIndex{
		SenderIndex: senderIndex,
		Reverse:     rev,
	}
	s.rememberedIndexes = s.rememberedIndexes.Prev()
}

func (s *wireGuardUDPStream) matchReceiverIndex(rev bool, receiverIndex uint32) bool {
	s.rememberedIndexesLock.RLock()
	defer s.rememberedIndexesLock.RUnlock()

	var found bool
	ris := s.rememberedIndexes
	for it := ris.Next(); it != ris; it = it.Next() {
		if it.Value == nil {
			break
		}
		wgidx := it.Value.(*wireGuardIndex)
		if wgidx.Reverse == !rev && wgidx.SenderIndex == receiverIndex {
			found = true
			break
		}
	}
	return found
}
