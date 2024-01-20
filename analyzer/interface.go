package analyzer

import (
	"net"
	"strings"
)

type Analyzer interface {
	// Name returns the name of the analyzer.
	Name() string
	// Limit returns the byte limit for this analyzer.
	// For example, an analyzer can return 1000 to indicate that it only ever needs
	// the first 1000 bytes of a stream to do its job. If the stream is still not
	// done after 1000 bytes, the engine will stop feeding it data and close it.
	// An analyzer can return 0 or a negative number to indicate that it does not
	// have a hard limit.
	// Note: for UDP streams, the engine always feeds entire packets, even if
	// the packet is larger than the remaining quota or the limit itself.
	Limit() int
}

type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

type TCPAnalyzer interface {
	Analyzer
	// NewTCP returns a new TCPStream.
	NewTCP(TCPInfo, Logger) TCPStream
}

type TCPInfo struct {
	// SrcIP is the source IP address.
	SrcIP net.IP
	// DstIP is the destination IP address.
	DstIP net.IP
	// SrcPort is the source port.
	SrcPort uint16
	// DstPort is the destination port.
	DstPort uint16
}

type TCPStream interface {
	// Feed feeds a chunk of reassembled data to the stream.
	// It returns a prop update containing the information extracted from the stream (can be nil),
	// and whether the analyzer is "done" with this stream (i.e. no more data should be fed).
	Feed(rev, start, end bool, skip int, data []byte) (u *PropUpdate, done bool)
	// Close indicates that the stream is closed.
	// Either the connection is closed, or the stream has reached its byte limit.
	// Like Feed, it optionally returns a prop update.
	Close(limited bool) *PropUpdate
}

type UDPAnalyzer interface {
	Analyzer
	// NewUDP returns a new UDPStream.
	NewUDP(UDPInfo, Logger) UDPStream
}

type UDPInfo struct {
	// SrcIP is the source IP address.
	SrcIP net.IP
	// DstIP is the destination IP address.
	DstIP net.IP
	// SrcPort is the source port.
	SrcPort uint16
	// DstPort is the destination port.
	DstPort uint16
}

type UDPStream interface {
	// Feed feeds a new packet to the stream.
	// It returns a prop update containing the information extracted from the stream (can be nil),
	// and whether the analyzer is "done" with this stream (i.e. no more data should be fed).
	Feed(rev bool, data []byte) (u *PropUpdate, done bool)
	// Close indicates that the stream is closed.
	// Either the connection is closed, or the stream has reached its byte limit.
	// Like Feed, it optionally returns a prop update.
	Close(limited bool) *PropUpdate
}

type (
	PropMap         map[string]interface{}
	CombinedPropMap map[string]PropMap
)

// Get returns the value of the property with the given key.
// The key can be a nested key, e.g. "foo.bar.baz".
// Returns nil if the key does not exist.
func (m PropMap) Get(key string) interface{} {
	keys := strings.Split(key, ".")
	if len(keys) == 0 {
		return nil
	}
	var current interface{} = m
	for _, k := range keys {
		currentMap, ok := current.(PropMap)
		if !ok {
			return nil
		}
		current = currentMap[k]
	}
	return current
}

// Get returns the value of the property with the given analyzer & key.
// The key can be a nested key, e.g. "foo.bar.baz".
// Returns nil if the key does not exist.
func (cm CombinedPropMap) Get(an string, key string) interface{} {
	m, ok := cm[an]
	if !ok {
		return nil
	}
	return m.Get(key)
}

type PropUpdateType int

const (
	PropUpdateNone PropUpdateType = iota
	PropUpdateMerge
	PropUpdateReplace
	PropUpdateDelete
)

type PropUpdate struct {
	Type PropUpdateType
	M    PropMap
}
