package io

import (
	"context"
	"net"
	"time"
)

type Verdict int

const (
	// VerdictAccept accepts the packet, but continues to process the stream.
	VerdictAccept Verdict = iota
	// VerdictAcceptModify is like VerdictAccept, but replaces the packet with a new one.
	VerdictAcceptModify
	// VerdictAcceptStream accepts the packet and stops processing the stream.
	VerdictAcceptStream
	// VerdictDrop drops the packet, but does not block the stream.
	VerdictDrop
	// VerdictDropStream drops the packet and blocks the stream.
	VerdictDropStream
)

// Packet represents an IP packet.
type Packet interface {
	// StreamID is the ID of the stream the packet belongs to.
	StreamID() uint32
	// Timestamp is the time the packet was received.
	Timestamp() time.Time
	// Data is the raw packet data, starting with the IP header.
	Data() []byte
}

// PacketCallback is called for each packet received.
// Return false to "unregister" and stop receiving packets.
type PacketCallback func(Packet, error) bool

type PacketIO interface {
	// Register registers a callback to be called for each packet received.
	// The callback should be called in one or more separate goroutines,
	// and stop when the context is cancelled.
	Register(context.Context, PacketCallback) error
	// SetVerdict sets the verdict for a packet.
	SetVerdict(Packet, Verdict, []byte) error
	// ProtectedDialContext is like net.DialContext, but the connection is "protected"
	// in the sense that the packets sent/received through the connection must bypass
	// the packet IO and not be processed by the callback.
	ProtectedDialContext(ctx context.Context, network, address string) (net.Conn, error)
	// Close closes the packet IO.
	Close() error
	// SetCancelFunc gives packet IO access to context cancel function, enabling it to
	// trigger a shutdown
	SetCancelFunc(cancelFunc context.CancelFunc) error
}

type ErrInvalidPacket struct {
	Err error
}

func (e *ErrInvalidPacket) Error() string {
	return "invalid packet: " + e.Err.Error()
}
