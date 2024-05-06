package io

import (
	"context"
	"hash/crc32"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var _ PacketIO = (*pcapPacketIO)(nil)

type pcapPacketIO struct {
	pcap     *pcap.Handle
	lastTime *time.Time
	ioCancel context.CancelFunc
	config   PcapPacketIOConfig
}

type PcapPacketIOConfig struct {
	PcapFile    string
	Realtime    bool
}

func NewPcapPacketIO(config PcapPacketIOConfig) (PacketIO, error) {
	handle, err := pcap.OpenOffline(config.PcapFile)

	if err != nil {
		return nil, err
	}

	return &pcapPacketIO{
		pcap:     handle,
		lastTime: nil,
		ioCancel: nil,
		config:   config,
	}, nil
}

func (p *pcapPacketIO) Register(ctx context.Context, cb PacketCallback) error {
	go func() {
		packetSource := gopacket.NewPacketSource(p.pcap, p.pcap.LinkType())
		for packet := range packetSource.Packets() {
			p.wait(packet)

			networkLayer := packet.NetworkLayer()
			if networkLayer != nil {
				src, dst := networkLayer.NetworkFlow().Endpoints()
				endpoints := []string{src.String(), dst.String()}
				sort.Strings(endpoints)
				id := crc32.Checksum([]byte(strings.Join(endpoints, ",")), crc32.IEEETable)

				cb(&pcapPacket{
					streamID:  id,
					timestamp: packet.Metadata().Timestamp,
					data:      packet.LinkLayer().LayerPayload(),
				}, nil)
			}
		}
		// Give the workers a chance to finish everything
		time.Sleep(time.Second)
		// Stop the engine when all packets are finished
		p.ioCancel()
	}()

	return nil
}

func (p *pcapPacketIO) ProtectedDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, nil
}

func (p *pcapPacketIO) SetVerdict(pkt Packet, v Verdict, newPacket []byte) error {
	return nil
}

func (p *pcapPacketIO) SetCancelFunc(cancelFunc context.CancelFunc) error {
	p.ioCancel = cancelFunc
	return nil
}

func (p *pcapPacketIO) Close() error {
	return nil
}

// Intentionally slow down the replay
// In realtime mode, this is to match the timestamps in the capture
func (p *pcapPacketIO) wait(packet gopacket.Packet) error {
	if !p.config.Realtime {
		return nil
	}

	if p.lastTime == nil {
		p.lastTime = &packet.Metadata().Timestamp
	} else {
		t := packet.Metadata().Timestamp.Sub(*p.lastTime)
		time.Sleep(t)
		p.lastTime = &packet.Metadata().Timestamp
	}

	return nil
}

var _ Packet = (*pcapPacket)(nil)

type pcapPacket struct {
	streamID  uint32
	timestamp time.Time
	data      []byte
}

func (p *pcapPacket) StreamID() uint32 {
	return p.streamID
}

func (p *pcapPacket) Timestamp() time.Time {
	return p.timestamp
}

func (p *pcapPacket) Data() []byte {
	return p.data
}
