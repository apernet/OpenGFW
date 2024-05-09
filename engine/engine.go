package engine

import (
	"context"
	"runtime"

	"github.com/apernet/OpenGFW/io"
	"github.com/apernet/OpenGFW/ruleset"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var _ Engine = (*engine)(nil)

type engine struct {
	logger  Logger
	io      io.PacketIO
	workers []*worker
}

func NewEngine(config Config) (Engine, error) {
	workerCount := config.Workers
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}
	var err error
	workers := make([]*worker, workerCount)
	for i := range workers {
		workers[i], err = newWorker(workerConfig{
			ID:                         i,
			ChanSize:                   config.WorkerQueueSize,
			Logger:                     config.Logger,
			Ruleset:                    config.Ruleset,
			TCPMaxBufferedPagesTotal:   config.WorkerTCPMaxBufferedPagesTotal,
			TCPMaxBufferedPagesPerConn: config.WorkerTCPMaxBufferedPagesPerConn,
			TCPTimeout:                 config.WorkerTCPTimeout,
			UDPMaxStreams:              config.WorkerUDPMaxStreams,
		})
		if err != nil {
			return nil, err
		}
	}
	return &engine{
		logger:  config.Logger,
		io:      config.IO,
		workers: workers,
	}, nil
}

func (e *engine) UpdateRuleset(r ruleset.Ruleset) error {
	for _, w := range e.workers {
		if err := w.UpdateRuleset(r); err != nil {
			return err
		}
	}
	return nil
}

func (e *engine) Run(ctx context.Context) error {
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel() // Stop workers

	// Register IO shutdown
	ioCtx, ioCancel := context.WithCancel(ctx)
	e.io.SetCancelFunc(ioCancel)
	defer ioCancel() // Stop IO

	// Start workers
	for _, w := range e.workers {
		go w.Run(workerCtx)
	}

	// Register IO callback
	errChan := make(chan error, 1)
	err := e.io.Register(ioCtx, func(p io.Packet, err error) bool {
		if err != nil {
			errChan <- err
			return false
		}
		return e.dispatch(p)
	})
	if err != nil {
		return err
	}

	// Block until IO errors or context is cancelled
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return nil
	case <-ioCtx.Done():
		return nil
	}
}

// dispatch dispatches a packet to a worker.
func (e *engine) dispatch(p io.Packet) bool {
	data := p.Data()
	ipVersion := data[0] >> 4
	var layerType gopacket.LayerType
	if ipVersion == 4 {
		layerType = layers.LayerTypeIPv4
	} else if ipVersion == 6 {
		layerType = layers.LayerTypeIPv6
	} else {
		// Unsupported network layer
		_ = e.io.SetVerdict(p, io.VerdictAcceptStream, nil)
		return true
	}
	// Convert to gopacket.Packet
	packet := gopacket.NewPacket(data, layerType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	packet.Metadata().Timestamp = p.Timestamp()
	// Load balance by stream ID
	index := p.StreamID() % uint32(len(e.workers))
	e.workers[index].Feed(&workerPacket{
		StreamID: p.StreamID(),
		Packet:   packet,
		SetVerdict: func(v io.Verdict, b []byte) error {
			return e.io.SetVerdict(p, v, b)
		},
	})
	return true
}
