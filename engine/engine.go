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
	ioList  []io.PacketIO
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
			UDPMaxStreams:              config.WorkerUDPMaxStreams,
		})
		if err != nil {
			return nil, err
		}
	}
	return &engine{
		logger:  config.Logger,
		ioList:  config.IOs,
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
	ioCtx, ioCancel := context.WithCancel(ctx)
	defer ioCancel() // Stop workers & IOs

	// Start workers
	for _, w := range e.workers {
		go w.Run(ioCtx)
	}

	// Register callbacks
	errChan := make(chan error, len(e.ioList))
	for _, i := range e.ioList {
		ioEntry := i // Make sure dispatch() uses the correct ioEntry
		err := ioEntry.Register(ioCtx, func(p io.Packet, err error) bool {
			if err != nil {
				errChan <- err
				return false
			}
			return e.dispatch(ioEntry, p)
		})
		if err != nil {
			return err
		}
	}

	// Block until IO errors or context is cancelled
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return nil
	}
}

// dispatch dispatches a packet to a worker.
// This must be safe for concurrent use, as it may be called from multiple IOs.
func (e *engine) dispatch(ioEntry io.PacketIO, p io.Packet) bool {
	data := p.Data()
	ipVersion := data[0] >> 4
	var layerType gopacket.LayerType
	if ipVersion == 4 {
		layerType = layers.LayerTypeIPv4
	} else if ipVersion == 6 {
		layerType = layers.LayerTypeIPv6
	} else {
		// Unsupported network layer
		_ = ioEntry.SetVerdict(p, io.VerdictAcceptStream, nil)
		return true
	}
	// Load balance by stream ID
	index := p.StreamID() % uint32(len(e.workers))
	packet := gopacket.NewPacket(data, layerType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	e.workers[index].Feed(&workerPacket{
		StreamID: p.StreamID(),
		Packet:   packet,
		SetVerdict: func(v io.Verdict, b []byte) error {
			return ioEntry.SetVerdict(p, v, b)
		},
	})
	return true
}
