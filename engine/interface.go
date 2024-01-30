package engine

import (
	"context"

	"github.com/apernet/OpenGFW/io"
	"github.com/apernet/OpenGFW/ruleset"
)

// Engine is the main engine for OpenGFW.
type Engine interface {
	// UpdateRuleset updates the ruleset.
	UpdateRuleset(ruleset.Ruleset) error
	// Run runs the engine, until an error occurs or the context is cancelled.
	Run(context.Context) error
}

// Config is the configuration for the engine.
type Config struct {
	Logger  Logger
	IOs     []io.PacketIO
	Ruleset ruleset.Ruleset

	Workers                          int // Number of workers. Zero or negative means auto (number of CPU cores).
	WorkerQueueSize                  int
	WorkerTCPMaxBufferedPagesTotal   int
	WorkerTCPMaxBufferedPagesPerConn int
	WorkerUDPMaxStreams              int
}

// Logger is the combined logging interface for the engine, workers and analyzers.
type Logger interface {
	WorkerStart(id int)
	WorkerStop(id int)

	TCPStreamNew(workerID int, info ruleset.StreamInfo)
	TCPStreamPropUpdate(info ruleset.StreamInfo, close bool)
	TCPStreamAction(info ruleset.StreamInfo, action ruleset.Action, noMatch bool)

	UDPStreamNew(workerID int, info ruleset.StreamInfo)
	UDPStreamPropUpdate(info ruleset.StreamInfo, close bool)
	UDPStreamAction(info ruleset.StreamInfo, action ruleset.Action, noMatch bool)

	MatchError(info ruleset.StreamInfo, err error)
	ModifyError(info ruleset.StreamInfo, err error)

	AnalyzerDebugf(streamID int64, name string, format string, args ...interface{})
	AnalyzerInfof(streamID int64, name string, format string, args ...interface{})
	AnalyzerErrorf(streamID int64, name string, format string, args ...interface{})
}
