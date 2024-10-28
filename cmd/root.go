package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/tcp"
	"github.com/apernet/OpenGFW/analyzer/udp"
	"github.com/apernet/OpenGFW/engine"
	"github.com/apernet/OpenGFW/io"
	"github.com/apernet/OpenGFW/modifier"
	modUDP "github.com/apernet/OpenGFW/modifier/udp"
	"github.com/apernet/OpenGFW/ruleset"
	"github.com/apernet/OpenGFW/ruleset/builtins/geo"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	appLogo = `
░█▀█░█▀█░█▀▀░█▀█░█▀▀░█▀▀░█░█
░█░█░█▀▀░█▀▀░█░█░█░█░█▀▀░█▄█
░▀▀▀░▀░░░▀▀▀░▀░▀░▀▀▀░▀░░░▀░▀
`
	appDesc    = "Open source network filtering and analysis software"
	appAuthors = "Aperture Internet Laboratory <https://github.com/apernet>"

	appLogLevelEnv  = "OPENGFW_LOG_LEVEL"
	appLogFormatEnv = "OPENGFW_LOG_FORMAT"
)

var logger *zap.Logger

// Flags
var (
	cfgFile   string
	pcapFile  string
	logLevel  string
	logFormat string
)

var rootCmd = &cobra.Command{
	Use:   "OpenGFW [flags] rule_file",
	Short: appDesc,
	Args:  cobra.ExactArgs(1),
	Run:   runMain,
}

var logLevelMap = map[string]zapcore.Level{
	"debug": zapcore.DebugLevel,
	"info":  zapcore.InfoLevel,
	"warn":  zapcore.WarnLevel,
	"error": zapcore.ErrorLevel,
}

var logFormatMap = map[string]zapcore.EncoderConfig{
	"console": {
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		MessageKey:     "msg",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     zapcore.RFC3339TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
	},
	"json": {
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		MessageKey:     "msg",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.EpochMillisTimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
	},
}

// Analyzers & modifiers

var analyzers = []analyzer.Analyzer{
	&tcp.FETAnalyzer{},
	&tcp.HTTPAnalyzer{},
	&tcp.SocksAnalyzer{},
	&tcp.SSHAnalyzer{},
	&tcp.TLSAnalyzer{},
	&tcp.TrojanAnalyzer{},
	&udp.DNSAnalyzer{},
	&udp.OpenVPNAnalyzer{},
	&udp.QUICAnalyzer{},
	&udp.WireGuardAnalyzer{},
}

var modifiers = []modifier.Modifier{
	&modUDP.DNSModifier{},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	initFlags()
	cobra.OnInitialize(initConfig)
	cobra.OnInitialize(initLogger) // initLogger must come after initConfig as it depends on config
}

func initFlags() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
	rootCmd.PersistentFlags().StringVarP(&pcapFile, "pcap", "p", "", "pcap file (optional)")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", envOrDefaultString(appLogLevelEnv, "info"), "log level")
	rootCmd.PersistentFlags().StringVarP(&logFormat, "log-format", "f", envOrDefaultString(appLogFormatEnv, "console"), "log format")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.SupportedExts = append([]string{"yaml", "yml"}, viper.SupportedExts...)
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.opengfw")
		viper.AddConfigPath("/etc/opengfw")
	}
}

func initLogger() {
	level, ok := logLevelMap[strings.ToLower(logLevel)]
	if !ok {
		fmt.Printf("unsupported log level: %s\n", logLevel)
		os.Exit(1)
	}
	enc, ok := logFormatMap[strings.ToLower(logFormat)]
	if !ok {
		fmt.Printf("unsupported log format: %s\n", logFormat)
		os.Exit(1)
	}
	c := zap.Config{
		Level:             zap.NewAtomicLevelAt(level),
		DisableCaller:     true,
		DisableStacktrace: true,
		Encoding:          strings.ToLower(logFormat),
		EncoderConfig:     enc,
		OutputPaths:       []string{"stderr"},
		ErrorOutputPaths:  []string{"stderr"},
	}
	var err error
	logger, err = c.Build()
	if err != nil {
		fmt.Printf("failed to initialize logger: %s\n", err)
		os.Exit(1)
	}
}

type cliConfig struct {
	IO      cliConfigIO      `mapstructure:"io"`
	Workers cliConfigWorkers `mapstructure:"workers"`
	Ruleset cliConfigRuleset `mapstructure:"ruleset"`
	Replay  cliConfigReplay  `mapstructure:"replay"`
}

type cliConfigIO struct {
	QueueSize      uint32  `mapstructure:"queueSize"`
	QueueNum       *uint16 `mapstructure:"queueNum"`
	Table          string  `mapstructure:"table"`
	ConnMarkAccept uint32  `mapstructure:"connMarkAccept"`
	ConnMarkDrop   uint32  `mapstructure:"connMarkDrop"`

	ReadBuffer  int  `mapstructure:"rcvBuf"`
	WriteBuffer int  `mapstructure:"sndBuf"`
	Local       bool `mapstructure:"local"`
	RST         bool `mapstructure:"rst"`
}

type cliConfigReplay struct {
	Realtime bool `mapstructure:"realtime"`
}

type cliConfigWorkers struct {
	Count                      int           `mapstructure:"count"`
	QueueSize                  int           `mapstructure:"queueSize"`
	TCPMaxBufferedPagesTotal   int           `mapstructure:"tcpMaxBufferedPagesTotal"`
	TCPMaxBufferedPagesPerConn int           `mapstructure:"tcpMaxBufferedPagesPerConn"`
	TCPTimeout                 time.Duration `mapstructure:"tcpTimeout"`
	UDPMaxStreams              int           `mapstructure:"udpMaxStreams"`
}

type cliConfigRuleset struct {
	GeoIp   string `mapstructure:"geoip"`
	GeoSite string `mapstructure:"geosite"`
}

func (c *cliConfig) fillLogger(config *engine.Config) error {
	config.Logger = &engineLogger{}
	return nil
}

func (c *cliConfig) fillIO(config *engine.Config) error {
	var ioImpl io.PacketIO
	var err error
	if pcapFile != "" {
		// Setup IO for pcap file replay
		logger.Info("replaying from pcap file", zap.String("pcap file", pcapFile))
		ioImpl, err = io.NewPcapPacketIO(io.PcapPacketIOConfig{
			PcapFile: pcapFile,
			Realtime: c.Replay.Realtime,
		})
	} else {
		// Setup IO for nfqueue
		ioImpl, err = io.NewNFQueuePacketIO(io.NFQueuePacketIOConfig{
			QueueSize:      c.IO.QueueSize,
			QueueNum:       c.IO.QueueNum,
			Table:          c.IO.Table,
			ConnMarkAccept: c.IO.ConnMarkAccept,
			ConnMarkDrop:   c.IO.ConnMarkDrop,

			ReadBuffer:  c.IO.ReadBuffer,
			WriteBuffer: c.IO.WriteBuffer,
			Local:       c.IO.Local,
			RST:         c.IO.RST,
		})
	}

	if err != nil {
		return configError{Field: "io", Err: err}
	}
	config.IO = ioImpl
	return nil
}

func (c *cliConfig) fillWorkers(config *engine.Config) error {
	config.Workers = c.Workers.Count
	config.WorkerQueueSize = c.Workers.QueueSize
	config.WorkerTCPMaxBufferedPagesTotal = c.Workers.TCPMaxBufferedPagesTotal
	config.WorkerTCPMaxBufferedPagesPerConn = c.Workers.TCPMaxBufferedPagesPerConn
	config.WorkerTCPTimeout = c.Workers.TCPTimeout
	config.WorkerUDPMaxStreams = c.Workers.UDPMaxStreams
	return nil
}

// Config validates the fields and returns a ready-to-use engine config.
// This does not include the ruleset.
func (c *cliConfig) Config() (*engine.Config, error) {
	engineConfig := &engine.Config{}
	fillers := []func(*engine.Config) error{
		c.fillLogger,
		c.fillIO,
		c.fillWorkers,
	}
	for _, f := range fillers {
		if err := f(engineConfig); err != nil {
			return nil, err
		}
	}
	return engineConfig, nil
}

func runMain(cmd *cobra.Command, args []string) {
	// Config
	if err := viper.ReadInConfig(); err != nil {
		logger.Fatal("failed to read config", zap.Error(err))
	}
	var config cliConfig
	if err := viper.Unmarshal(&config); err != nil {
		logger.Fatal("failed to parse config", zap.Error(err))
	}
	engineConfig, err := config.Config()
	if err != nil {
		logger.Fatal("failed to parse config", zap.Error(err))
	}
	defer engineConfig.IO.Close() // Make sure to close IO on exit

	// Ruleset
	rawRs, err := ruleset.ExprRulesFromYAML(args[0])
	if err != nil {
		logger.Fatal("failed to load rules", zap.Error(err))
	}
	rsConfig := &ruleset.BuiltinConfig{
		Logger:               &rulesetLogger{},
		GeoMatcher:           geo.NewGeoMatcher(config.Ruleset.GeoSite, config.Ruleset.GeoIp),
		ProtectedDialContext: engineConfig.IO.ProtectedDialContext,
	}
	rs, err := ruleset.CompileExprRules(rawRs, analyzers, modifiers, rsConfig)
	if err != nil {
		logger.Fatal("failed to compile rules", zap.Error(err))
	}
	engineConfig.Ruleset = rs

	// Engine
	en, err := engine.NewEngine(*engineConfig)
	if err != nil {
		logger.Fatal("failed to initialize engine", zap.Error(err))
	}

	// Signal handling
	ctx, cancelFunc := context.WithCancel(context.Background())
	go func() {
		// Graceful shutdown
		shutdownChan := make(chan os.Signal, 1)
		signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)
		<-shutdownChan
		logger.Info("shutting down gracefully...")
		cancelFunc()
	}()
	go func() {
		// Rule reload
		reloadChan := make(chan os.Signal, 1)
		signal.Notify(reloadChan, syscall.SIGHUP)
		for {
			<-reloadChan
			logger.Info("reloading rules")
			rawRs, err := ruleset.ExprRulesFromYAML(args[0])
			if err != nil {
				logger.Error("failed to load rules, using old rules", zap.Error(err))
				continue
			}
			rs, err := ruleset.CompileExprRules(rawRs, analyzers, modifiers, rsConfig)
			if err != nil {
				logger.Error("failed to compile rules, using old rules", zap.Error(err))
				continue
			}
			err = en.UpdateRuleset(rs)
			if err != nil {
				logger.Error("failed to update ruleset", zap.Error(err))
			} else {
				logger.Info("rules reloaded")
			}
		}
	}()

	logger.Info("engine started")
	logger.Info("engine exited", zap.Error(en.Run(ctx)))
}

type engineLogger struct{}

func (l *engineLogger) WorkerStart(id int) {
	logger.Debug("worker started", zap.Int("id", id))
}

func (l *engineLogger) WorkerStop(id int) {
	logger.Debug("worker stopped", zap.Int("id", id))
}

func (l *engineLogger) TCPStreamNew(workerID int, info ruleset.StreamInfo) {
	logger.Debug("new TCP stream",
		zap.Int("workerID", workerID),
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()))
}

func (l *engineLogger) TCPStreamPropUpdate(info ruleset.StreamInfo, close bool) {
	logger.Debug("TCP stream property update",
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.Any("props", info.Props),
		zap.Bool("close", close))
}

func (l *engineLogger) TCPStreamAction(info ruleset.StreamInfo, action ruleset.Action, noMatch bool) {
	if noMatch {
		logger.Debug("TCP stream no match",
			zap.Int64("id", info.ID),
			zap.String("src", info.SrcString()),
			zap.String("dst", info.DstString()),
			zap.String("action", action.String()))
	} else {
		logger.Info("TCP stream action",
			zap.Int64("id", info.ID),
			zap.String("src", info.SrcString()),
			zap.String("dst", info.DstString()),
			zap.String("action", action.String()))
	}
}

func (l *engineLogger) TCPFlush(workerID, flushed, closed int) {
	logger.Debug("TCP flush",
		zap.Int("workerID", workerID),
		zap.Int("flushed", flushed),
		zap.Int("closed", closed))
}

func (l *engineLogger) UDPStreamNew(workerID int, info ruleset.StreamInfo) {
	logger.Debug("new UDP stream",
		zap.Int("workerID", workerID),
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()))
}

func (l *engineLogger) UDPStreamPropUpdate(info ruleset.StreamInfo, close bool) {
	logger.Debug("UDP stream property update",
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.Any("props", info.Props),
		zap.Bool("close", close))
}

func (l *engineLogger) UDPStreamAction(info ruleset.StreamInfo, action ruleset.Action, noMatch bool) {
	if noMatch {
		logger.Debug("UDP stream no match",
			zap.Int64("id", info.ID),
			zap.String("src", info.SrcString()),
			zap.String("dst", info.DstString()),
			zap.String("action", action.String()))
	} else {
		logger.Info("UDP stream action",
			zap.Int64("id", info.ID),
			zap.String("src", info.SrcString()),
			zap.String("dst", info.DstString()),
			zap.String("action", action.String()))
	}
}

func (l *engineLogger) ModifyError(info ruleset.StreamInfo, err error) {
	logger.Error("modify error",
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.Error(err))
}

func (l *engineLogger) AnalyzerDebugf(streamID int64, name string, format string, args ...interface{}) {
	logger.Debug("analyzer debug message",
		zap.Int64("id", streamID),
		zap.String("name", name),
		zap.String("msg", fmt.Sprintf(format, args...)))
}

func (l *engineLogger) AnalyzerInfof(streamID int64, name string, format string, args ...interface{}) {
	logger.Info("analyzer info message",
		zap.Int64("id", streamID),
		zap.String("name", name),
		zap.String("msg", fmt.Sprintf(format, args...)))
}

func (l *engineLogger) AnalyzerErrorf(streamID int64, name string, format string, args ...interface{}) {
	logger.Error("analyzer error message",
		zap.Int64("id", streamID),
		zap.String("name", name),
		zap.String("msg", fmt.Sprintf(format, args...)))
}

type rulesetLogger struct{}

func (l *rulesetLogger) Log(info ruleset.StreamInfo, name string) {
	logger.Info("ruleset log",
		zap.String("name", name),
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.Any("props", info.Props))
}

func (l *rulesetLogger) MatchError(info ruleset.StreamInfo, name string, err error) {
	logger.Error("ruleset match error",
		zap.String("name", name),
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.Error(err))
}

func envOrDefaultString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
