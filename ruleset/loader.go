package ruleset

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/modifier"
	"go.uber.org/zap"
)

type RuleSetHandler func(Ruleset) error

type RuleSetLoader interface {
	Start() error
}

type SignalRuleSetLoader struct {
	o          sync.Once
	filePath   string
	handler    RuleSetHandler
	reloadChan chan os.Signal
	analyzers  []analyzer.Analyzer
	modifiers  []modifier.Modifier
	config     *BuiltinConfig
	logger     *zap.Logger
}

func NewSignalRuleSetLoader(path string, handler RuleSetHandler, ans []analyzer.Analyzer, mods []modifier.Modifier, cfg *BuiltinConfig) RuleSetLoader {
	return &SignalRuleSetLoader{
		o:          sync.Once{},
		filePath:   path,
		handler:    handler,
		reloadChan: make(chan os.Signal),
		analyzers:  ans,
		modifiers:  mods,
		config:     cfg,
	}
}

func (l *SignalRuleSetLoader) Start() error {
	l.o.Do(
		func() {
			signal.Notify(l.reloadChan, syscall.SIGHUP)
			go func() {
				for {
					<-l.reloadChan
					l.logger.Info("reloading rules")
					rawRs, err := ExprRulesFromYAML(l.filePath)
					if err != nil {
						l.logger.Error("failed to load rules, using old rules", zap.Error(err))
						continue
					}
					rs, err := CompileExprRules(rawRs, l.analyzers, l.modifiers, l.config)
					if err != nil {
						l.logger.Error("failed to compile rules, using old rules", zap.Error(err))
						continue
					}
					err = l.handler(rs)
					if err != nil {
						l.logger.Error("failed to update ruleset", zap.Error(err))
					} else {
						l.logger.Info("rules reloaded")
					}
				}
			}()
		},
	)
	return nil
}
