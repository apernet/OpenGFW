package engine

import "github.com/apernet/OpenGFW/analyzer"

var _ analyzer.Logger = (*analyzerLogger)(nil)

type analyzerLogger struct {
	StreamID int64
	Name     string
	Logger   Logger
}

func (l *analyzerLogger) Debugf(format string, args ...interface{}) {
	l.Logger.AnalyzerDebugf(l.StreamID, l.Name, format, args...)
}

func (l *analyzerLogger) Infof(format string, args ...interface{}) {
	l.Logger.AnalyzerInfof(l.StreamID, l.Name, format, args...)
}

func (l *analyzerLogger) Errorf(format string, args ...interface{}) {
	l.Logger.AnalyzerErrorf(l.StreamID, l.Name, format, args...)
}

func processPropUpdate(cpm analyzer.CombinedPropMap, name string, update *analyzer.PropUpdate) (updated bool) {
	if update == nil || update.Type == analyzer.PropUpdateNone {
		return false
	}
	switch update.Type {
	case analyzer.PropUpdateMerge:
		m := cpm[name]
		if m == nil {
			m = make(analyzer.PropMap, len(update.M))
			cpm[name] = m
		}
		for k, v := range update.M {
			m[k] = v
		}
		return true
	case analyzer.PropUpdateReplace:
		cpm[name] = update.M
		return true
	case analyzer.PropUpdateDelete:
		delete(cpm, name)
		return true
	default:
		// Invalid update type, ignore for now
		return false
	}
}
