package ruleset

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/conf"
	"github.com/expr-lang/expr/vm"
	"gopkg.in/yaml.v3"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/modifier"
	"github.com/apernet/OpenGFW/ruleset/acl"
)

// ExprRule is the external representation of an expression rule.
type ExprRule struct {
	Name     string        `yaml:"name"`
	Action   string        `yaml:"action"`
	Modifier ModifierEntry `yaml:"modifier"`
	Expr     string        `yaml:"expr"`
}

type ModifierEntry struct {
	Name string                 `yaml:"name"`
	Args map[string]interface{} `yaml:"args"`
}

func ExprRulesFromYAML(file string) ([]ExprRule, error) {
	bs, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var rules []ExprRule
	err = yaml.Unmarshal(bs, &rules)
	return rules, err
}

// compiledExprRule is the internal, compiled representation of an expression rule.
type compiledExprRule struct {
	Name        string
	Action      Action
	ModInstance modifier.Instance
	Program     *vm.Program
	Analyzers   map[string]struct{}
}

var _ Ruleset = (*exprRuleset)(nil)

type exprRuleset struct {
	Rules      []compiledExprRule
	Ans        []analyzer.Analyzer
	GeoMatcher *acl.GeoMatcher
}

func (r *exprRuleset) Analyzers(info StreamInfo) []analyzer.Analyzer {
	return r.Ans
}

func (r *exprRuleset) Match(info StreamInfo) (MatchResult, error) {
	env := streamInfoToExprEnv(info)
	for _, rule := range r.Rules {
		v, err := vm.Run(rule.Program, env)
		if err != nil {
			return MatchResult{
				Action: ActionMaybe,
			}, fmt.Errorf("rule %q failed to run: %w", rule.Name, err)
		}
		if vBool, ok := v.(bool); ok && vBool {
			return MatchResult{
				Action:      rule.Action,
				ModInstance: rule.ModInstance,
			}, nil
		}
	}
	return MatchResult{
		Action: ActionMaybe,
	}, nil
}

// CompileExprRules compiles a list of expression rules into a ruleset.
// It returns an error if any of the rules are invalid, or if any of the analyzers
// used by the rules are unknown (not provided in the analyzer list).
func CompileExprRules(rules []ExprRule, ans []analyzer.Analyzer, mods []modifier.Modifier) (Ruleset, error) {
	var compiledRules []compiledExprRule
	fullAnMap := analyzersToMap(ans)
	fullModMap := modifiersToMap(mods)
	depAnMap := make(map[string]analyzer.Analyzer)
	geoMatcher, err := acl.NewGeoLoader()
	if err != nil {
		return nil, err
	}
	// Compile all rules and build a map of analyzers that are used by the rules.
	for _, rule := range rules {
		action, ok := actionStringToAction(rule.Action)
		if !ok {
			return nil, fmt.Errorf("rule %q has invalid action %q", rule.Name, rule.Action)
		}
		visitor := &depVisitor{Analyzers: make(map[string]struct{})}
		geoip := expr.Function(
			"geoip",
			func(params ...any) (any, error) {
				return geoMatcher.MatchGeoIp(params[0].(string), params[1].(string)), nil
			},
			new(func(string, string) bool),
		)
		geosite := expr.Function(
			"geosite",
			func(params ...any) (any, error) {
				return geoMatcher.MatchGeoSite(params[0].(string), params[1].(string)), nil
			},
			new(func(string, string) bool),
		)
		program, err := expr.Compile(rule.Expr,
			func(c *conf.Config) {
				c.Strict = false
				c.Expect = reflect.Bool
				c.Visitors = append(c.Visitors, visitor)
			},
			geoip,
			geosite,
		)
		if err != nil {
			return nil, fmt.Errorf("rule %q has invalid expression: %w", rule.Name, err)
		}
		for name := range visitor.Analyzers {
			a, ok := fullAnMap[name]
			if !ok && !isBuiltInAnalyzer(name) {
				return nil, fmt.Errorf("rule %q uses unknown analyzer %q", rule.Name, name)
			}
			depAnMap[name] = a
		}
		cr := compiledExprRule{
			Name:      rule.Name,
			Action:    action,
			Program:   program,
			Analyzers: visitor.Analyzers,
		}
		if action == ActionModify {
			mod, ok := fullModMap[rule.Modifier.Name]
			if !ok {
				return nil, fmt.Errorf("rule %q uses unknown modifier %q", rule.Name, rule.Modifier.Name)
			}
			modInst, err := mod.New(rule.Modifier.Args)
			if err != nil {
				return nil, fmt.Errorf("rule %q failed to create modifier instance: %w", rule.Name, err)
			}
			cr.ModInstance = modInst
		}
		compiledRules = append(compiledRules, cr)
	}
	// Convert the analyzer map to a list.
	var depAns []analyzer.Analyzer
	for _, a := range depAnMap {
		depAns = append(depAns, a)
	}
	return &exprRuleset{
		Rules:      compiledRules,
		Ans:        depAns,
		GeoMatcher: geoMatcher,
	}, nil
}

func streamInfoToExprEnv(info StreamInfo) map[string]interface{} {
	m := map[string]interface{}{
		"id":    info.ID,
		"proto": info.Protocol.String(),
		"ip": map[string]string{
			"src": info.SrcIP.String(),
			"dst": info.DstIP.String(),
		},
		"port": map[string]uint16{
			"src": info.SrcPort,
			"dst": info.DstPort,
		},
	}
	for anName, anProps := range info.Props {
		if len(anProps) != 0 {
			// Ignore analyzers with empty properties
			m[anName] = anProps
		}
	}
	return m
}

func isBuiltInAnalyzer(name string) bool {
	switch name {
	case "id", "proto", "ip", "port", "geoip", "geosite":
		return true
	default:
		return false
	}
}

func actionStringToAction(action string) (Action, bool) {
	switch strings.ToLower(action) {
	case "allow":
		return ActionAllow, true
	case "block":
		return ActionBlock, true
	case "drop":
		return ActionDrop, true
	case "modify":
		return ActionModify, true
	default:
		return ActionMaybe, false
	}
}

// analyzersToMap converts a list of analyzers to a map of name -> analyzer.
// This is for easier lookup when compiling rules.
func analyzersToMap(ans []analyzer.Analyzer) map[string]analyzer.Analyzer {
	anMap := make(map[string]analyzer.Analyzer)
	for _, a := range ans {
		anMap[a.Name()] = a
	}
	return anMap
}

// modifiersToMap converts a list of modifiers to a map of name -> modifier.
// This is for easier lookup when compiling rules.
func modifiersToMap(mods []modifier.Modifier) map[string]modifier.Modifier {
	modMap := make(map[string]modifier.Modifier)
	for _, m := range mods {
		modMap[m.Name()] = m
	}
	return modMap
}

type depVisitor struct {
	Analyzers map[string]struct{}
}

func (v *depVisitor) Visit(node *ast.Node) {
	if idNode, ok := (*node).(*ast.IdentifierNode); ok {
		v.Analyzers[idNode.Value] = struct{}{}
	}
}
