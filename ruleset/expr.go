package ruleset

import (
	"fmt"
	"net"
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
	"github.com/apernet/OpenGFW/ruleset/builtins"
	"github.com/apernet/OpenGFW/ruleset/builtins/geo"
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
}

var _ Ruleset = (*exprRuleset)(nil)

type exprRuleset struct {
	Rules      []compiledExprRule
	Ans        []analyzer.Analyzer
	GeoMatcher *geo.GeoMatcher
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
func CompileExprRules(rules []ExprRule, ans []analyzer.Analyzer, mods []modifier.Modifier, config *BuiltinConfig) (Ruleset, error) {
	var compiledRules []compiledExprRule
	fullAnMap := analyzersToMap(ans)
	fullModMap := modifiersToMap(mods)
	depAnMap := make(map[string]analyzer.Analyzer)
	geoMatcher, err := geo.NewGeoMatcher(config.GeoSiteFilename, config.GeoIpFilename)
	if err != nil {
		return nil, err
	}
	// Compile all rules and build a map of analyzers that are used by the rules.
	for _, rule := range rules {
		action, ok := actionStringToAction(rule.Action)
		if !ok {
			return nil, fmt.Errorf("rule %q has invalid action %q", rule.Name, rule.Action)
		}
		visitor := &idVisitor{Identifiers: make(map[string]bool)}
		patcher := &idPatcher{}
		program, err := expr.Compile(rule.Expr,
			func(c *conf.Config) {
				c.Strict = false
				c.Expect = reflect.Bool
				c.Visitors = append(c.Visitors, visitor, patcher)
				registerBuiltinFunctions(c.Functions, geoMatcher)
			},
		)
		if err != nil {
			return nil, fmt.Errorf("rule %q has invalid expression: %w", rule.Name, err)
		}
		if patcher.err != nil {
			return nil, fmt.Errorf("rule %q failed to patch expression: %w", rule.Name, patcher.err)
		}
		for name := range visitor.Identifiers {
			if isBuiltInAnalyzer(name) {
				continue
			}
			// Check if it's one of the built-in functions, and if so,
			// skip it as an analyzer & do initialization if necessary.
			switch name {
			case "geoip":
				if err := geoMatcher.LoadGeoIP(); err != nil {
					return nil, fmt.Errorf("rule %q failed to load geoip: %w", rule.Name, err)
				}
			case "geosite":
				if err := geoMatcher.LoadGeoSite(); err != nil {
					return nil, fmt.Errorf("rule %q failed to load geosite: %w", rule.Name, err)
				}
			case "cidr":
			default:
				a, ok := fullAnMap[name]
				if !ok {
					return nil, fmt.Errorf("rule %q uses unknown analyzer %q", rule.Name, name)
				}
				depAnMap[name] = a
			}
		}
		cr := compiledExprRule{
			Name:    rule.Name,
			Action:  action,
			Program: program,
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

func registerBuiltinFunctions(funcMap map[string]*ast.Function, geoMatcher *geo.GeoMatcher) {
	funcMap["geoip"] = &ast.Function{
		Name: "geoip",
		Func: func(params ...any) (any, error) {
			return geoMatcher.MatchGeoIp(params[0].(string), params[1].(string)), nil
		},
		Types: []reflect.Type{reflect.TypeOf(geoMatcher.MatchGeoIp)},
	}
	funcMap["geosite"] = &ast.Function{
		Name: "geosite",
		Func: func(params ...any) (any, error) {
			return geoMatcher.MatchGeoSite(params[0].(string), params[1].(string)), nil
		},
		Types: []reflect.Type{reflect.TypeOf(geoMatcher.MatchGeoSite)},
	}
	funcMap["cidr"] = &ast.Function{
		Name: "cidr",
		Func: func(params ...any) (any, error) {
			return builtins.MatchCIDR(params[0].(string), params[1].(*net.IPNet)), nil
		},
		Types: []reflect.Type{reflect.TypeOf((func(string, string) bool)(nil)), reflect.TypeOf(builtins.MatchCIDR)},
	}
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
	case "id", "proto", "ip", "port":
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

type idVisitor struct {
	Identifiers map[string]bool
}

func (v *idVisitor) Visit(node *ast.Node) {
	if idNode, ok := (*node).(*ast.IdentifierNode); ok {
		v.Identifiers[idNode.Value] = true
	}
}

type idPatcher struct {
	err error
}

func (p *idPatcher) Visit(node *ast.Node) {
	switch (*node).(type) {
	case *ast.CallNode:
		callNode := (*node).(*ast.CallNode)
		switch callNode.Func.Name {
		case "cidr":
			cidrStringNode, ok := callNode.Arguments[1].(*ast.StringNode)
			if !ok {
				return
			}
			cidr, err := builtins.CompileCIDR(cidrStringNode.Value)
			if err != nil {
				p.err = err
				return
			}
			callNode.Arguments[1] = &ast.ConstantNode{Value: cidr}
		default:
		}
	default:
	}
}
