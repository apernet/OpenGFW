package ruleset

import (
	"context"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/expr-lang/expr/builtin"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/conf"
	"github.com/expr-lang/expr/vm"
	"gopkg.in/yaml.v3"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/modifier"
	"github.com/apernet/OpenGFW/ruleset/builtins"
)

// ExprRule is the external representation of an expression rule.
type ExprRule struct {
	Name     string        `yaml:"name"`
	Action   string        `yaml:"action"`
	Log      bool          `yaml:"log"`
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
	Action      *Action // fallthrough if nil
	Log         bool
	ModInstance modifier.Instance
	Program     *vm.Program
}

var _ Ruleset = (*exprRuleset)(nil)

type exprRuleset struct {
	Rules  []compiledExprRule
	Ans    []analyzer.Analyzer
	Logger Logger
}

func (r *exprRuleset) Analyzers(info StreamInfo) []analyzer.Analyzer {
	return r.Ans
}

func (r *exprRuleset) Match(info StreamInfo) MatchResult {
	env := streamInfoToExprEnv(info)
	for _, rule := range r.Rules {
		v, err := vm.Run(rule.Program, env)
		if err != nil {
			// Log the error and continue to the next rule.
			r.Logger.MatchError(info, rule.Name, err)
			continue
		}
		if vBool, ok := v.(bool); ok && vBool {
			if rule.Log {
				r.Logger.Log(info, rule.Name)
			}
			if rule.Action != nil {
				return MatchResult{
					Action:      *rule.Action,
					ModInstance: rule.ModInstance,
				}
			}
		}
	}
	// No match
	return MatchResult{
		Action: ActionMaybe,
	}
}

// CompileExprRules compiles a list of expression rules into a ruleset.
// It returns an error if any of the rules are invalid, or if any of the analyzers
// used by the rules are unknown (not provided in the analyzer list).
func CompileExprRules(rules []ExprRule, ans []analyzer.Analyzer, mods []modifier.Modifier, config *BuiltinConfig) (Ruleset, error) {
	var compiledRules []compiledExprRule
	fullAnMap := analyzersToMap(ans)
	fullModMap := modifiersToMap(mods)
	depAnMap := make(map[string]analyzer.Analyzer)
	funcMap := buildFunctionMap(config)
	// Compile all rules and build a map of analyzers that are used by the rules.
	for _, rule := range rules {
		if rule.Action == "" && !rule.Log {
			return nil, fmt.Errorf("rule %q must have at least one of action or log", rule.Name)
		}
		var action *Action
		if rule.Action != "" {
			a, ok := actionStringToAction(rule.Action)
			if !ok {
				return nil, fmt.Errorf("rule %q has invalid action %q", rule.Name, rule.Action)
			}
			action = &a
		}
		visitor := &idVisitor{Variables: make(map[string]bool), Identifiers: make(map[string]bool)}
		patcher := &idPatcher{FuncMap: funcMap}
		program, err := expr.Compile(rule.Expr,
			func(c *conf.Config) {
				c.Strict = false
				c.Expect = reflect.Bool
				c.Visitors = append(c.Visitors, visitor, patcher)
				for name, f := range funcMap {
					c.Functions[name] = &builtin.Function{
						Name:  name,
						Func:  f.Func,
						Types: f.Types,
					}
				}
			},
		)
		if err != nil {
			return nil, fmt.Errorf("rule %q has invalid expression: %w", rule.Name, err)
		}
		if patcher.Err != nil {
			return nil, fmt.Errorf("rule %q failed to patch expression: %w", rule.Name, patcher.Err)
		}
		for name := range visitor.Identifiers {
			// Skip built-in analyzers & user-defined variables
			if isBuiltInAnalyzer(name) || visitor.Variables[name] {
				continue
			}
			if f, ok := funcMap[name]; ok {
				// Built-in function, initialize if necessary
				if f.InitFunc != nil {
					if err := f.InitFunc(); err != nil {
						return nil, fmt.Errorf("rule %q failed to initialize function %q: %w", rule.Name, name, err)
					}
				}
			} else if a, ok := fullAnMap[name]; ok {
				// Analyzer, add to dependency map
				depAnMap[name] = a
			}
		}
		cr := compiledExprRule{
			Name:    rule.Name,
			Action:  action,
			Log:     rule.Log,
			Program: program,
		}
		if action != nil && *action == ActionModify {
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
		Rules:  compiledRules,
		Ans:    depAns,
		Logger: config.Logger,
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

// idVisitor is a visitor that collects all identifiers in an expression.
// This is for determining which analyzers are used by the expression.
type idVisitor struct {
	Variables   map[string]bool
	Identifiers map[string]bool
}

func (v *idVisitor) Visit(node *ast.Node) {
	if varNode, ok := (*node).(*ast.VariableDeclaratorNode); ok {
		v.Variables[varNode.Name] = true
	} else if idNode, ok := (*node).(*ast.IdentifierNode); ok {
		v.Identifiers[idNode.Value] = true
	}
}

// idPatcher patches the AST during expr compilation, replacing certain values with
// their internal representations for better runtime performance.
type idPatcher struct {
	FuncMap map[string]*Function
	Err     error
}

func (p *idPatcher) Visit(node *ast.Node) {
	switch (*node).(type) {
	case *ast.CallNode:
		callNode := (*node).(*ast.CallNode)
		if callNode.Callee == nil {
			// Ignore invalid call nodes
			return
		}
		if f, ok := p.FuncMap[callNode.Callee.String()]; ok {
			if f.PatchFunc != nil {
				if err := f.PatchFunc(&callNode.Arguments); err != nil {
					p.Err = err
					return
				}
			}
		}
	}
}

type Function struct {
	InitFunc  func() error
	PatchFunc func(args *[]ast.Node) error
	Func      func(params ...any) (any, error)
	Types     []reflect.Type
}

func buildFunctionMap(config *BuiltinConfig) map[string]*Function {
	return map[string]*Function{
		"geoip": {
			InitFunc:  config.GeoMatcher.LoadGeoIP,
			PatchFunc: nil,
			Func: func(params ...any) (any, error) {
				return config.GeoMatcher.MatchGeoIp(params[0].(string), params[1].(string)), nil
			},
			Types: []reflect.Type{reflect.TypeOf(config.GeoMatcher.MatchGeoIp)},
		},
		"geosite": {
			InitFunc:  config.GeoMatcher.LoadGeoSite,
			PatchFunc: nil,
			Func: func(params ...any) (any, error) {
				return config.GeoMatcher.MatchGeoSite(params[0].(string), params[1].(string)), nil
			},
			Types: []reflect.Type{reflect.TypeOf(config.GeoMatcher.MatchGeoSite)},
		},
		"cidr": {
			InitFunc: nil,
			PatchFunc: func(args *[]ast.Node) error {
				cidrStringNode, ok := (*args)[1].(*ast.StringNode)
				if !ok {
					return fmt.Errorf("cidr: invalid argument type")
				}
				cidr, err := builtins.CompileCIDR(cidrStringNode.Value)
				if err != nil {
					return err
				}
				(*args)[1] = &ast.ConstantNode{Value: cidr}
				return nil
			},
			Func: func(params ...any) (any, error) {
				return builtins.MatchCIDR(params[0].(string), params[1].(*net.IPNet)), nil
			},
			Types: []reflect.Type{reflect.TypeOf(builtins.MatchCIDR)},
		},
		"lookup": {
			InitFunc: nil,
			PatchFunc: func(args *[]ast.Node) error {
				var serverStr *ast.StringNode
				if len(*args) > 1 {
					// Has the optional server argument
					var ok bool
					serverStr, ok = (*args)[1].(*ast.StringNode)
					if !ok {
						return fmt.Errorf("lookup: invalid argument type")
					}
				}
				r := &net.Resolver{
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						if serverStr != nil {
							address = serverStr.Value
						}
						return config.ProtectedDialContext(ctx, network, address)
					},
				}
				if len(*args) > 1 {
					(*args)[1] = &ast.ConstantNode{Value: r}
				} else {
					*args = append(*args, &ast.ConstantNode{Value: r})
				}
				return nil
			},
			Func: func(params ...any) (any, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				return params[1].(*net.Resolver).LookupHost(ctx, params[0].(string))
			},
			Types: []reflect.Type{
				reflect.TypeOf((func(string, *net.Resolver) []string)(nil)),
			},
		},
	}
}
