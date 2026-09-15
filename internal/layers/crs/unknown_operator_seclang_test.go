package crs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Unknown operator names must fail the rule load (SecLang fails the rule
// load on an unrecognized operator). The previous behavior passed unknown
// names through to evaluateOperator, whose default compiled the OPERATOR
// NAME ITSELF as a regex pattern — a rule like `SecRule ARGS "@strq admin"`
// loaded "successfully" and could only ever match a value containing the
// literal substring "@strq": silently inert. Matching is case-insensitive
// (@STREQ is the same operator), and the SecLang implicit-@rx default for
// @-less operator sections is unchanged.

func TestParseSecRule_RejectsUnknownOperator(t *testing.T) {
	p := NewParser()
	_, err := p.parseSecRule(`SecRule ARGS "@strq admin" "id:9207001,phase:2,deny,msg:'x'"`)
	if err == nil {
		t.Fatal("expected unknown operator to fail the rule parse")
	}
	if !strings.Contains(err.Error(), "@strq") {
		t.Errorf("error should name the unknown operator, got: %v", err)
	}
}

func TestParseSecRule_OperatorNamesCaseInsensitive(t *testing.T) {
	p := NewParser()
	rule, err := p.parseSecRule(`SecRule ARGS "@STREQ admin" "id:9207002,phase:2,deny,msg:'x'"`)
	if err != nil {
		t.Fatalf("case-variant operator must parse: %v", err)
	}
	if rule.Operator.Type != "@streq" {
		t.Errorf("operator type = %q, want %q", rule.Operator.Type, "@streq")
	}
}

func TestParseSecRule_ImplicitRxDefaultUnchanged(t *testing.T) {
	p := NewParser()
	rule, err := p.parseSecRule(`SecRule ARGS "admin" "id:9207003,phase:2,deny,msg:'x'"`)
	if err != nil {
		t.Fatalf("implicit-@rx rule must parse: %v", err)
	}
	if rule.Operator.Type != "@rx" || rule.Operator.Argument != "admin" {
		t.Errorf("operator = %+v, want type @rx argument admin", rule.Operator)
	}
}

func TestOperatorEvaluator_RejectsUnknownType(t *testing.T) {
	eval := NewOperatorEvaluator()
	// The value deliberately contains the operator name: the old fallback
	// compiled the NAME as a regex and matched here (result=true, err=nil).
	result, err := eval.Evaluate(RuleOperator{Type: "@nosuchop", Argument: "x"}, "@nosuchop")
	if err == nil {
		t.Fatal("unknown operator type must error at the evaluator, not silently regex")
	}
	if result {
		t.Errorf("unknown operator must not match, got result=true err=%v", err)
	}
}

func TestLayer_UnknownOperatorFailsLoad(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "rules.conf")
	if err := os.WriteFile(conf, []byte(`SecRule ARGS "@strq admin" "id:9207004,phase:2,deny"`+"\n"), 0o644); err != nil {
		t.Fatalf("writing rules: %v", err)
	}
	layer := NewLayer(&Config{Enabled: true, RulePath: dir, ParanoiaLevel: 1, AnomalyThreshold: 5})
	err := layer.LoadError()
	if err == nil {
		t.Fatal("unknown operator must fail the rule load (fail-closed)")
	}
	if !strings.Contains(err.Error(), "@strq") {
		t.Errorf("LoadError should name the operator, got: %v", err)
	}
}
