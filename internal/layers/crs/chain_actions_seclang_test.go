package crs

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Chained rules written on a single line (six quoted sections) are parsed by
// parseRule's chain block. Its parseActions/parseVariables errors used to be
// discarded, so a chain line carrying an unsupported transform loaded
// "successfully" with its actions silently dropped — the same transform on a
// non-chain rule failed the load. The chain actions' surrounding quotes are
// also stripped now (parseActions does not self-strip, unlike
// parseVariables/parseOperator), so the last action's name is no longer
// corrupted by a trailing quote.

const chainTransformLine = `SecRule ARGS "@streq attack" "id:9001,phase:2,chain" ARGS "@streq x" "phase:2,deny,t:normalizePath"`

func TestParseSecRule_RejectsUnknownTransformInChainLine(t *testing.T) {
	p := NewParser()
	_, err := p.parseSecRule(chainTransformLine)
	if err == nil {
		t.Fatal("expected the chain line's unsupported transform to fail the parse")
	}
	if !strings.Contains(err.Error(), "normalizePath") {
		t.Errorf("error should name the unsupported transform, got: %v", err)
	}
}

func TestParseSecRule_ChainActionsQuotesStripped(t *testing.T) {
	p := NewParser()
	rule, err := p.parseSecRule(`SecRule ARGS "@streq attack" "id:9002,phase:2,deny,chain" ARGS "@streq x" "phase:2,t:lowercase"`)
	if err != nil {
		t.Fatalf("supported transform in chain actions must parse: %v", err)
	}
	if rule.Chain == nil {
		t.Fatal("chain rule expected")
	}
	got := rule.Chain.Actions.Transformations
	if len(got) != 1 || got[0] != "lowercase" {
		t.Errorf("chain Transformations = %v, want [lowercase] (no trailing quote)", got)
	}
}

func TestLayer_UnknownTransformInChainLineFailsLoad(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "rules.conf")
	if err := os.WriteFile(conf, []byte(chainTransformLine+"\n"), 0o644); err != nil {
		t.Fatalf("writing rules: %v", err)
	}
	layer := NewLayer(&Config{Enabled: true, RulePath: dir, ParanoiaLevel: 1, AnomalyThreshold: 5})
	err := layer.LoadError()
	if err == nil {
		t.Fatal("unsupported transform on a chain line must fail the rule load (fail-closed)")
	}
	if !strings.Contains(err.Error(), "normalizePath") {
		t.Errorf("LoadError should name the transform, got: %v", err)
	}
}

func TestLayer_CleanSingleLineChainFires(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "rules.conf")
	clean := `SecRule ARGS "@streq attack" "id:9003,phase:2,deny,chain" ARGS "@streq x" "phase:2"`
	if err := os.WriteFile(conf, []byte(clean+"\n"), 0o644); err != nil {
		t.Fatalf("writing rules: %v", err)
	}
	layer := NewLayer(&Config{Enabled: true, RulePath: dir, ParanoiaLevel: 1, AnomalyThreshold: 5})
	if err := layer.LoadError(); err != nil {
		t.Fatalf("clean chain must load: %v", err)
	}
	req := httptest.NewRequest("GET", "/?arg=attack&x=x", nil)
	ctx := &engine.RequestContext{Method: req.Method, Headers: req.Header, Request: req}
	res := layer.Process(ctx)
	if res.Action != engine.ActionBlock {
		t.Errorf("clean single-line chain must fire (deny), got action=%v findings=%d", res.Action, len(res.Findings))
	}
}
