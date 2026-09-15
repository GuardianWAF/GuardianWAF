package crs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Unknown transformations must fail the rule load (SecLang: "Invalid
// transformation"). A rule that silently skips one of its transforms
// inspects untransformed data — a detection bypass — so the engine's
// LoadError path is the fail-closed enforcement point (serve refuses to
// start on a non-nil LoadError). Transform names resolve
// case-insensitively, so a validated case variant must actually apply
// instead of silently no-oping.

func TestParseSecRule_RejectsUnknownTransformation(t *testing.T) {
	p := NewParser()
	_, err := p.parseSecRule(`SecRule ARGS "@streq /etc/passwd" "id:9206001,phase:2,deny,t:normalizePath,msg:'x'"`)
	if err == nil {
		t.Fatal("expected unknown transformation to fail the rule parse")
	}
	if !strings.Contains(err.Error(), "normalizePath") {
		t.Errorf("error should name the unsupported transform, got: %v", err)
	}
}

func TestParseSecRule_AcceptsSupportedTransformsAnyCase(t *testing.T) {
	p := NewParser()
	rule, err := p.parseSecRule(`SecRule ARGS "@rx x" "id:9206002,phase:2,deny,t:none,t:lowercase,t:urlDecodeUni,t:Trim,msg:'x'"`)
	if err != nil {
		t.Fatalf("supported transforms must parse: %v", err)
	}
	got := rule.Actions.Transformations
	want := []string{"none", "lowercase", "urlDecodeUni", "Trim"}
	if len(got) != len(want) {
		t.Fatalf("Transformations = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Transformations[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestTransform_CaseInsensitiveApplication(t *testing.T) {
	if got := Transform("HeLLo", []string{"LOWERCASE"}); got != "hello" {
		t.Errorf("Transform with case-variant name = %q, want %q", got, "hello")
	}
	if got := Transform("HeLLo", []string{"t:UPPERCASE"}); got != "HELLO" {
		t.Errorf("Transform with t:-prefixed case-variant name = %q, want %q", got, "HELLO")
	}
	if got := Transform("a\x00b", []string{"RemoveNulls"}); got != "ab" {
		t.Errorf("Transform RemoveNulls case-variant = %q, want %q", got, "ab")
	}
}

func TestLayer_UnknownTransformationFailsLoad(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "rules.conf")
	if err := os.WriteFile(conf, []byte(`SecRule ARGS "@streq /etc/passwd" "id:9206003,phase:2,deny,t:normalizePath,msg:'x'"`+"\n"), 0o644); err != nil {
		t.Fatalf("writing rules: %v", err)
	}
	layer := NewLayer(&Config{Enabled: true, RulePath: dir, ParanoiaLevel: 1, AnomalyThreshold: 5})
	err := layer.LoadError()
	if err == nil {
		t.Fatal("unknown transformation must fail the rule load (fail-closed)")
	}
	if !strings.Contains(err.Error(), "normalizePath") {
		t.Errorf("LoadError should name the transform, got: %v", err)
	}
}
