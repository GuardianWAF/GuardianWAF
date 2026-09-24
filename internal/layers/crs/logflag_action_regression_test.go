package crs

// Regression (round 2026-09-24-crs-denylog-action-collapse): the standalone
// log/nolog/auditlog actions are logging flags, not the primary action, but
// parseActions wrote them into RuleActions.Action with last-token-wins — so
// the canonical SecLang spelling "deny,log" parsed as Action="log" and
// shouldBlock (which blocks only on block|deny|drop) silently lost the
// explicit deny: a blocking rule degraded to log-only unless anomaly scoring
// independently crossed the threshold. The logging flags must never touch
// Action; the primary action must survive them in any order.

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestParse_LogFlagsNeverClobberPrimaryAction(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{"deny then log", `SecRule ARGS "@streq attack" "id:1,phase:2,deny,log,msg:'m'"`, "deny"},
		{"log then deny", `SecRule ARGS "@streq attack" "id:2,phase:2,log,deny,msg:'m'"`, "deny"},
		{"deny then nolog", `SecRule ARGS "@streq attack" "id:3,phase:2,deny,nolog,msg:'m'"`, "deny"},
		{"pass then log", `SecRule ARGS "@streq attack" "id:4,phase:2,pass,log,msg:'m'"`, "pass"},
		{"block then log", `SecRule ARGS "@streq attack" "id:5,phase:2,block,log,msg:'m'"`, "block"},
		{"bare log has no primary action", `SecRule ARGS "@streq attack" "id:6,phase:2,log,msg:'m'"`, ""},
		{"bare nolog has no primary action", `SecRule ARGS "@streq attack" "id:7,phase:2,nolog,msg:'m'"`, ""},
		{"auditlog ignored", `SecRule ARGS "@streq attack" "id:8,phase:2,deny,auditlog,msg:'m'"`, "deny"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewParser()
			rules, err := p.ParseFile(tc.line + "\n")
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(rules) != 1 {
				t.Fatalf("rules = %d, want 1", len(rules))
			}
			if got := rules[0].Actions.Action; got != tc.want {
				t.Fatalf("Action = %q, want %q", got, tc.want)
			}
			// The msg action after the flags must survive parsing intact.
			if rules[0].Actions.Msg != "m" {
				t.Fatalf("Msg = %q, want %q (later actions must still parse)", rules[0].Actions.Msg, "m")
			}
		})
	}
}

// TestLayer_DenyLogBlocks pins the user-visible contract: a deny,log rule
// must block through the real Process path. The rule carries no severity, so
// its match score (default 1) stays below the anomaly threshold (5) — the
// ONLY path to block is the explicit deny via shouldBlock.
func TestLayer_DenyLogBlocks(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "rules.conf")
	line := `SecRule ARGS "@streq attack" "id:1001,phase:2,deny,log,msg:'blocked'"`
	if err := os.WriteFile(conf, []byte(line+"\n"), 0o644); err != nil {
		t.Fatalf("writing rules: %v", err)
	}
	layer := NewLayer(&Config{Enabled: true, RulePath: dir, ParanoiaLevel: 1, AnomalyThreshold: 5})
	if err := layer.LoadError(); err != nil {
		t.Fatalf("load: %v", err)
	}
	req := httptest.NewRequest("GET", "/?arg=attack", nil)
	ctx := &engine.RequestContext{Method: req.Method, Headers: req.Header, Request: req}
	res := layer.Process(ctx)
	if res.Action != engine.ActionBlock {
		t.Fatalf("deny,log rule did not block (Action=%v, Score=%d) — explicit deny lost to the trailing logging flag", res.Action, res.Score)
	}
	if len(res.Findings) == 0 {
		t.Fatalf("blocked result should still carry the finding (the log flag must not suppress detection reporting)")
	}

	// Control: pass,log must stay non-blocking (log flag must not over-block).
	dir2 := t.TempDir()
	conf2 := filepath.Join(dir2, "rules.conf")
	line2 := `SecRule ARGS "@streq attack" "id:1002,phase:2,pass,log,msg:'seen'"`
	if err := os.WriteFile(conf2, []byte(line2+"\n"), 0o644); err != nil {
		t.Fatalf("writing rules: %v", err)
	}
	layer2 := NewLayer(&Config{Enabled: true, RulePath: dir2, ParanoiaLevel: 1, AnomalyThreshold: 5})
	if err := layer2.LoadError(); err != nil {
		t.Fatalf("load control: %v", err)
	}
	req2 := httptest.NewRequest("GET", "/?arg=attack", nil)
	ctx2 := &engine.RequestContext{Method: req2.Method, Headers: req2.Header, Request: req2}
	if res2 := layer2.Process(ctx2); res2.Action == engine.ActionBlock {
		t.Fatalf("pass,log control blocked (Score=%d) — logging flag must not make a rule disruptive", res2.Score)
	}
}
