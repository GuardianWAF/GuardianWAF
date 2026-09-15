package crs

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// The @validate* operators are SecLang DETECTION operators: they must MATCH
// (fire the rule) when the inspected value violates the constraint and must
// NOT match compliant values — the polarity the layer's matched->block chain
// consumes. The previous implementations returned "true = input is
// well-formed", so a canonical CRS rule ("@validateByteRange 1-255", the
// NUL-byte detector) blocked every clean request and passed the attack.
// These tests drive the real chain (rules file -> NewLayer -> Process) with
// the canonical ModSecurity usage of each operator.

func newSecLangRuleLayer(t *testing.T, rule string) *Layer {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "rules.conf")
	if err := os.WriteFile(conf, []byte(rule+"\n"), 0o644); err != nil {
		t.Fatalf("writing rules: %v", err)
	}
	layer := NewLayer(&Config{
		Enabled:          true,
		RulePath:         dir,
		ParanoiaLevel:    1,
		AnomalyThreshold: 5,
	})
	if err := layer.LoadError(); err != nil {
		t.Fatalf("rules failed to load: %v", err)
	}
	return layer
}

func runCRSRequest(t *testing.T, layer *Layer, target string) engine.LayerResult {
	t.Helper()
	r := httptest.NewRequest("GET", target, nil)
	ctx := engine.AcquireContext(r, 1, 1<<20)
	defer engine.ReleaseContext(ctx)
	return layer.Process(ctx)
}

func TestValidateByteRangeSecLangContract(t *testing.T) {
	layer := newSecLangRuleLayer(t,
		`SecRule ARGS "@validateByteRange 1-255" "id:9202001,phase:2,deny,severity:CRITICAL,msg:'NUL byte outside allowed range'"`)

	// Byte 0x00 is outside 1-255 — the operator must match and the rule deny.
	res := runCRSRequest(t, layer, "/?q=abc%00def")
	if res.Action != engine.ActionBlock || len(res.Findings) == 0 {
		t.Fatalf("NUL byte in ARGS must be detected (block + finding), got action=%s findings=%d", res.Action, len(res.Findings))
	}
	if res.Findings[0].Category != "9202001" {
		t.Errorf("finding Category = %q, want rule id 9202001", res.Findings[0].Category)
	}

	// All bytes comply — the rule must not fire.
	res = runCRSRequest(t, layer, "/?q=hello")
	if res.Action != engine.ActionPass || len(res.Findings) != 0 {
		t.Fatalf("compliant value must not fire the deny rule, got action=%s findings=%d", res.Action, len(res.Findings))
	}
}

func TestValidateUrlEncodingSecLangContract(t *testing.T) {
	layer := newSecLangRuleLayer(t,
		`SecRule REQUEST_URI "@validateUrlEncoding" "id:9202002,phase:1,deny,severity:CRITICAL,msg:'Invalid URL encoding'"`)

	// %zz is not a valid escape — the operator must match. (REQUEST_URI is the
	// raw-data target: an invalid escape in the query never reaches ARGS,
	// because url.ParseQuery rejects the whole query.)
	res := runCRSRequest(t, layer, "/?q=abc%zz")
	if res.Action != engine.ActionBlock || len(res.Findings) == 0 {
		t.Fatalf("invalid percent escape must be detected (block + finding), got action=%s findings=%d", res.Action, len(res.Findings))
	}

	// Valid escape — no match.
	res = runCRSRequest(t, layer, "/?q=abc%20def")
	if res.Action != engine.ActionPass || len(res.Findings) != 0 {
		t.Fatalf("validly-encoded request must not fire the rule, got action=%s findings=%d", res.Action, len(res.Findings))
	}
}

func TestValidateUtf8EncodingSecLangContract(t *testing.T) {
	layer := newSecLangRuleLayer(t,
		`SecRule ARGS "@validateUtf8Encoding" "id:9202003,phase:2,deny,severity:CRITICAL,msg:'Invalid UTF-8 encoding'"`)

	// 0xFF 0xFE is not valid UTF-8 — must match.
	res := runCRSRequest(t, layer, "/?q=%ff%fe")
	if res.Action != engine.ActionBlock || len(res.Findings) == 0 {
		t.Fatalf("invalid UTF-8 payload must be detected (block + finding), got action=%s findings=%d", res.Action, len(res.Findings))
	}

	// Plain ASCII — no match.
	res = runCRSRequest(t, layer, "/?q=hello")
	if res.Action != engine.ActionPass || len(res.Findings) != 0 {
		t.Fatalf("valid UTF-8 must not fire the rule, got action=%s findings=%d", res.Action, len(res.Findings))
	}

	// A genuine U+FFFD character (EF BF BD) is VALID UTF-8 — no match. The
	// pre-fix RuneError scan misclassified it as invalid, which after the
	// polarity fix would have blocked innocent input.
	res = runCRSRequest(t, layer, "/?q=%EF%BF%BD")
	if res.Action != engine.ActionPass || len(res.Findings) != 0 {
		t.Fatalf("legitimate U+FFFD is valid UTF-8 and must not fire the rule, got action=%s findings=%d", res.Action, len(res.Findings))
	}
}
