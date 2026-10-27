package crs

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regressions from audit round 80 (CRS parser/executor). Evidence:
// .temp_files/ledger_audit80-crs-virtualpatch.md.

func audit80Layer(t *testing.T, files map[string]string) *Layer {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	l := NewLayer(&Config{Enabled: true, ParanoiaLevel: 1, AnomalyThreshold: 1000, RulePath: dir})
	if err := l.LoadError(); err != nil {
		t.Fatalf("LoadError: %v", err)
	}
	return l
}

func audit80Process(l *Layer, target string, hdr map[string]string) engine.LayerResult {
	req := httptest.NewRequest("GET", target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	ctx := engine.AcquireContext(req, 1, 1<<20)
	defer engine.ReleaseContext(ctx)
	return l.Process(ctx)
}

// F185: the layer reuses one Parser for every .conf in a rule directory, and
// ParseFile accumulated into the parser across calls — file N's load
// re-returned files 1..N-1, duplicating their rules (double scores, duplicate
// findings).
func TestCRSMultiFileDirectoryRegistersEachRuleOnce(t *testing.T) {
	rule := func(id string) string {
		return `SecRule ARGS "@contains AUDIT80" "id:` + id + `,phase:2,pass,severity:WARNING,msg:'r'"` + "\n"
	}
	l := audit80Layer(t, map[string]string{"a.conf": rule("1"), "b.conf": rule("2"), "c.conf": rule("3")})
	if got := len(l.GetAllRules()); got != 3 {
		t.Fatalf("FAIL: %d rules registered from 3 single-rule files, want 3", got)
	}
	res := audit80Process(l, "/?q=AUDIT80", nil)
	if res.Score != 15 || len(res.Findings) != 3 {
		t.Fatalf("FAIL: score=%d findings=%d, want 15/3 (rules evaluated more than once)", res.Score, len(res.Findings))
	}
}

// F186: regex key selectors are case-insensitive in SecLang; Go canonicalizes
// header names, so a lowercase header selector never matched.
func TestCRSRegexKeySelectorIsCaseInsensitive(t *testing.T) {
	h := map[string]string{"x-api-key": "AUDIT80"}
	for _, tc := range []struct {
		name, rule string
		want       engine.Action
	}{
		{"lowercase selector", `SecRule REQUEST_HEADERS:/^x-api-/ "@contains AUDIT80" "id:1,phase:1,deny"` + "\n", engine.ActionBlock},
		{"lowercase count", `SecRule &REQUEST_HEADERS:/^x-api-key$/ "@eq 1" "id:2,phase:1,deny"` + "\n", engine.ActionBlock},
		{"anchoring kept", `SecRule REQUEST_HEADERS:/^api-/ "@contains AUDIT80" "id:3,phase:1,deny"` + "\n", engine.ActionPass},
	} {
		l := audit80Layer(t, map[string]string{"r.conf": tc.rule})
		if got := audit80Process(l, "/", h).Action; got != tc.want {
			t.Errorf("FAIL %s: action=%v, want %v", tc.name, got, tc.want)
		}
	}
}

// F187: exclusions (ARGS|!ARGS:comment) remove the excluded FIELD; they used
// to remove every value equal to it, so repeating the payload in the excluded
// field suppressed inspection of the attacked field.
func TestCRSExclusionIsByFieldNotValue(t *testing.T) {
	l := audit80Layer(t, map[string]string{"r.conf": `SecRule ARGS|!ARGS:comment "@contains AUDIT80" "id:1,phase:2,deny"` + "\n"})
	if got := audit80Process(l, "/?comment=AUDIT80&id=AUDIT80", nil).Action; got != engine.ActionBlock {
		t.Fatalf("FAIL: payload in excluded+attacked field passed (action=%v) — exclusion is by value", got)
	}
	if got := audit80Process(l, "/?comment=AUDIT80", nil).Action; got != engine.ActionPass {
		t.Fatalf("FAIL: excluded field alone fired (action=%v)", got)
	}
	hl := audit80Layer(t, map[string]string{"r.conf": `SecRule REQUEST_HEADERS|!REQUEST_HEADERS:x-free-text "@contains AUDIT80" "id:2,phase:1,deny"` + "\n"})
	if got := audit80Process(hl, "/", map[string]string{"X-Free-Text": "AUDIT80"}).Action; got != engine.ActionPass {
		t.Fatalf("FAIL: case-insensitive header exclusion did not exclude (action=%v)", got)
	}
	if got := audit80Process(hl, "/", map[string]string{"X-Free-Text": "AUDIT80", "X-Other": "AUDIT80"}).Action; got != engine.ActionBlock {
		t.Fatalf("FAIL: header exclusion suppressed a different header with the same value (action=%v)", got)
	}
}
