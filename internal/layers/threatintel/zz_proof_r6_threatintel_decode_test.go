package threatintel

// Round-6 proof: the phishing-domain body scan (ADR 0034 check_redirects)
// is defeated by ONE malformed percent-escape anywhere in the request body.
//
// bodyURLCandidates builds its second (decoded) view with a single
// url.QueryUnescape over the WHOLE body. url.QueryUnescape is all-or-nothing:
// a single malformed escape makes it return ("", err). The extractor then
// returns the raw-view hosts only and never looks at the decoded view.
//
// A form body percent-encodes its values, so the raw view holds
// "https%3A%2F%2Fevil-phish.example%2Fpay" — no "http://" literal, so the raw
// scan finds nothing. The decoded view is the only view that can see the
// URL. When the attacker appends a bare "%" anywhere in the body (or any
// other invalid escape), the decoded view is thrown away and the listed
// phishing domain is never checked.
//
// Correct behaviour (asserted here): a body that carries a listed phishing
// URL must be blocked regardless of unrelated malformed escapes elsewhere in
// the same body — a stray "%" in another field must not silently disable the
// control for the whole request.
//
// Controls: the same body WITHOUT the stray escape is blocked (so the harness
// is sound), and a benign body with a stray "%" is not flagged.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

const r6PhishDomain = "evil-r6-phish.example"

// r6Layer builds a threat-intel layer whose feed lists r6PhishDomain.
func r6Layer(t *testing.T) *Layer {
	t.Helper()
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "domains.jsonl")
	feed := `{"domain":"` + r6PhishDomain + `","score":90,"type":"phishing","source":"r6"}` + "\n"
	if err := os.WriteFile(feedPath, []byte(feed), 0o600); err != nil {
		t.Fatalf("write feed: %v", err)
	}
	layer, err := NewLayer(&Config{
		Enabled: true,
		DomainRep: DomainRepConfig{
			Enabled:        true,
			BlockMalicious: true,
			CheckRedirects: true,
		},
		Feeds: []FeedConfig{{Type: "file", Path: feedPath, Format: "jsonl"}},
	})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	return layer
}

// r6Process runs the real layer over a POST body.
func r6Process(t *testing.T, layer *Layer, body string) engine.LayerResult {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://benign.example/submit", strings.NewReader(body))
	req.Host = "benign.example"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := engine.AcquireContext(req, 1, 1<<20)
	defer engine.ReleaseContext(ctx)
	return layer.Process(ctx)
}

func TestProofThreatIntelBodyScanSurvivesMalformedEscape(t *testing.T) {
	layer := r6Layer(t)

	// --- Control 1: the same body WITHOUT a stray escape is blocked. ---
	clean := "url=https%3A%2F%2F" + r6PhishDomain + "%2Fpay&submit=1"
	got := r6Process(t, layer, clean)
	if got.Action != engine.ActionBlock {
		t.Fatalf("CONTROL FAILED: the percent-encoded phishing URL was not blocked without a stray "+
			"escape (action=%v findings=%v) — harness problem, not the defect", got.Action, got.Findings)
	}
	t.Log("CONTROL PASS: a percent-encoded listed phishing URL is blocked")

	// --- The defect: a stray "%" in another field must not disable the scan. ---
	// "&note=100%" is an ordinary value (a discount, a percentage) and makes
	// url.QueryUnescape fail for the ENTIRE body.
	poisoned := "url=https%3A%2F%2F" + r6PhishDomain + "%2Fpay&note=100%"
	got = r6Process(t, layer, poisoned)
	if got.Action != engine.ActionBlock {
		t.Fatalf("FAIL: the listed phishing domain was NOT detected when the body also contained a "+
			"malformed percent-escape (action=%v findings=%v). bodyURLCandidates decodes the whole body "+
			"with one url.QueryUnescape, which is all-or-nothing: a single invalid escape makes it "+
			"return an error, so the decoded view — the only view that can see a percent-encoded URL — "+
			"is discarded and the phishing check is silently disabled for the whole request.",
			got.Action, got.Findings)
	}
	t.Log("PASS: the phishing URL is detected despite an unrelated malformed escape")

	// --- Control 2: a benign body with a stray escape is not flagged. ---
	benign := "url=https%3A%2F%2Fclean-r6.example%2Fpay&note=100%"
	got = r6Process(t, layer, benign)
	if got.Action == engine.ActionBlock || len(got.Findings) != 0 {
		t.Fatalf("CONTROL FAILED: a benign body was flagged (action=%v findings=%v)", got.Action, got.Findings)
	}
	t.Log("CONTROL PASS: a benign body with a stray escape is not flagged")
}
