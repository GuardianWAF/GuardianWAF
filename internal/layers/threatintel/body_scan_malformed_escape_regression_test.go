package threatintel

// Regression: the phishing-domain body scan (ADR 0034 check_redirects) must
// not be defeated by a malformed percent-escape elsewhere in the body.
//
// bodyURLCandidates builds its second (decoded) view with a single
// url.QueryUnescape over the WHOLE body. url.QueryUnescape is all-or-nothing:
// one malformed escape makes it return ("", err), and the extractor then
// returned the raw-view hosts only. A form body percent-encodes its values,
// so the raw view holds "https%3A%2F%2F<domain>" — no "http://" literal, so
// the raw scan finds nothing. The decoded view was therefore the ONLY view
// that could see a percent-encoded URL, and a stray "%" in an unrelated field
// ("note=100%") discarded it and silenced the control for the whole request.
//
// The decoded view is now produced with the repo's canonical tolerant decoder
// (sanitizer.DecodeURLRecursive), which keeps an invalid escape literal
// instead of failing the entire body.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

const malformedEscapePhishDomain = "evil-malformed-escape.example"

// malformedEscapeLayer builds a threat-intel layer whose feed lists
// malformedEscapePhishDomain.
func malformedEscapeLayer(t *testing.T) *Layer {
	t.Helper()
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "domains.jsonl")
	feed := `{"domain":"` + malformedEscapePhishDomain + `","score":90,"type":"phishing","source":"regression"}` + "\n"
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

// malformedEscapeProcess runs the real layer over a POST body.
func malformedEscapeProcess(t *testing.T, layer *Layer, body string) engine.LayerResult {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://benign.example/submit", strings.NewReader(body))
	req.Host = "benign.example"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := engine.AcquireContext(req, 1, 1<<20)
	defer engine.ReleaseContext(ctx)
	return layer.Process(ctx)
}

func TestBodyScanSurvivesMalformedPercentEscape(t *testing.T) {
	encoded := "url=https%3A%2F%2F" + malformedEscapePhishDomain + "%2Fpay"

	t.Run("a listed phishing URL is blocked despite a stray escape", func(t *testing.T) {
		layer := malformedEscapeLayer(t)
		got := malformedEscapeProcess(t, layer, encoded+"&note=100%")
		if got.Action != engine.ActionBlock {
			t.Fatalf("the listed phishing domain was not detected when the body also contained a "+
				"malformed percent-escape (action=%v findings=%v) — the decoded view was discarded "+
				"whole, so the phishing check was silently disabled for this request",
				got.Action, got.Findings)
		}
	})

	t.Run("a listed phishing URL is blocked despite an invalid hex escape", func(t *testing.T) {
		layer := malformedEscapeLayer(t)
		got := malformedEscapeProcess(t, layer, encoded+"&note=%zz")
		if got.Action != engine.ActionBlock {
			t.Fatalf("the listed phishing domain was not detected with an invalid hex escape in the "+
				"body (action=%v findings=%v)", got.Action, got.Findings)
		}
	})

	t.Run("a double-encoded phishing URL is detected too", func(t *testing.T) {
		layer := malformedEscapeLayer(t)
		// "https%253A%252F%252F<domain>" decodes to the percent-encoded form
		// in one pass and to the URL in the next; the scan must reach it.
		double := "url=https%253A%252F%252F" + malformedEscapePhishDomain + "%252Fpay"
		got := malformedEscapeProcess(t, layer, double)
		if got.Action != engine.ActionBlock {
			t.Fatalf("a double-encoded phishing URL was not detected (action=%v findings=%v)",
				got.Action, got.Findings)
		}
	})

	// Control: the same body without a stray escape is blocked, so the cases
	// above cannot pass merely because the scan was broken.
	t.Run("control: the same body without a stray escape is blocked", func(t *testing.T) {
		layer := malformedEscapeLayer(t)
		got := malformedEscapeProcess(t, layer, encoded+"&submit=1")
		if got.Action != engine.ActionBlock {
			t.Fatalf("control failed: the percent-encoded phishing URL was not blocked (action=%v findings=%v)",
				got.Action, got.Findings)
		}
	})

	// Control: a benign body carrying a stray escape is not flagged.
	t.Run("control: a benign body with a stray escape is not flagged", func(t *testing.T) {
		layer := malformedEscapeLayer(t)
		got := malformedEscapeProcess(t, layer, "url=https%3A%2F%2Fclean.example%2Fpay&note=100%")
		if got.Action == engine.ActionBlock || len(got.Findings) != 0 {
			t.Fatalf("control failed: a benign body was flagged (action=%v findings=%v)",
				got.Action, got.Findings)
		}
	})
}

// The extractor itself must not lose a host to an unrelated malformed escape.
func TestBodyURLCandidatesSurvivesMalformedEscape(t *testing.T) {
	got := bodyURLCandidates("url=https%3A%2F%2Fevil.example%2Fpay&note=100%")
	if len(got) != 1 || got[0] != "evil.example" {
		t.Fatalf("bodyURLCandidates = %v, want [evil.example]", got)
	}
}
