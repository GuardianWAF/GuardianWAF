package threatintel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: ADR 0034 documents check_redirects as "the request body is scanned
// for URLs and their hostnames are also checked (… a form submission that POSTs
// to a known phishing domain triggers an alert)", and the knob ships enabled in
// the operator-facing config example. It was parsed and plumbed into the layer
// but read by nothing, so the documented control did not exist.
func newDomainRepLayer(t *testing.T, checkRedirects, blockMalicious bool) *Layer {
	t.Helper()

	dir := t.TempDir()
	feedPath := filepath.Join(dir, "domains.jsonl")
	feed := `{"domain":"evil-phish.example","score":90,"type":"phishing","source":"regression"}` + "\n"
	if err := os.WriteFile(feedPath, []byte(feed), 0o600); err != nil {
		t.Fatalf("write feed: %v", err)
	}

	layer, err := NewLayer(&Config{
		Enabled: true,
		DomainRep: DomainRepConfig{
			Enabled:        true,
			BlockMalicious: blockMalicious,
			CheckRedirects: checkRedirects,
		},
		Feeds: []FeedConfig{{Type: "file", Path: feedPath, Format: "jsonl"}},
	})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	return layer
}

func processBody(t *testing.T, layer *Layer, host, body string) engine.LayerResult {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://"+host+"/submit", strings.NewReader(body))
	req.Host = host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := engine.AcquireContext(req, 1, 1<<20)
	defer engine.ReleaseContext(ctx)
	return layer.Process(ctx)
}

func matchedDomains(r engine.LayerResult) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.MatchedValue)
	}
	return out
}

func TestCheckRedirectsScansBodyURLs(t *testing.T) {
	t.Run("form submission with a percent-encoded phishing URL blocks", func(t *testing.T) {
		layer := newDomainRepLayer(t, true, true)
		// A form submission always percent-encodes the value.
		got := processBody(t, layer, "benign.example",
			"url=https%3A%2F%2Fevil-phish.example%2Fpay&submit=1")
		if got.Action != engine.ActionBlock {
			t.Fatalf("listed phishing URL in a form body was not blocked: action=%v findings=%v",
				got.Action, matchedDomains(got))
		}
	})

	t.Run("plain body URL is checked too", func(t *testing.T) {
		layer := newDomainRepLayer(t, true, true)
		got := processBody(t, layer, "benign.example", `{"url":"https://evil-phish.example/pay"}`)
		if got.Action != engine.ActionBlock {
			t.Fatalf("listed phishing URL in a JSON body was not blocked: action=%v findings=%v",
				got.Action, matchedDomains(got))
		}
	})

	t.Run("log-only mode reports the body match without blocking", func(t *testing.T) {
		layer := newDomainRepLayer(t, true, false)
		got := processBody(t, layer, "benign.example", "url=https://evil-phish.example/pay")
		if got.Action == engine.ActionBlock {
			t.Fatalf("block_malicious=false must not block a body URL match")
		}
		if len(got.Findings) != 1 || got.Findings[0].Score != 45 {
			t.Fatalf("body match must be reported at half score like the Host path: %+v", got.Findings)
		}
	})

	t.Run("control: the knob gates the behaviour", func(t *testing.T) {
		layer := newDomainRepLayer(t, false, true)
		got := processBody(t, layer, "benign.example", "url=https://evil-phish.example/pay")
		if len(got.Findings) != 0 {
			t.Fatalf("check_redirects=false must not inspect the body: %v", matchedDomains(got))
		}
	})

	t.Run("control: a clean body URL is not flagged", func(t *testing.T) {
		layer := newDomainRepLayer(t, true, true)
		got := processBody(t, layer, "benign.example", "url=https://clean.example/pay")
		if len(got.Findings) != 0 {
			t.Fatalf("clean body URL flagged: %v", matchedDomains(got))
		}
	})

	t.Run("control: the Host check is unchanged", func(t *testing.T) {
		layer := newDomainRepLayer(t, true, true)
		got := processBody(t, layer, "evil-phish.example", "submit=1")
		if got.Action != engine.ActionBlock {
			t.Fatalf("Host check regressed: action=%v findings=%v", got.Action, matchedDomains(got))
		}
	})

	t.Run("a domain in both the Host and the body is reported once", func(t *testing.T) {
		layer := newDomainRepLayer(t, true, false)
		got := processBody(t, layer, "evil-phish.example", "url=https://evil-phish.example/pay")
		if len(got.Findings) != 1 {
			t.Fatalf("same domain in Host and body produced %d findings, want 1", len(got.Findings))
		}
	})
}

// bodyURLCandidates is the extractor behind the scan: it must tolerate the URL
// shapes a real body carries without inventing hosts.
func TestBodyURLCandidates(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"plain", "url=https://evil.example/pay", []string{"evil.example"}},
		{"encoded form value", "url=https%3A%2F%2Fevil.example%2Fpay", []string{"evil.example"}},
		{"uppercase scheme", "GO TO HTTPS://Evil.Example/Pay", []string{"evil.example"}},
		{"userinfo and port", "https://user:pw@evil.example:8443/pay", []string{"evil.example"}},
		{"trailing sentence dot", "see https://evil.example.", []string{"evil.example"}},
		{"json body", `{"a":"https://evil.example","b":"http://other.example/x"}`, []string{"evil.example", "other.example"}},
		{"duplicates collapse", "https://evil.example/a https://evil.example/b", []string{"evil.example"}},
		{"no scheme", "evil.example/pay", nil},
		{"scheme without authority", "https://", nil},
		{"empty", "", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bodyURLCandidates(tc.body)
			if len(got) != len(tc.want) {
				t.Fatalf("bodyURLCandidates(%q) = %v, want %v", tc.body, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("bodyURLCandidates(%q) = %v, want %v", tc.body, got, tc.want)
				}
			}
		})
	}
}

// A body full of links must not turn one request into unbounded reputation work.
func TestBodyURLCandidatesBounded(t *testing.T) {
	var b strings.Builder
	for i := range maxBodyURLHosts * 2 {
		fmt.Fprintf(&b, "https://host%03d.example/x ", i)
	}
	if got := len(bodyURLCandidates(b.String())); got > maxBodyURLHosts {
		t.Fatalf("extractor returned %d hosts, want at most %d", got, maxBodyURLHosts)
	}
}
