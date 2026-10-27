package threatintel

import (
	"bufio"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: domain reputation must inspect the request's effective Host.
//
// The Host was absent from engine.RequestContext.Headers, because net/http's
// server promotes the request's Host header into Request.Host and deletes it
// from Request.Header — while this layer reads it from that view
// (`getHost(ctx.Headers)`). Domain reputation was therefore dead in
// production for every real request against ADR 0034 ("When
// DomainRepConfig.Enabled is true, the Host header is checked against the
// domain blocklist", Status: Implemented), including the BlockMalicious path.
//
// The earlier domain-block regression test did not catch this because it built
// the context by hand with Headers{"Host": ...}, injecting the value the
// engine never produces. This test parses the request the way the server does,
// so the Host reaches the layer only through the engine's view.
func TestDomainReputationInspectsEffectiveHostFromServedRequest(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "domains.jsonl")
	feed := `{"domain":"evil-phish.example","score":90,"type":"phishing","source":"regression"}` + "\n"
	if err := os.WriteFile(feedPath, []byte(feed), 0o600); err != nil {
		t.Fatalf("write feed: %v", err)
	}

	layer, err := NewLayer(&Config{
		Enabled:   true,
		DomainRep: DomainRepConfig{Enabled: true, BlockMalicious: true},
		Feeds:     []FeedConfig{{Type: "file", Path: feedPath, Format: "jsonl"}},
	})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}

	process := func(raw string) engine.LayerResult {
		t.Helper()
		r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			t.Fatalf("ReadRequest(%q): %v", raw, err)
		}
		ctx := engine.AcquireContext(r, 1, 1024)
		defer engine.ReleaseContext(ctx)
		return layer.Process(ctx)
	}

	// A listed phishing Host must block (block_malicious: true, score 90 >= 70).
	listed := process("POST /login HTTP/1.1\r\nHost: evil-phish.example\r\nContent-Length: 0\r\n\r\n")
	if listed.Action != engine.ActionBlock {
		t.Fatalf("listed phishing Host was not blocked: action = %v, findings = %d "+
			"(the Host never reached the layer's inspection view)", listed.Action, len(listed.Findings))
	}
	if len(listed.Findings) == 0 {
		t.Fatal("blocked request produced no findings")
	}

	// Control: a Host that is not on the feed must stay untouched.
	benign := process("POST /login HTTP/1.1\r\nHost: benign.example\r\nContent-Length: 0\r\n\r\n")
	if benign.Action != engine.ActionPass || len(benign.Findings) != 0 {
		t.Fatalf("benign Host was flagged: action = %v, findings = %d", benign.Action, len(benign.Findings))
	}
}

// Regression for the non-blocking branch of the same defect: with
// block_malicious disabled the documented behaviour is an alert, and that was
// dead in production too.
func TestDomainReputationLogsEffectiveHostFromServedRequest(t *testing.T) {
	layer, err := NewLayer(&Config{
		Enabled:   true,
		DomainRep: DomainRepConfig{Enabled: true, BlockMalicious: false},
	})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	layer.AddDomain("evil-phish.example", &ThreatInfo{Score: 90, Type: "phishing", Source: "regression"})

	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"POST /login HTTP/1.1\r\nHost: evil-phish.example\r\nContent-Length: 0\r\n\r\n")))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	ctx := engine.AcquireContext(r, 1, 1024)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("listed domain produced no alert: the effective Host was not inspected")
	}
	if result.Findings[0].MatchedValue != "evil-phish.example" {
		t.Errorf("finding matched %q, want the requested Host", result.Findings[0].MatchedValue)
	}
}
