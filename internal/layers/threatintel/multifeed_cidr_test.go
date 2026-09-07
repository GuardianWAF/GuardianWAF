package threatintel

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests: updateEntries used to wholesale-replace the CIDR radix
// tree with the entries of the single feed whose callback fired. Every
// FeedManager gets SetUpdateCallback(l.updateEntries), so with multiple feeds
// the last refresh won: even at startup, NewLayer's per-feed LoadOnce loop
// left the tree holding only the second feed's ranges, and each periodic
// refresh flip-flopped the tree between feeds — silently unflagging every
// other feed's malicious IP ranges from a BLOCKING control. The tree is now
// rebuilt from the union of all feeds' accumulated ranges.

func writeFeedFile(t *testing.T, dir, name, line string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestLayer_MultipleFeeds_CIDRUnion(t *testing.T) {
	dir := t.TempDir()
	feedA := writeFeedFile(t, dir, "feed-a.jsonl",
		`{"cidr":"10.0.0.0/8","info":{"score":90,"type":"botnet","source":"feed-a"}}`)
	feedB := writeFeedFile(t, dir, "feed-b.jsonl",
		`{"cidr":"192.168.50.0/24","info":{"score":90,"type":"malware_c2","source":"feed-b"}}`)

	l, err := NewLayer(&Config{
		Enabled:      true,
		IPReputation: IPRepConfig{Enabled: true, BlockMalicious: true, ScoreThreshold: 50},
		Feeds: []FeedConfig{
			{Type: "file", Path: feedA, Format: "jsonl"},
			{Type: "file", Path: feedB, Format: "jsonl"},
		},
	})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}

	if got := l.Stats()["cidr_entries"]; got != 2 {
		t.Fatalf("cidr_entries=%d, want 2 (one range per feed)", got)
	}
	for _, ip := range []string{"10.5.0.1", "192.168.50.7"} {
		res := l.Process(&engine.RequestContext{ClientIP: net.ParseIP(ip)})
		if res.Action != engine.ActionBlock {
			t.Fatalf("%s action=%s, want block (range from each feed must be enforced)", ip, res.Action)
		}
	}

	// Refresh branch: a callback carrying only feed B's slice must not drop
	// feed A's ranges — the tree is rebuilt from the accumulated union.
	l.updateEntries([]ThreatEntry{
		{CIDR: "192.168.50.0/24", Info: &ThreatInfo{Score: 90, Type: "malware_c2", Source: "feed-b"}},
	})
	if got := l.Stats()["cidr_entries"]; got != 2 {
		t.Fatalf("after single-feed refresh: cidr_entries=%d, want 2 (union preserved)", got)
	}
	if res := l.Process(&engine.RequestContext{ClientIP: net.ParseIP("10.5.0.1")}); res.Action != engine.ActionBlock {
		t.Fatalf("feed-a range unblocked after single-feed refresh: %s", res.Action)
	}
}

// TestLayer_UpdateEntries_SkipsNilInfoAndKeepsExactIP guards the secondary
// branches: entries without Info are skipped (never inserted into the union),
// and exact-IP entries keep flowing into the IP cache alongside CIDRs.
func TestLayer_UpdateEntries_SkipsNilInfoAndKeepsExactIP(t *testing.T) {
	l, err := NewLayer(&Config{Enabled: true})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}

	l.updateEntries([]ThreatEntry{
		{CIDR: "10.0.0.0/8"}, // no Info: must be skipped
		{IP: "203.0.113.9", Info: &ThreatInfo{Score: 80, Type: "scanner", Source: "t"}},
	})

	if got := l.Stats()["cidr_entries"]; got != 0 {
		t.Fatalf("cidr_entries=%d, want 0 (nil-Info entries must be skipped)", got)
	}
	if _, ok := l.ipCache.Get("203.0.113.9"); !ok {
		t.Fatal("exact IP entry missing from ip cache")
	}
}
