package lfi

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestCoverageGaps(t *testing.T) {
	d := NewDetector(true, 1)
	if d.Order() != 0 {
		t.Fatalf("Order() = %d, want 0", d.Order())
	}
	result := d.Process(&engine.RequestContext{
		NormalizedHeaders: map[string][]string{"Referer": {"safe", "../etc/passwd"}},
	})
	if result.Action != engine.ActionLog {
		t.Fatalf("normalized Referer action = %v, want log", result.Action)
	}

	if got := checkWindowsPaths(`progra~1`, "query"); len(got) == 0 {
		t.Fatal("expected Windows short-name finding")
	}
	if got := safeTruncate("short", 100); got != "short" {
		t.Fatalf("safeTruncate short = %q", got)
	}
	got := safeTruncate(strings.Repeat("a", 98)+"€", 100)
	if !utf8.ValidString(got) || len(got) != 98 {
		t.Fatalf("safeTruncate split UTF-8: %q (%d bytes)", got, len(got))
	}
}

func TestTrieRestartCanMatchSingleByteTerminal(t *testing.T) {
	tree := &sensitivePathTrie{root: &trieNode{}}
	tree.root.children['a'] = &trieNode{}
	tree.root.children['x'] = &trieNode{score: 10, description: "x"}
	if got := tree.checkWithTrie("ax", "query"); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
}
