package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/dashboard"
)

func TestVerifyAuditCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := dashboard.NewPersistentAuditLog(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"add_ban", "remove_ban"} {
		if err := log.Append(dashboard.AuditEntry{Timestamp: time.Now(), Method: "POST", Path: "/api/v1/bans", Mutation: m}); err != nil {
			t.Fatal(err)
		}
	}
	_ = log.Close()

	if code := runMain([]string{"guardianwaf", "verify-audit", path}); code != 0 {
		t.Fatalf("intact log: exit %d", code)
	}
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), "remove_ban", "add_rule", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runMain([]string{"guardianwaf", "verify-audit", path}); code != 1 {
		t.Fatalf("tampered log: exit %d, want 1", code)
	}
	if code := runMain([]string{"guardianwaf", "verify-audit"}); code != 2 {
		t.Fatalf("missing argument: exit %d, want 2", code)
	}
}
