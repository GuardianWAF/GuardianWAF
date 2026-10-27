package dashboard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeChainedAudit(t *testing.T, n int) (string, AuditChainHead) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := NewPersistentAuditLog(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if err := log.Append(AuditEntry{
			Timestamp: time.Date(2026, 10, 27, 12, 0, i, 0, time.FixedZone("TRT", 3*3600)),
			Method:    "POST", Path: "/api/v1/bans", Mutation: "add_ban",
			AuthType: "session", Principal: "admin", RemoteAddr: "10.0.0.1", Status: 200,
		}); err != nil {
			t.Fatal(err)
		}
	}
	head := log.Head()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	return path, head
}

func auditLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

func writeAuditLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAuditHashChainSurvivesRestart(t *testing.T) {
	path, head := writeChainedAudit(t, 3)
	if head.Seq != 3 || len(head.Hash) != 64 {
		t.Fatalf("head = %+v", head)
	}
	got, err := VerifyAuditFile(path)
	if err != nil || got != head {
		t.Fatalf("VerifyAuditFile = %+v, %v; want %+v", got, err, head)
	}

	// Reopening continues the chain rather than restarting it.
	log, err := NewPersistentAuditLog(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if log.Head() != head {
		t.Fatalf("replayed head = %+v, want %+v", log.Head(), head)
	}
	if err := log.Append(AuditEntry{Timestamp: time.Now(), Method: "DELETE", Path: "/api/v1/bans", Mutation: "remove_ban"}); err != nil {
		t.Fatal(err)
	}
	if e := log.Recent(1)[0]; e.Seq != 4 || e.PrevHash != head.Hash {
		t.Fatalf("appended entry seq=%d prev=%q", e.Seq, e.PrevHash)
	}
	_ = log.Close()
	if got, err := VerifyAuditFile(path); err != nil || got.Seq != 4 {
		t.Fatalf("after restart append: %+v, %v", got, err)
	}
}

func TestAuditHashChainDetectsTampering(t *testing.T) {
	for name, tamper := range map[string]func([]string) []string{
		"edited field": func(l []string) []string {
			l[1] = strings.Replace(l[1], `"principal":"admin"`, `"principal":"someone"`, 1)
			return l
		},
		"deleted entry": func(l []string) []string { return append(l[:1], l[2:]...) },
		"reordered":     func(l []string) []string { l[1], l[2] = l[2], l[1]; return l },
		"inserted legacy": func(l []string) []string {
			legacy := `{"timestamp":"2026-10-27T12:00:00Z","method":"POST","path":"/api/v1/bans","auth_type":"session","principal":"admin","remote_addr":"10.0.0.1","status":200,"mutation":"add_ban"}`
			return append(l[:2], append([]string{legacy}, l[2:]...)...)
		},
		"rehashed without prev": func(l []string) []string {
			// Recomputing one entry's hash cannot hide an edit: the next
			// entry's prev_hash still names the original.
			var e AuditEntry
			mustUnmarshal(t, l[1], &e)
			e.Principal = "someone"
			e.Hash, _ = auditEntryHash(e)
			l[1] = mustMarshal(t, e)
			return l
		},
	} {
		t.Run(name, func(t *testing.T) {
			path, _ := writeChainedAudit(t, 4)
			writeAuditLines(t, path, tamper(auditLines(t, path)))
			if _, err := VerifyAuditFile(path); err == nil {
				t.Fatal("tampered audit log verified")
			}
			if _, err := NewPersistentAuditLog(path, 0); err == nil {
				t.Fatal("tampered audit log opened")
			}
		})
	}
}

// Logs written before the chain existed still open; the chain starts after them.
func TestAuditHashChainAcceptsLegacyPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	legacy := `{"timestamp":"2026-01-02T03:04:05Z","method":"POST","path":"/api/v1/rules","auth_type":"session","principal":"admin","remote_addr":"10.0.0.1","status":200,"mutation":"add_rule"}`
	writeAuditLines(t, path, []string{legacy})
	log, err := NewPersistentAuditLog(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Append(AuditEntry{Timestamp: time.Now(), Method: "POST", Path: "/api/v1/bans", Mutation: "add_ban"}); err != nil {
		t.Fatal(err)
	}
	_ = log.Close()
	if head, err := VerifyAuditFile(path); err != nil || head.Seq != 1 {
		t.Fatalf("legacy prefix: %+v, %v", head, err)
	}
}

// Clamped fields with a rune cut in half must hash the same on replay.
func TestAuditHashChainStableForInvalidUTF8(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := NewPersistentAuditLog(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Append(AuditEntry{Timestamp: time.Now(), Method: "POST", Path: "/x\xff" + strings.Repeat("ğ", maxAuditPathBytes), Mutation: "m"}); err != nil {
		t.Fatal(err)
	}
	_ = log.Close()
	if _, err := VerifyAuditFile(path); err != nil {
		t.Fatal(err)
	}
}

func mustUnmarshal(t *testing.T, s string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(s), v); err != nil {
		t.Fatal(err)
	}
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Whatever request data lands in an entry, the stored chain must verify.
func FuzzAuditHashChainRoundTrip(f *testing.F) {
	f.Add("POST", "/api/v1/bans", "admin", "add_ban")
	f.Add("PUT", "/x\xff\xfe<&> ", "\x00", "�")
	f.Fuzz(func(t *testing.T, method, path, principal, mutation string) {
		if method == "" || path == "" || mutation == "" {
			return
		}
		file := filepath.Join(t.TempDir(), "audit.jsonl")
		log, err := NewPersistentAuditLog(file, 0)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := log.Append(AuditEntry{Timestamp: time.Now(), Method: method, Path: path, Principal: principal, Mutation: mutation}); err != nil {
				t.Fatal(err)
			}
		}
		head := log.Head()
		_ = log.Close()
		if got, err := VerifyAuditFile(file); err != nil || got != head {
			t.Fatalf("VerifyAuditFile = %+v, %v; want %+v", got, err, head)
		}
	})
}
