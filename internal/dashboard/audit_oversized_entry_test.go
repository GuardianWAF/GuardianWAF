package dashboard

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Regression: AuditLog.Append wrote request-derived fields (Path, and the
// path itself in unclassified Mutations) without a size cap, while the
// startup replay reads with a scanner capped at maxAuditEntryBytes and a
// longer line fails startup by design. A single long-path request therefore
// made every subsequent process start fail with bufio.ErrTooLong until the
// JSONL was hand-edited.
func TestAuditReplaysAfterOversizedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	log, err := NewPersistentAuditLog(path, 100)
	if err != nil {
		t.Fatalf("NewPersistentAuditLog: %v", err)
	}

	bigPath := "/api/v1/config/" + strings.Repeat("a", 100*1024)
	if err := log.Append(AuditEntry{
		Timestamp:  time.Now(),
		Method:     "PUT",
		Path:       bigPath,
		AuthType:   "global_key",
		Principal:  "admin",
		RemoteAddr: "203.0.113.9",
		Status:     200,
		Mutation:   "update_config",
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := NewPersistentAuditLog(path, 100)
	if err != nil {
		t.Fatalf("audit log is not replayable after an oversized entry: %v", err)
	}
	defer reopened.Close()

	entries := reopened.Recent(10)
	if len(entries) != 1 {
		t.Fatalf("replay lost the entry (got %d, want 1)", len(entries))
	}
	// The clamped path must retain the route prefix so the audit stays useful.
	if !strings.HasPrefix(entries[0].Path, "/api/v1/config/") {
		t.Fatalf("clamped path lost its route prefix: %q", entries[0].Path)
	}
}

// Control: normal-length paths must be preserved verbatim by the clamp.
func TestAuditPreservesNormalPathsVerbatim(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	log, err := NewPersistentAuditLog(path, 100)
	if err != nil {
		t.Fatalf("NewPersistentAuditLog: %v", err)
	}
	normal := "/api/v1/config/waf"
	if err := log.Append(AuditEntry{
		Timestamp: time.Now(),
		Method:    "PUT",
		Path:      normal,
		AuthType:  "global_key",
		Principal: "admin",
		Status:    200,
		Mutation:  "update_config_subresource",
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := NewPersistentAuditLog(path, 100)
	if err != nil {
		t.Fatalf("replay of normal entries failed: %v", err)
	}
	defer reopened.Close()

	entries := reopened.Recent(10)
	if len(entries) != 1 || entries[0].Path != normal {
		t.Fatalf("normal path not preserved verbatim: %+v", entries)
	}
}
