package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewAuditLog_DefaultSize(t *testing.T) {
	al := NewAuditLog(0)
	if al.maxSize != defaultAuditLogSize {
		t.Errorf("expected default size %d, got %d", defaultAuditLogSize, al.maxSize)
	}
	al = NewAuditLog(-5)
	if al.maxSize != defaultAuditLogSize {
		t.Errorf("expected default size %d for negative input, got %d", defaultAuditLogSize, al.maxSize)
	}
	al = NewAuditLog(10)
	if al.maxSize != 10 {
		t.Errorf("expected size 10, got %d", al.maxSize)
	}
}

func TestAuditLog_AppendAndRecent(t *testing.T) {
	al := NewAuditLog(3)
	if al.Len() != 0 {
		t.Errorf("empty log Len = %d, want 0", al.Len())
	}
	if got := al.Recent(10); len(got) != 0 {
		t.Errorf("empty log Recent = %d entries, want 0", len(got))
	}

	base := time.Now()
	for i := range 2 {
		al.Append(AuditEntry{Timestamp: base.Add(time.Duration(i) * time.Second), Path: fmt.Sprintf("/p%d", i)})
	}
	if al.Len() != 2 {
		t.Errorf("Len = %d, want 2", al.Len())
	}
	got := al.Recent(10)
	if len(got) != 2 {
		t.Fatalf("Recent = %d entries, want 2", len(got))
	}
	// Newest first
	if got[0].Path != "/p1" || got[1].Path != "/p0" {
		t.Errorf("Recent order = [%s, %s], want [/p1, /p0]", got[0].Path, got[1].Path)
	}
}

func TestAuditLog_WrapAround(t *testing.T) {
	al := NewAuditLog(3)
	base := time.Now()
	for i := range 5 {
		al.Append(AuditEntry{Timestamp: base.Add(time.Duration(i) * time.Second), Path: fmt.Sprintf("/p%d", i)})
	}
	if al.Len() != 3 {
		t.Errorf("Len after wrap = %d, want 3", al.Len())
	}
	got := al.Recent(0) // n <= 0 → all entries
	if len(got) != 3 {
		t.Fatalf("Recent = %d entries, want 3", len(got))
	}
	want := []string{"/p4", "/p3", "/p2"}
	for i, w := range want {
		if got[i].Path != w {
			t.Errorf("Recent[%d] = %s, want %s", i, got[i].Path, w)
		}
	}
	// Limit smaller than total
	got = al.Recent(2)
	if len(got) != 2 || got[0].Path != "/p4" || got[1].Path != "/p3" {
		t.Errorf("Recent(2) = %v, want [/p4, /p3]", got)
	}
}

func TestClassifyMutation(t *testing.T) {
	tests := []struct {
		method, path, want string
	}{
		{http.MethodPost, "/api/v1/config/reload", "reload_config"},
		{http.MethodPut, "/api/v1/config", "update_config"},
		{http.MethodPut, "/api/v1/config/ratelimit", "update_config_subresource"},
		{http.MethodPost, "/api/v1/rules", "add_rule"},
		{http.MethodPut, "/api/v1/rules/42", "update_rule"},
		{http.MethodPatch, "/api/v1/rules/42", "toggle_rule"},
		{http.MethodDelete, "/api/v1/rules/42", "delete_rule"},
		{http.MethodPost, "/api/v1/alerting/webhooks", "add_webhook"},
		{http.MethodDelete, "/api/v1/alerting/webhooks/slack", "delete_webhook"},
		{http.MethodPost, "/api/v1/alerting/emails", "add_email"},
		{http.MethodDelete, "/api/v1/alerting/emails/ops", "delete_email"},
		{http.MethodPost, "/api/v1/rotate-key", "rotate_api_key"},
		{http.MethodPost, "/api/v1/tenants", "create_tenant"},
		{http.MethodPut, "/api/v1/tenants/t1", "update_tenant"},
		{http.MethodDelete, "/api/v1/tenants/t1", "delete_tenant"},
		{http.MethodPost, "/api/v1/ai/analyze", "ai_operation"},
		{http.MethodPost, "/api/v1/alerting/test", "test_alert"},
		{http.MethodPost, "/logout", "logout"},
		{http.MethodPost, "/api/v1/unknown", "POST /api/v1/unknown"},
	}
	for _, tt := range tests {
		if got := classifyMutation(tt.method, tt.path); got != tt.want {
			t.Errorf("classifyMutation(%s, %s) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestAuditWrap_SkipsReadOnlyMethods(t *testing.T) {
	d := New(nil, nil, "test-key")
	handler := d.auditWrap(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest(method, "/api/v1/rules", nil))
		if w.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", method, w.Code)
		}
	}
	if d.auditLog.Len() != 0 {
		t.Errorf("read-only methods were audited: %d entries", d.auditLog.Len())
	}
}

func TestAuditWrap_RecordsMutation(t *testing.T) {
	d := New(nil, nil, "test-key")
	handler := d.auditWrap(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil)
	req.RemoteAddr = "192.0.2.7:1234"
	req = setAuthInfo(req, authGlobalKey, "")
	w := httptest.NewRecorder()
	handler(w, req)

	entries := d.auditLog.Recent(0)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Mutation != "add_rule" || e.Status != http.StatusCreated ||
		e.AuthType != authGlobalKey || e.Principal != "admin" || e.RemoteAddr != "192.0.2.7" {
		t.Errorf("unexpected entry: %+v", e)
	}
}

func TestAuditWrap_TenantPrincipal(t *testing.T) {
	d := New(nil, nil, "test-key")
	handler := d.auditWrap(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rules/9", nil)
	req = setAuthInfo(req, authTenant, "tenant-1")
	w := httptest.NewRecorder()
	handler(w, req)

	entries := d.auditLog.Recent(0)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Principal != "tenant-1" || e.AuthType != authTenant || e.Status != http.StatusForbidden {
		t.Errorf("unexpected entry: %+v", e)
	}
}

func TestAuditWrap_DefaultStatus200(t *testing.T) {
	d := New(nil, nil, "test-key")
	handler := d.auditWrap(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok")) // implicit 200, no WriteHeader call
	})
	handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/logout", nil))

	entries := d.auditLog.Recent(0)
	if len(entries) != 1 || entries[0].Status != http.StatusOK || entries[0].Mutation != "logout" {
		t.Errorf("unexpected entries: %+v", entries)
	}
}

func TestHandleGetAudit(t *testing.T) {
	d := New(nil, nil, "test-key")
	base := time.Now()
	for i := range 5 {
		d.auditLog.Append(AuditEntry{Timestamp: base.Add(time.Duration(i) * time.Second), Path: fmt.Sprintf("/p%d", i)})
	}

	w := httptest.NewRecorder()
	d.handleGetAudit(w, httptest.NewRequest(http.MethodGet, "/api/v1/audit?limit=2", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp struct {
		Entries []AuditEntry `json:"entries"`
		Total   int          `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(resp.Entries) != 2 || resp.Total != 5 {
		t.Errorf("entries = %d, total = %d; want 2, 5", len(resp.Entries), resp.Total)
	}
	if resp.Entries[0].Path != "/p4" {
		t.Errorf("newest entry path = %s, want /p4", resp.Entries[0].Path)
	}

	// Invalid limit falls back to default (100 → all 5 here)
	w = httptest.NewRecorder()
	d.handleGetAudit(w, httptest.NewRequest(http.MethodGet, "/api/v1/audit?limit=abc", nil))
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(resp.Entries) != 5 {
		t.Errorf("entries with invalid limit = %d, want 5", len(resp.Entries))
	}
}

func TestPersistentAuditLog_RequiresAbsolutePath(t *testing.T) {
	if _, err := NewPersistentAuditLog("dashboard.jsonl", 10); err == nil {
		t.Fatal("expected relative audit path to be rejected")
	}
}

func TestPersistentAuditLog_ReplaysAndSecuresStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "dashboard.jsonl")
	log, err := NewPersistentAuditLog(path, 2)
	if err != nil {
		t.Fatalf("NewPersistentAuditLog: %v", err)
	}
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if err := log.Append(AuditEntry{
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Method:    http.MethodPost, Path: fmt.Sprintf("/api/v1/rules/%d", i),
			Mutation: "create rule", Status: http.StatusCreated,
		}); err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if info, err := os.Stat(path); err != nil {
		t.Fatalf("Stat audit file: %v", err)
	} else if got := info.Mode().Perm(); got != auditFileMode {
		t.Fatalf("audit file mode = %o, want %o", got, auditFileMode)
	}
	if info, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatalf("Stat audit directory: %v", err)
	} else if got := info.Mode().Perm(); got != auditDirMode {
		t.Fatalf("audit directory mode = %o, want %o", got, auditDirMode)
	}

	replayed, err := NewPersistentAuditLog(path, 2)
	if err != nil {
		t.Fatalf("reopen audit log: %v", err)
	}
	defer func() { _ = replayed.Close() }()
	entries := replayed.Recent(0)
	if len(entries) != 2 || entries[0].Path != "/api/v1/rules/2" || entries[1].Path != "/api/v1/rules/1" {
		t.Fatalf("replayed entries = %#v", entries)
	}
}

func TestPersistentAuditLog_RejectsCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashboard.jsonl")
	if err := os.WriteFile(path, []byte("{\"timestamp\":\"2026-07-20T12:00:00Z\"\n"), auditFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPersistentAuditLog(path, 10); err == nil {
		t.Fatal("expected malformed audit log to be rejected")
	}
}

func TestAuditWrap_PersistsMutationAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashboard.jsonl")
	first, err := NewPersistentAuditLog(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	d := New(nil, nil, "test-key")
	d.SetAuditLog(first)
	handler := d.auditWrap(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rules/rule-1", nil)
	req.Header.Set("X-API-Key", "test-key")
	w := httptest.NewRecorder()
	handler(w, req)
	if err := d.CloseWithContext(t.Context()); err != nil {
		t.Fatalf("CloseWithContext: %v", err)
	}

	replayed, err := NewPersistentAuditLog(path, 10)
	if err != nil {
		t.Fatalf("reopen audit log: %v", err)
	}
	defer func() { _ = replayed.Close() }()
	entries := replayed.Recent(1)
	if len(entries) != 1 || entries[0].Path != req.URL.Path || entries[0].Status != http.StatusNoContent {
		t.Fatalf("persisted entries = %#v", entries)
	}
}

func TestAuditWrap_CountsPersistenceFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashboard.jsonl")
	persistent, err := NewPersistentAuditLog(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistent.file.Close(); err != nil {
		t.Fatal(err)
	}

	d := New(nil, nil, "test-key")
	d.SetAuditLog(persistent)
	before := AuditPersistenceFailures()
	handler := d.auditWrap(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodDelete, "/api/v1/rules/rule-1", nil))
	if got := AuditPersistenceFailures(); got != before+1 {
		t.Fatalf("audit persistence failures = %d, want %d", got, before+1)
	}
}

func TestHandleGetAudit_NilLog(t *testing.T) {
	d := New(nil, nil, "test-key")
	d.auditLog = nil
	w := httptest.NewRecorder()
	d.handleGetAudit(w, httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp struct {
		Entries []AuditEntry `json:"entries"`
		Total   int          `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(resp.Entries) != 0 || resp.Total != 0 {
		t.Errorf("entries = %d, total = %d; want 0, 0", len(resp.Entries), resp.Total)
	}
}
