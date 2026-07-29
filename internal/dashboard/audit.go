package dashboard

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AuditEntry represents a single auditable REST API mutation.
// It captures who did what, when, and the result — never the request body
// or credentials.
type AuditEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	AuthType   string    `json:"auth_type"` // "session", "global_key", "tenant_key"
	Principal  string    `json:"principal"` // tenant ID or "admin"
	RemoteAddr string    `json:"remote_addr"`
	Status     int       `json:"status"`
	Mutation   string    `json:"mutation"` // human-readable summary
}

// AuditLog is a thread-safe ring buffer of recent audit entries.
// Old entries are overwritten when the buffer fills up.
type AuditLog struct {
	mu      sync.Mutex
	entries []AuditEntry
	maxSize int
	pos     int
	full    bool
	file    *os.File
}

var auditPersistenceFailures atomic.Uint64

// AuditPersistenceFailures returns the process-lifetime count of dashboard
// mutation audit records that could not be durably appended.
func AuditPersistenceFailures() uint64 {
	return auditPersistenceFailures.Load()
}

const (
	defaultAuditLogSize = 1000
	auditDirMode        = 0o700
	auditFileMode       = 0o600
	maxAuditEntryBytes  = 64 * 1024
)

// NewAuditLog creates an in-memory audit log ring buffer.
func NewAuditLog(maxSize int) *AuditLog {
	return newAuditLog(maxSize)
}

func newAuditLog(maxSize int) *AuditLog {
	if maxSize <= 0 {
		maxSize = defaultAuditLogSize
	}
	return &AuditLog{
		entries: make([]AuditEntry, maxSize),
		maxSize: maxSize,
	}
}

// NewPersistentAuditLog opens a JSONL audit store and replays its newest
// entries into the bounded in-memory ring. A malformed or unreadable store is
// rejected so operators do not unknowingly start with an incomplete audit log.
func NewPersistentAuditLog(path string, maxSize int) (*AuditLog, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" || path == "." {
		return nil, fmt.Errorf("audit path must not be empty")
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("audit path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), auditDirMode); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(path), auditDirMode); err != nil {
		return nil, fmt.Errorf("secure audit directory: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, auditFileMode)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	closeOnError := func(cause error) (*AuditLog, error) {
		_ = file.Close()
		return nil, cause
	}
	if err := file.Chmod(auditFileMode); err != nil {
		return closeOnError(fmt.Errorf("secure audit log: %w", err))
	}

	log := newAuditLog(maxSize)
	log.file = file
	if _, err := file.Seek(0, 0); err != nil {
		return closeOnError(fmt.Errorf("seek audit log: %w", err))
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), maxAuditEntryBytes)
	line := 0
	for scanner.Scan() {
		line++
		if len(strings.TrimSpace(scanner.Text())) == 0 {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return closeOnError(fmt.Errorf("decode audit log line %d: %w", line, err))
		}
		if entry.Timestamp.IsZero() || entry.Method == "" || entry.Path == "" || entry.Mutation == "" {
			return closeOnError(fmt.Errorf("decode audit log line %d: required audit fields are missing", line))
		}
		log.appendMemory(entry)
	}
	if err := scanner.Err(); err != nil {
		return closeOnError(fmt.Errorf("read audit log: %w", err))
	}
	if _, err := file.Seek(0, 2); err != nil {
		return closeOnError(fmt.Errorf("seek audit log end: %w", err))
	}
	return log, nil
}

func (al *AuditLog) appendMemory(entry AuditEntry) {
	al.entries[al.pos] = entry
	al.pos = (al.pos + 1) % al.maxSize
	if al.pos == 0 {
		al.full = true
	}
}

// Append adds an entry to the audit log and durably syncs persistent stores
// before returning. The ring is updated only after the append succeeds.
func (al *AuditLog) Append(entry AuditEntry) error {
	if al == nil {
		return nil
	}
	al.mu.Lock()
	defer al.mu.Unlock()
	if al.file != nil {
		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("encode audit entry: %w", err)
		}
		data = append(data, '\n')
		if _, err := al.file.Write(data); err != nil {
			return fmt.Errorf("append audit entry: %w", err)
		}
		if err := al.file.Sync(); err != nil {
			return fmt.Errorf("sync audit entry: %w", err)
		}
	}
	al.appendMemory(entry)
	return nil
}

// Close syncs and closes the persistent audit file. It is safe for in-memory logs.
func (al *AuditLog) Close() error {
	if al == nil {
		return nil
	}
	al.mu.Lock()
	defer al.mu.Unlock()
	if al.file == nil {
		return nil
	}
	if err := al.file.Sync(); err != nil {
		return fmt.Errorf("sync audit log: %w", err)
	}
	if err := al.file.Close(); err != nil {
		return fmt.Errorf("close audit log: %w", err)
	}
	al.file = nil
	return nil
}

// Recent returns the most recent N entries in reverse chronological order.
func (al *AuditLog) Recent(n int) []AuditEntry {
	al.mu.Lock()
	defer al.mu.Unlock()

	total := al.pos
	if al.full {
		total = al.maxSize
	}
	if n <= 0 || n > total {
		n = total
	}

	result := make([]AuditEntry, 0, n)
	for i := range n {
		idx := (al.pos - 1 - i + al.maxSize) % al.maxSize
		entry := al.entries[idx]
		if entry.Timestamp.IsZero() {
			break
		}
		result = append(result, entry)
	}
	return result
}

// Len returns the number of entries in the buffer.
func (al *AuditLog) Len() int {
	al.mu.Lock()
	defer al.mu.Unlock()
	if al.full {
		return al.maxSize
	}
	return al.pos
}

// classifyMutation returns a human-readable description of what a request does,
// based on its method and path pattern.
func classifyMutation(method, path string) string {
	switch {
	case method == http.MethodPost && path == "/api/v1/config/reload":
		return "reload_config"
	case method == http.MethodPut && path == "/api/v1/config":
		return "update_config"
	case method == http.MethodPut && strings.HasPrefix(path, "/api/v1/config/"):
		return "update_config_subresource"
	case method == http.MethodPost && path == "/api/v1/rules":
		return "add_rule"
	case method == http.MethodPut && strings.HasPrefix(path, "/api/v1/rules/"):
		return "update_rule"
	case method == http.MethodPatch && strings.HasPrefix(path, "/api/v1/rules/"):
		return "toggle_rule"
	case method == http.MethodDelete && strings.HasPrefix(path, "/api/v1/rules/"):
		return "delete_rule"
	case method == http.MethodPost && path == "/api/v1/alerting/webhooks":
		return "add_webhook"
	case method == http.MethodDelete && strings.HasPrefix(path, "/api/v1/alerting/webhooks/"):
		return "delete_webhook"
	case method == http.MethodPost && path == "/api/v1/alerting/emails":
		return "add_email"
	case method == http.MethodDelete && strings.HasPrefix(path, "/api/v1/alerting/emails/"):
		return "delete_email"
	case method == http.MethodPost && path == "/api/v1/alerting/test":
		return "test_alert"
	case method == http.MethodPost && path == "/api/v1/rotate-key":
		return "rotate_api_key"
	case method == http.MethodPost && strings.HasSuffix(path, "/apikey") && strings.HasPrefix(path, "/api/v1/tenants/"):
		return "rotate_tenant_api_key"
	case method == http.MethodPut && strings.Contains(path, "/config") && strings.HasPrefix(path, "/api/v1/tenants/"):
		return "update_tenant_config"
	case method == http.MethodPost && path == "/api/v1/tenants":
		return "create_tenant"
	case method == http.MethodPut && strings.HasPrefix(path, "/api/v1/tenants/"):
		return "update_tenant"
	case method == http.MethodDelete && strings.HasPrefix(path, "/api/v1/tenants/"):
		return "delete_tenant"
	case method == http.MethodPut && path == "/api/v1/routing":
		return "update_routing"
	case method == http.MethodPost && path == "/api/v1/ipacl":
		return "add_ip_acl"
	case method == http.MethodDelete && path == "/api/v1/ipacl":
		return "remove_ip_acl"
	case method == http.MethodPost && path == "/api/v1/bans":
		return "add_ban"
	case method == http.MethodDelete && path == "/api/v1/bans":
		return "remove_ban"
	case method == http.MethodPut && path == "/api/v1/ai/config":
		return "update_ai_config"
	case method == http.MethodPost && strings.HasPrefix(path, "/api/v1/ai/"):
		return "ai_operation"
	case method == http.MethodPost && path == "/api/v1/alerts":
		return "add_alert"
	case method == http.MethodPut && strings.HasPrefix(path, "/api/v1/alerts/"):
		return "update_alert"
	case method == http.MethodDelete && strings.HasPrefix(path, "/api/v1/alerts/"):
		return "delete_alert"
	case method == http.MethodPost && path == "/api/v1/ssl/certificates":
		return "upload_certificate"
	case method == http.MethodDelete && strings.HasPrefix(path, "/api/v1/ssl/certificates/"):
		return "delete_certificate"
	case strings.HasPrefix(path, "/api/clusters"):
		return "cluster_mutation"
	case strings.HasPrefix(path, "/api/admin/tenants/rules"):
		return "admin_tenant_rule_mutation"
	case strings.HasPrefix(path, "/api/admin/tenants"):
		return "admin_tenant_mutation"
	case method == http.MethodPost && strings.HasPrefix(path, "/api/admin/billing/"):
		return "generate_invoice"
	case strings.HasPrefix(path, "/api/crs/"):
		return "crs_mutation"
	case strings.HasPrefix(path, "/api/dlp/"):
		return "dlp_mutation"
	case strings.HasPrefix(path, "/api/clientside/"):
		return "clientside_mutation"
	case strings.HasPrefix(path, "/api/apivalidation/"):
		return "api_validation_mutation"
	case strings.HasPrefix(path, "/api/virtualpatch/"):
		return "virtual_patch_mutation"
	case method == http.MethodPost && path == "/logout":
		return "logout"
	default:
		return fmt.Sprintf("%s %s", method, path)
	}
}

// auditIdentity captures the principal selected by inner authentication
// middleware. auditWrap intentionally sits outside authentication so denied
// management attempts are recorded too; this shared per-request value preserves
// the authenticated identity without putting mutable state into request context.
type auditIdentity struct {
	authType  string
	principal string
}

// auditWrap wraps a handler with audit logging for mutating requests.
// Non-mutating methods (GET, HEAD, OPTIONS) are passed through without logging.
func (d *Dashboard) auditWrap(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			handler(w, r)
			return
		}

		identity := &auditIdentity{authType: "unauthenticated", principal: "unauthenticated"}
		if authType := getAuthType(r); authType != "" {
			identity.authType = authType
			identity.principal = auditPrincipal(r)
		}
		r = r.WithContext(context.WithValue(r.Context(), auditIdentityCtxKey{}, identity))
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		handler(sw, r)

		entry := AuditEntry{
			Timestamp:  time.Now(),
			Method:     r.Method,
			Path:       r.URL.Path,
			AuthType:   identity.authType,
			Principal:  identity.principal,
			RemoteAddr: d.getClientIP(r),
			Status:     sw.status,
			Mutation:   classifyMutation(r.Method, r.URL.Path),
		}

		if d.auditLog != nil {
			if err := d.auditLog.Append(entry); err != nil {
				auditPersistenceFailures.Add(1)
				dashboardLog.Error("dashboard audit persistence failed",
					"error", err,
					"mutation", entry.Mutation,
					"path", entry.Path)
			}
		}

		// Also emit to structured log. Successful management mutations stay
		// visible at the default production log level.
		if sw.status >= 200 && sw.status < 300 {
			dashboardLog.Info("audit: "+entry.Mutation,
				"method", entry.Method,
				"path", entry.Path,
				"auth_type", entry.AuthType,
				"principal", entry.Principal,
				"status", entry.Status)
		} else {
			dashboardLog.Warn("audit: "+entry.Mutation+" (failed)",
				"method", entry.Method,
				"path", entry.Path,
				"auth_type", entry.AuthType,
				"principal", entry.Principal,
				"status", entry.Status)
		}
	}
}

// statusWriter captures the HTTP status code written by a handler.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

// SetAuditLog replaces the dashboard audit store. The previous store is closed.
func (d *Dashboard) SetAuditLog(log *AuditLog) {
	if log == nil {
		return
	}
	if d.auditLog != nil && d.auditLog != log {
		if err := d.auditLog.Close(); err != nil {
			dashboardLog.Error("close previous dashboard audit log", "error", err)
		}
	}
	d.auditLog = log
}

// handleGetAudit returns recent audit log entries.
func (d *Dashboard) handleGetAudit(w http.ResponseWriter, r *http.Request) {
	if d.auditLog == nil {
		writeJSON(w, http.StatusOK, map[string]any{"entries": []AuditEntry{}, "total": 0})
		return
	}

	n := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = min(parsed, 500)
		}
	}

	entries := d.auditLog.Recent(n)
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"total":   d.auditLog.Len(),
	})
}
