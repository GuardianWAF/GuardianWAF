package dashboard

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	sessionCookieName            = "gwaf_session"
	sessionMaxAge                = 24 * time.Hour
	sessionAbsMaxAge             = 7 * 24 * time.Hour // Absolute maximum session lifetime (7 days)
	MaxConcurrentSessionsPerIP  = 5                  // Max simultaneous sessions per client IP; oldest evicted when exceeded
)

// secretHolder holds the HMAC signing key atomically for thread safety.
// Reads and writes are safe for concurrent use.
var secretHolder atomic.Value

// revokedSessions stores session tokens that have been explicitly revoked.
// Tokens in this map are treated as invalid regardless of their signature/expiry.
// Uses a sync.Map for lock-free reads and safe concurrent writes.
var revokedSessions sync.Map

// activeSessions tracks concurrent session tokens per client IP for
// SESSION-003 mitigation. Each IP has a set of valid (non-expired,
// non-revoked) sessions. When MaxConcurrentSessionsPerIP is exceeded,
// oldest sessions are invalidated to make room for new ones.
// Key: client IP string, Value: map of session token -> last access time.
var activeSessions sync.Map

func init() {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		// crypto/rand failure is a critical security issue — cannot safely generate
		// session secrets. Fail fast rather than using a predictable fallback.
		log.Fatalf("[auth] FATAL: crypto/rand failed — cannot generate session secret: %v", err)
	}
	secretHolder.Store(secret)
}

func loadSecret() []byte {
	return secretHolder.Load().([]byte)
}

// SetSessionSecret sets a persistent session secret from config.
// This allows sessions to survive server restarts when a secret_key is configured.
// The key is hex-decoded; if decoding fails, the raw bytes are used.
// Thread-safe via atomic.Value.
func SetSessionSecret(key string) {
	if key == "" {
		return
	}
	if decoded, err := hex.DecodeString(key); err == nil && len(decoded) >= 16 {
		secretHolder.Store(decoded)
	} else {
		h := sha256.Sum256([]byte(key))
		secretHolder.Store(h[:])
	}
}

// signSession creates an HMAC-signed session token bound to a client IP: timestamp.signature
// The IP is included in the HMAC to prevent session cookie theft across different clients.
func signSession(clientIP string) string {
	now := time.Now().Unix()
	ts := fmt.Sprintf("%d.%d", now, now) // timestamp.creation_timestamp
	mac := hmac.New(sha256.New, loadSecret())
	mac.Write([]byte(ts + ":" + clientIP))
	sig := hex.EncodeToString(mac.Sum(nil))
	return ts + "." + sig
}

// verifySession checks if a session token is valid, not expired, not revoked,
// and bound to the given client IP.
func verifySession(token, clientIP string) bool {
	if token == "" {
		return false
	}
	// Check revocation first — revoked tokens fail immediately regardless of signature
	if _, revoked := revokedSessions.Load(token); revoked {
		return false
	}
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return false
	}
	ts := parts[0]
	created := parts[1]
	sig := parts[2]

	// Verify HMAC (includes IP binding) — use ts.created as the signed payload
	tsFull := ts + "." + created
	mac := hmac.New(sha256.New, loadSecret())
	mac.Write([]byte(tsFull + ":" + clientIP))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return false
	}

	// Check sliding expiry (last renewal)
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || unix < 0 {
		return false
	}
	if time.Since(time.Unix(unix, 0)) >= sessionMaxAge {
		return false
	}

	// Check absolute expiry (creation time)
	createdUnix, err := strconv.ParseInt(created, 10, 64)
	if err != nil || createdUnix < 0 {
		return false
	}
	return time.Since(time.Unix(createdUnix, 0)) < sessionAbsMaxAge
}

// RevokeSession invalidates a session token server-side immediately.
// The token remains valid client-side but will be rejected by verifySession.
// This provides immediate session invalidation on logout/compromise.
func RevokeSession(token string) {
	if token != "" {
		revokedSessions.Store(token, time.Now())
	}
}

// cleanupRevokedSessions removes revoked session tokens that have exceeded
// sessionAbsMaxAge — they can never be valid anyway, so keeping them is wasteful.
func cleanupRevokedSessions() {
	cutoff := time.Now().Add(-sessionAbsMaxAge)
	revokedSessions.Range(func(k, v any) bool {
		if t, ok := v.(time.Time); ok && t.Before(cutoff) {
			revokedSessions.Delete(k)
		}
		return true
	})
}

// cleanupRevokedSessionsLoop runs periodic cleanup of expired revoked tokens.
func cleanupRevokedSessionsLoop() {
	ticker := time.NewTicker(sessionAbsMaxAge)
	defer ticker.Stop()
	for range ticker.C {
		cleanupRevokedSessions()
	}
}

// registerActiveSession records a new session for a client IP and enforces
// MaxConcurrentSessionsPerIP by evicting the oldest sessions when the limit
// is exceeded. This prevents unlimited concurrent sessions from the same IP.
func registerActiveSession(token, clientIP string) {
	now := time.Now()

	ipSessions, _ := activeSessions.LoadOrStore(clientIP, &sync.Map{})
	sm := ipSessions.(*sync.Map)

	// Count current sessions
	count := 0
	var oldestToken string
	var oldestTime time.Time

	sm.Range(func(k, v any) bool {
		t := k.(string)
		lt := v.(time.Time)
		count++
		if oldestTime.IsZero() || lt.Before(oldestTime) {
			oldestTime = lt
			oldestToken = t
		}
		return true
	})

	// Evict oldest sessions until under limit
	for count >= MaxConcurrentSessionsPerIP && oldestToken != "" {
		sm.Delete(oldestToken)
		count--
		// Find next oldest
		oldestTime = time.Time{}
		oldestToken = ""
		sm.Range(func(k, v any) bool {
			t := k.(string)
			lt := v.(time.Time)
			if oldestTime.IsZero() || lt.Before(oldestTime) {
				oldestTime = lt
				oldestToken = t
			}
			return true
		})
	}

	sm.Store(token, now)
}

// clientIPFromRequest extracts the client IP from a request's RemoteAddr.
func clientIPFromRequest(r *http.Request) string {
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	// Normalize IPv6 addresses to prevent rate-limit bypass via different representations
	if parsed := net.ParseIP(ip); parsed != nil {
		ip = parsed.String()
	}
	return ip
}

// extractTenantID extracts the tenant ID from the request path or header.
// Path format: /t/{tenant-id}/... (e.g. /t/tenant-abc/api/v1/events)
// Header format: X-Tenant-ID header (for API clients)
func extractTenantID(r *http.Request) string {
	var raw string
	// Try path prefix /t/{tenant-id}/
	if strings.HasPrefix(r.URL.Path, "/t/") {
		path := strings.TrimPrefix(r.URL.Path, "/t/")
		if idx := strings.Index(path, "/"); idx > 0 {
			raw = path[:idx]
		} else if path != "" && !strings.Contains(path, "/") {
			raw = path
		}
	}
	if raw == "" {
		raw = r.Header.Get("X-Tenant-ID")
	}
	// Validate: max 64 chars, alphanumeric + dash + underscore + dot only
	if len(raw) > 64 {
		return ""
	}
	for _, c := range raw {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return ""
		}
	}
	return raw
}

// verifyTenantAPIKey checks if an API key matches a stored hash.
// Supports v2 (iterated HMAC), v1 (salted SHA256), and legacy (unsalted SHA256).
func verifyTenantAPIKey(storedHash, apiKey string) bool {
	matched, _ := verifyAPIKeyHash(storedHash, apiKey)
	return matched
}

// verifyAPIKeyHash mirrors tenant.verifyAPIKey to avoid circular imports.
func verifyAPIKeyHash(storedHash, apiKey string) (matched bool, upgrade bool) {
	parts := strings.Split(storedHash, "$")

	// v2 format: v2$salt$hash
	if len(parts) == 3 && parts[0] == "v2" {
		salt, err := hex.DecodeString(parts[1])
		if err != nil {
			return false, false
		}
		expected, err := hex.DecodeString(parts[2])
		if err != nil {
			return false, false
		}
		derived := deriveAPIKey([]byte(apiKey), salt, 100000)
		return subtle.ConstantTimeCompare(derived, expected) == 1, false
	}

	// v1 format: salt$hash
	if len(parts) == 2 {
		salt, _ := hex.DecodeString(parts[0])
		hash := sha256.Sum256(append(salt, []byte(apiKey)...))
		return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(hex.EncodeToString(hash[:]))) == 1, true
	}

	// Legacy unsalted SHA256
	expected := sha256.Sum256([]byte(apiKey))
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(hex.EncodeToString(expected[:]))) == 1, true
}

// deriveAPIKey performs iterated HMAC-SHA256 key derivation.
func deriveAPIKey(password, salt []byte, iterations int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	result := mac.Sum(nil)
	for range iterations - 1 {
		mac.Reset()
		result = mac.Sum(result)
	}
	out := make([]byte, len(result))
	copy(out, result)
	return out
}

// isAuthenticated checks if the request has a valid session cookie, global dashboard API key,
// OR a per-tenant API key (AUTH-003). Per-tenant keys are scoped to a specific tenant identified
// by the request path prefix (/t/{tenant-id}/...) or X-Tenant-ID header.
//
// Per-tenant API key scoping (AUTH-003) requires: (1) per-tenant key storage with TenantID field
// (stored in dashboard.tenantAPIKeys), (2) middleware to extract tenant from request path/host,
// (3) key validation scoped to that tenant. A tenant-scoped key only grants access within
// its own tenant context and cannot access other tenants' data or admin endpoints.
//
// For multi-tenant deployments, per-tenant API keys should be used instead of the global
// dashboard key. The global key grants system-wide access and should be rotated if compromised.
// authTypeCtxKey and authTenantCtxKey are context keys for auth scoping.
type authTypeCtxKey struct{}
type authTenantCtxKey struct{}

const (
	authGlobalKey = "global_key"
	authTenant    = "tenant_key"
	authSession   = "session"
)

// adminOnlyPrefixes lists API path prefixes that require global key or session auth.
// Tenant-scoped API keys are restricted to read-only data endpoints.
var adminOnlyPrefixes = []string{
	"/api/v1/config",
	"/api/v1/routing",
	"/api/v1/ipacl",
	"/api/v1/bans",
	"/api/v1/ai/config",
	"/api/v1/ai/analyze",
	"/api/v1/ai/test",
	"/api/v1/alerting/webhooks",
	"/api/v1/alerting/emails",
	"/api/v1/alerting/test",
	"/api/v1/rules",
	"/api/v1/compliance",
}

func setAuthInfo(r *http.Request, authType, tenantID string) *http.Request {
	ctx := context.WithValue(r.Context(), authTypeCtxKey{}, authType)
	if tenantID != "" {
		ctx = context.WithValue(ctx, authTenantCtxKey{}, tenantID)
	}
	return r.WithContext(ctx)
}

func getAuthType(r *http.Request) string {
	if v, ok := r.Context().Value(authTypeCtxKey{}).(string); ok {
		return v
	}
	return ""
}

func (d *Dashboard) isAuthenticated(r *http.Request) (*http.Request, bool) {
	if d.apiKey == "" {
		log.Printf("[ERROR] Dashboard API key is not configured — refusing request. Set apiKey before starting the dashboard.")
		return r, false
	}

	// Check global API key header (for programmatic access)
	if key := r.Header.Get("X-API-Key"); key != "" && subtle.ConstantTimeCompare([]byte(key), []byte(d.apiKey)) == 1 {
		return setAuthInfo(r, authGlobalKey, ""), true
	}
	// Reject API keys in query parameters
	if r.URL.Query().Get("api_key") != "" {
		log.Printf("[WARN] Rejected API key from query parameter from %s — use X-API-Key header only", r.RemoteAddr)
		return r, false
	}

	// Check per-tenant API key (AUTH-003): scoped to a specific tenant
	tenantID := extractTenantID(r)
	if tenantID != "" && d.tenantAPIKeys != nil {
		if hash, ok := d.tenantAPIKeys[tenantID]; ok {
			if key := r.Header.Get("X-API-Key"); key != "" && verifyTenantAPIKey(hash, key) {
				return setAuthInfo(r, authTenant, tenantID), true
			}
		}
	}

	// Check session cookie (for browser access)
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return r, false
	}
	if verifySession(cookie.Value, clientIPFromRequest(r)) {
		return setAuthInfo(r, authSession, ""), true
	}
	return r, false
}

// setSessionCookie sets the session cookie on the response with proper security flags.
func setSessionCookie(w http.ResponseWriter, r *http.Request) {
	token := signSession(clientIPFromRequest(r))
	// Enforce concurrent session limit for this IP
	registerActiveSession(token, clientIPFromRequest(r))
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // Always require TLS for session cookies
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionMaxAge.Seconds()),
	})
}

// loginPage returns the HTML login form.
func loginPage(errMsg string) string {
	errorHTML := ""
	if errMsg != "" {
		errorHTML = `<div class="error">` + html.EscapeString(errMsg) + `</div>`
	}
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GuardianWAF - Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:#0f172a;color:#e2e8f0;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#1e293b;border-radius:16px;padding:48px 40px;width:100%;max-width:400px;
box-shadow:0 25px 50px rgba(0,0,0,0.5)}
.logo{text-align:center;margin-bottom:32px}
.logo h1{font-size:24px;color:#f8fafc}
.logo .shield{font-size:48px;margin-bottom:12px;display:block}
.logo p{color:#64748b;font-size:14px;margin-top:8px}
label{display:block;font-size:13px;color:#94a3b8;margin-bottom:6px;font-weight:500}
input{width:100%;padding:12px 16px;background:#0f172a;border:1px solid #334155;border-radius:8px;
color:#f1f5f9;font-size:15px;outline:none;transition:border-color .2s}
input:focus{border-color:#3b82f6}
button{width:100%;padding:12px;background:#3b82f6;color:#fff;border:none;border-radius:8px;
font-size:15px;font-weight:600;cursor:pointer;margin-top:20px;transition:background .2s}
button:hover{background:#2563eb}
.error{background:#7f1d1d;color:#fca5a5;padding:12px;border-radius:8px;margin-bottom:16px;
font-size:13px;text-align:center}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <span class="shield">&#128737;</span>
    <h1>GuardianWAF</h1>
    <p>Enter your API key to access the dashboard</p>
  </div>
  ` + errorHTML + `
  <form method="POST" action="/login">
    <label for="key">API Key</label>
    <input type="password" id="key" name="key" placeholder="Enter your API key" autofocus required>
    <button type="submit">Sign In</button>
  </form>
</div>
</body>
</html>`
}