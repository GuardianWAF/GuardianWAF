package dashboard

import (
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
	"sync/atomic"
	"time"
)

const (
	sessionCookieName = "gwaf_session"
	sessionMaxAge     = 24 * time.Hour
)

// secretHolder holds the HMAC signing key atomically for thread safety.
// Reads and writes are safe for concurrent use.
var secretHolder atomic.Value

func init() {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
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
	ts := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, loadSecret())
	mac.Write([]byte(ts + ":" + clientIP))
	sig := hex.EncodeToString(mac.Sum(nil))
	return ts + "." + sig
}

// verifySession checks if a session token is valid, not expired, and bound to the given client IP.
func verifySession(token, clientIP string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	ts := parts[0]
	sig := parts[1]

	// Verify HMAC (includes IP binding)
	mac := hmac.New(sha256.New, loadSecret())
	mac.Write([]byte(ts + ":" + clientIP))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return false
	}

	// Check expiry
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || unix < 0 {
		return false
	}
	created := time.Unix(unix, 0)
	return time.Since(created) < sessionMaxAge
}

// clientIPFromRequest extracts the client IP from a request's RemoteAddr.
func clientIPFromRequest(r *http.Request) string {
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	return ip
}

// isAuthenticated checks if the request has a valid session cookie or API key.
func (d *Dashboard) isAuthenticated(r *http.Request) bool {
	if d.apiKey == "" {
		// This should never happen — main.go auto-generates an API key.
		// Library users must set one via SetSessionSecret() or New(..., apiKey).
		log.Printf("[ERROR] Dashboard API key is not configured — refusing request. Set apiKey before starting the dashboard.")
		return false
	}

	// Check API key header (for programmatic access)
	if key := r.Header.Get("X-API-Key"); key != "" && subtle.ConstantTimeCompare([]byte(key), []byte(d.apiKey)) == 1 {
		return true
	}
	// Reject API keys in query parameters — they leak via access logs, browser history, and Referer headers
	if r.URL.Query().Get("api_key") != "" {
		log.Printf("[WARN] Rejected API key from query parameter from %s — use X-API-Key header only", r.RemoteAddr)
		return false
	}

	// Check session cookie (for browser access)
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	return verifySession(cookie.Value, clientIPFromRequest(r))
}

// setSessionCookie sets the session cookie on the response with proper security flags.
func setSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    signSession(clientIPFromRequest(r)),
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
