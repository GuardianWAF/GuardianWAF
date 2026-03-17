package dashboard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	sessionCookieName = "gwaf_session"
	sessionMaxAge     = 24 * time.Hour
	loginPath         = "/login"
)

// sessionSecret is generated once at startup for HMAC signing.
var sessionSecret []byte

func init() {
	sessionSecret = make([]byte, 32)
	rand.Read(sessionSecret)
}

// signSession creates an HMAC-signed session token: timestamp.signature
func signSession() string {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(ts))
	sig := hex.EncodeToString(mac.Sum(nil))
	return ts + "." + sig
}

// verifySession checks if a session token is valid and not expired.
func verifySession(token string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	ts := parts[0]
	sig := parts[1]

	// Verify HMAC
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(ts))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return false
	}

	// Check expiry
	var unix int64
	for _, c := range ts {
		unix = unix*10 + int64(c-'0')
	}
	created := time.Unix(unix, 0)
	return time.Since(created) < sessionMaxAge
}

// isAuthenticated checks if the request has a valid session cookie or API key.
func (d *Dashboard) isAuthenticated(r *http.Request) bool {
	if d.apiKey == "" {
		return true // No auth configured
	}

	// Check API key header (for programmatic access)
	if key := r.Header.Get("X-API-Key"); key == d.apiKey {
		return true
	}
	if key := r.URL.Query().Get("api_key"); key == d.apiKey {
		return true
	}

	// Check session cookie (for browser access)
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	return verifySession(cookie.Value)
}

// setSessionCookie sets the session cookie on the response.
func setSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    signSession(),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionMaxAge.Seconds()),
	})
}

// loginPage returns the HTML login form.
func loginPage(errMsg string) string {
	errorHTML := ""
	if errMsg != "" {
		errorHTML = `<div class="error">` + errMsg + `</div>`
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
