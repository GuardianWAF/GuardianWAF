package dashboard

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"math"
	"net"
	"net/http"
	"runtime/debug"
	"sync"
	"time"
)

var loginLog = slog.Default().With(slog.String("component", "dashboard/login"))

// maxLoginRequestBody caps the size of the login form body (4 KiB). The
// form only carries an API key + minimal fields; anything larger is either
// a misuse or a probing attempt and is rejected with 413 before parsing.
const maxLoginRequestBody = 4096

type loginBucket struct {
	mu        sync.Mutex
	attempts  int
	lastFail  time.Time
	locked    bool
	lockUntil time.Time
}

// apiBucket is a per-IP token bucket for API rate limiting.
type apiBucket struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

// apiBucketAllow returns true if the IP is allowed, false if rate limited.
// Each IP gets a token bucket of apiRateLimit tokens per apiRateWindow.
// Burst tokens (apiRateBurst) are available immediately, refill continuously.
func (d *Dashboard) apiBucketAllow(clientIP string) bool {
	val, _ := d.apiBuckets.LoadOrStore(clientIP, newAPIBucket())
	b := val.(*apiBucket)

	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens = math.Min(b.maxTokens, b.tokens+elapsed*b.refillRate)
	b.lastRefill = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// newAPIBucket creates a fresh token bucket for an IP.
func newAPIBucket() *apiBucket {
	refillRate := float64(apiRateLimit) / apiRateWindow.Seconds()
	return &apiBucket{
		tokens:     float64(apiRateBurst),
		maxTokens:  float64(apiRateBurst),
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

func (d *Dashboard) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if d.apiKey == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if _, ok := d.isAuthenticated(r); ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(loginPage(""))) // nolint:errcheck // login page write; error ignored after headers committed
}

func (d *Dashboard) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	// CSRF protection: verify Origin or Referer matches the request host
	if !verifySameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if d.apiKey == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Rate limit check
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	if !d.checkLoginRateLimit(clientIP) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(loginPage("Too many failed attempts. Please try again later.")))
		// nolint:errcheck // login page write; error ignored after headers committed
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxLoginRequestBody) // API keys are short
	if err := r.ParseForm(); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	key := r.PostForm.Get("key")
	if subtle.ConstantTimeCompare([]byte(key), []byte(d.apiKey)) != 1 {
		d.recordLoginFailure(clientIP)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(loginPage("Invalid API key. Please try again.")))
		// nolint:errcheck // login page write; error ignored after headers committed
		return
	}
	d.resetLoginAttempts(clientIP)
	setSessionCookie(w, r, d.trustedProxyNets)
	http.Redirect(w, r, "/", http.StatusFound)
}

// checkLoginRateLimit returns false if the IP is currently locked out.
func (d *Dashboard) checkLoginRateLimit(ip string) bool {
	val, ok := d.loginBuckets.Load(ip)
	if !ok {
		return true
	}
	b := val.(*loginBucket)
	b.mu.Lock()
	defer b.mu.Unlock()

	// If locked out, check if lockout has expired
	if b.locked {
		if time.Now().After(b.lockUntil) {
			b.locked = false
			b.attempts = 0
			return true
		}
		return false
	}

	// Reset attempts if outside the window
	if b.attempts > 0 && time.Since(b.lastFail) > loginWindow {
		b.attempts = 0
	}
	return true
}

// recordLoginFailure records a failed login attempt and locks out if threshold exceeded.
func (d *Dashboard) recordLoginFailure(ip string) {
	val, _ := d.loginBuckets.LoadOrStore(ip, &loginBucket{})
	b := val.(*loginBucket)
	b.mu.Lock()
	defer b.mu.Unlock()

	// Reset if outside window
	if b.attempts > 0 && time.Since(b.lastFail) > loginWindow {
		b.attempts = 0
	}

	b.attempts++
	b.lastFail = time.Now()

	if b.attempts >= loginMaxAttempts {
		b.locked = true
		b.lockUntil = time.Now().Add(loginLockout)
	}
}

// resetLoginAttempts clears the rate limit counter on successful login.
func (d *Dashboard) resetLoginAttempts(ip string) {
	d.loginBuckets.Delete(ip)
}

// cleanupLoginBuckets periodically removes expired login rate-limit entries
// to prevent unbounded memory growth from unique attacker IPs.
func (d *Dashboard) cleanupLoginBuckets() {
	defer d.cleanupWG.Done()
	defer func() {
		if r := recover(); r != nil {
			loginLog.Error("login bucket cleanup panic recovered",
				"panic", r,
				"stack", string(debug.Stack()))
		}
	}()
	ticker := time.NewTicker(loginLockout)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			d.loginBuckets.Range(func(key, value any) bool {
				b := value.(*loginBucket)
				b.mu.Lock()
				expired := b.locked && now.After(b.lockUntil) || (!b.locked && now.Sub(b.lastFail) > loginWindow)
				b.mu.Unlock()
				if expired {
					d.loginBuckets.Delete(key)
				}
				return true
			})
		case <-d.loginStopCh:
			return
		}
	}
}

// cleanupAPIBuckets removes stale API rate limit entries.
func (d *Dashboard) cleanupAPIBuckets() {
	defer d.cleanupWG.Done()
	defer func() {
		if r := recover(); r != nil {
			loginLog.Error("api bucket cleanup panic recovered",
				"panic", r,
				"stack", string(debug.Stack()))
		}
	}()
	ticker := time.NewTicker(apiRateCleanupTick)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			d.apiBuckets.Range(func(key, value any) bool {
				b := value.(*apiBucket)
				b.mu.Lock()
				// Bucket is stale if no tokens have been refilled for 2x the window
				stale := now.Sub(b.lastRefill) > apiRateWindow*2
				b.mu.Unlock()
				if stale {
					d.apiBuckets.Delete(key)
				}
				return true
			})
		case <-d.apiStopCh:
			return
		}
	}
}

// CloseWithContext signals background goroutines (login bucket cleanup,
// API rate limit cleanup, revoked-session cleanup) to stop and waits
// for them to drain. Returns ctx.Err() if the context fires before
// the goroutines exit. Safe to call multiple times — stop channel
// closes are idempotent under select/default.
func (d *Dashboard) CloseWithContext(ctx context.Context) error {
	select {
	case <-d.loginStopCh:
	default:
		close(d.loginStopCh)
	}
	select {
	case <-d.apiStopCh:
	default:
		close(d.apiStopCh)
	}
	done := make(chan struct{})
	go func() {
		d.cleanupWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close waits for background goroutines to stop with no timeout.
func (d *Dashboard) Close() {
	_ = d.CloseWithContext(context.Background())
}

func (d *Dashboard) handleLogout(w http.ResponseWriter, r *http.Request) {
	// CSRF protection: logout is a state-changing operation, so it must
	// be a non-GET request. Same-origin check rejects requests without
	// either Origin or Referer — browsers can strip these headers in
	// some scenarios, and a malicious page can submit requests without
	// them, making the absence a CSRF risk indicator.
	if r.Method == http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !verifySameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Revoke session server-side immediately
	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		RevokeSession(cookie.Value)
	}
	// #nosec G124 -- Secure is set dynamically: true for direct TLS or trusted-proxy, false for plain HTTP.
	// This is a deletion cookie (Value="", MaxAge=-1) — no sensitive data at stake regardless.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secureCookieForRequest(r, d.trustedProxyNets),
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}
