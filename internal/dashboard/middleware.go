package dashboard

import (
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// --- Auth middleware ---

// getClientIP extracts the client IP from the request, never using X-Forwarded-For.
func (d *Dashboard) getClientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// adminAuthWrap requires the system admin API key. It is used for
// cross-tenant provisioning operations (tenant create/update/delete, config
// changes, API-key regeneration) so they cannot be performed with the ordinary
// dashboard key — preserving the admin/dashboard key separation regardless of
// which route (/api/admin/* or the /api/v1/* compat routes) reaches them.
func (d *Dashboard) adminAuthWrap(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !d.isAdminAuthenticated(r) {
			writeError(w, http.StatusUnauthorized, "admin API key required")
			return
		}
		setRequestAuditIdentity(r, "admin_key", "admin")
		handler(w, r)
	}
}

// adminAuthAuditWrap records both accepted and denied administrator mutations.
func (d *Dashboard) adminAuthAuditWrap(handler http.HandlerFunc) http.HandlerFunc {
	return d.auditWrap(d.adminAuthWrap(handler))
}

// authWrap wraps a handler with authentication and authorization checks.
// It authenticates via session cookie or X-API-Key header, enforces tenant
// API key scoping (fail-closed allowlist), and applies CSRF protection for
// cookie-authenticated state-changing requests. Authenticated /api/v1/
// requests are subject to per-IP rate limiting.
func (d *Dashboard) authWrap(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r, ok := d.isAuthenticated(r)
		if !ok {
			// API requests get 401 JSON, browser requests get redirected to login
			if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/mcp") {
				writeError(w, http.StatusUnauthorized, "unauthorized")
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}
		setRequestAuditIdentity(r, getAuthType(r), auditPrincipal(r))

		// Check API rate limit for /api/v1/* endpoints (authenticated only)
		if strings.HasPrefix(r.URL.Path, "/api/v1/") && getAuthType(r) != authSession {
			if !d.apiBucketAllow(d.getClientIP(r)) {
				writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
		}

		// Enforce tenant API key scoping (fail-closed): a tenant-scoped key may
		// only reach explicitly allow-listed read-only API endpoints. Any other
		// /api/ path — including admin endpoints and any newly added route — is
		// denied by default.
		if getAuthType(r) == authTenant && strings.HasPrefix(r.URL.Path, "/api/") {
			if !tenantKeyAllows(r.URL.Path) {
				writeError(w, http.StatusForbidden, "tenant-scoped API key cannot access this endpoint")
				return
			}
		}

		// Refresh only the session credential that actually authenticated this
		// request. Header-authenticated callers must never mint browser sessions.
		if getAuthType(r) == authSession {
			if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
				refreshSessionCookie(w, r, d.trustedProxyNets, cookie.Value)
			}
		}

		// CSRF protection for state-changing requests authenticated via cookie
		// (API key header auth is inherently CSRF-safe since browsers can't set custom headers cross-origin)
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if r.Header.Get("X-API-Key") == "" && !verifySameOrigin(r) {
				writeError(w, http.StatusForbidden, "CSRF validation failed")
				return
			}
		}

		handler(w, r)
	}
}

func auditPrincipal(r *http.Request) string {
	if getAuthType(r) == authTenant {
		if tenantID, ok := r.Context().Value(authTenantCtxKey{}).(string); ok && tenantID != "" {
			return tenantID
		}
	}
	return "admin"
}

func setRequestAuditIdentity(r *http.Request, authType, principal string) {
	if identity, ok := r.Context().Value(auditIdentityCtxKey{}).(*auditIdentity); ok {
		identity.authType = authType
		identity.principal = principal
	}
}

// authAuditWrap records both accepted and denied authenticated mutations.
func (d *Dashboard) authAuditWrap(handler http.HandlerFunc) http.HandlerFunc {
	return d.auditWrap(d.authWrap(handler))
}

// pprofWrap restricts pprof endpoints to localhost connections and requires
// pprofKey (or adminKey when pprofKey is not set) for authentication.
func (d *Dashboard) pprofWrap(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Use RemoteAddr directly - never trust X-Forwarded-For for pprof access.
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "connection error", http.StatusBadRequest)
			return
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			http.Error(w, "pprof endpoints are localhost-only", http.StatusForbidden)
			return
		}
		// Require pprofKey when set; when adminKey is set and pprofKey is not,
		// accept adminKey as a fallback (admin has debug access). If neither
		// key is configured, keep pprof disabled even for localhost.
		if d.pprofKey != "" {
			_, authorized := d.checkPprofKey(r)
			if !authorized {
				http.Error(w, "pprof access denied", http.StatusForbidden)
				return
			}
		} else if d.adminKey != "" {
			if key := r.Header.Get("X-API-Key"); key == "" || subtle.ConstantTimeCompare([]byte(key), []byte(d.adminKey)) != 1 {
				http.Error(w, "pprof access denied", http.StatusForbidden)
				return
			}
		} else {
			http.Error(w, "pprof access denied", http.StatusForbidden)
			return
		}
		handler.ServeHTTP(w, r)
	}
}

// verifySameOrigin checks that a state-changing request (POST, PUT, DELETE)
// originates from the same host by verifying the Origin or Referer header.
// Returns true if the origin matches the request Host.
// Requests without Origin or Referer are rejected — while CSRF is a browser-only
// attack vector, browsers can strip these headers in certain scenarios, and
// malicious pages can submit requests without them, making the absence itself
// a risk indicator for cookie-authenticated endpoints.
func verifySameOrigin(r *http.Request) bool {
	// Check Origin header first (most reliable)
	origin := r.Header.Get("Origin")
	if origin != "" {
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return u.Host == r.Host
	}

	// Fall back to Referer header
	referer := r.Header.Get("Referer")
	if referer != "" {
		u, err := url.Parse(referer)
		if err != nil {
			return false
		}
		return u.Host == r.Host
	}

	// No Origin or Referer — reject to prevent CSRF via stripped headers
	return false
}

// CORSMiddleware sets CORS headers on all responses so that browsers can read
// the response body even when the server returns 4xx/5xx. For OPTIONS requests
// it answers the preflight directly with 204 No Content. The dashboard is
// same-origin; cross-origin requests still require Access-Control-Allow-Origin
// to be set by callers that need true cross-origin support.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers on every response so error responses are readable by browsers.
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
