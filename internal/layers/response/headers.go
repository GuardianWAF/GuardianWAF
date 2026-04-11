package response

import (
	"net/http"
	"strings"
)

// SecurityHeaders defines the security headers to inject into responses.
type SecurityHeaders struct {
	HSTS                  string // e.g., "max-age=31536000; includeSubDomains"
	XContentTypeOptions   string // e.g., "nosniff"
	XFrameOptions         string // e.g., "SAMEORIGIN"
	ReferrerPolicy        string // e.g., "strict-origin-when-cross-origin"
	PermissionsPolicy     string // e.g., "camera=(), microphone=()"
	ContentSecurityPolicy string // e.g., "default-src 'self'"
	XXSSProtection        string // e.g., "1; mode=block"
	CacheControl          string // e.g., "no-store"
}

// DefaultSecurityHeaders returns a recommended set of security headers.
func DefaultSecurityHeaders() SecurityHeaders {
	return SecurityHeaders{
		HSTS:                  "max-age=31536000; includeSubDomains",
		XContentTypeOptions:   "nosniff",
		XFrameOptions:         "SAMEORIGIN",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		PermissionsPolicy:     "camera=(), microphone=(), geolocation=()",
		ContentSecurityPolicy: "default-src 'self'",
		XXSSProtection:        "0",
		CacheControl:          "",
	}
}

// Apply adds security headers to the response writer.
// Only non-empty header values are set. Values containing CR or LF are
// rejected to prevent header injection (defense-in-depth).
func (sh *SecurityHeaders) Apply(w http.ResponseWriter) {
	if sh.HSTS != "" {
		setSafeHeader(w, "Strict-Transport-Security", sh.HSTS)
	}
	if sh.XContentTypeOptions != "" {
		setSafeHeader(w, "X-Content-Type-Options", sh.XContentTypeOptions)
	}
	if sh.XFrameOptions != "" {
		setSafeHeader(w, "X-Frame-Options", sh.XFrameOptions)
	}
	if sh.ReferrerPolicy != "" {
		setSafeHeader(w, "Referrer-Policy", sh.ReferrerPolicy)
	}
	if sh.PermissionsPolicy != "" {
		setSafeHeader(w, "Permissions-Policy", sh.PermissionsPolicy)
	}
	if sh.ContentSecurityPolicy != "" {
		setSafeHeader(w, "Content-Security-Policy", sh.ContentSecurityPolicy)
	}
	if sh.XXSSProtection != "" {
		setSafeHeader(w, "X-XSS-Protection", sh.XXSSProtection)
	}
	if sh.CacheControl != "" {
		setSafeHeader(w, "Cache-Control", sh.CacheControl)
	}
}

// setSafeHeader sets a header only if the value contains no CR/LF characters.
func setSafeHeader(w http.ResponseWriter, key, value string) {
	if strings.ContainsAny(value, "\r\n") {
		return
	}
	w.Header().Set(key, value)
}
