package response

import (
	"net/http"
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
// Only non-empty header values are set.
func (sh *SecurityHeaders) Apply(w http.ResponseWriter) {
	if sh.HSTS != "" {
		w.Header().Set("Strict-Transport-Security", sh.HSTS)
	}
	if sh.XContentTypeOptions != "" {
		w.Header().Set("X-Content-Type-Options", sh.XContentTypeOptions)
	}
	if sh.XFrameOptions != "" {
		w.Header().Set("X-Frame-Options", sh.XFrameOptions)
	}
	if sh.ReferrerPolicy != "" {
		w.Header().Set("Referrer-Policy", sh.ReferrerPolicy)
	}
	if sh.PermissionsPolicy != "" {
		w.Header().Set("Permissions-Policy", sh.PermissionsPolicy)
	}
	if sh.ContentSecurityPolicy != "" {
		w.Header().Set("Content-Security-Policy", sh.ContentSecurityPolicy)
	}
	if sh.XXSSProtection != "" {
		w.Header().Set("X-XSS-Protection", sh.XXSSProtection)
	}
	if sh.CacheControl != "" {
		w.Header().Set("Cache-Control", sh.CacheControl)
	}
}
