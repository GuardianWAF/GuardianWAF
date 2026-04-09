package dashboard

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"
)

// RecoveryMiddleware wraps an HTTP handler with panic recovery
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rv := recover(); rv != nil {
				// Log the panic with stack trace
				log.Printf("[PANIC RECOVERED] %v\n%s", rv, debug.Stack())

				// Return 500 error - safe to do for non-SSE endpoints
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, `{"error": "Internal Server Error", "message": "An unexpected error occurred"}`)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware logs all HTTP requests
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response wrapper to capture status code
		wrapper := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapper, r)

		duration := time.Since(start)

		// Log request details
		log.Printf("[%s] %s %s - %d (%s)",
			r.Method,
			r.URL.Path,
			r.RemoteAddr,
			wrapper.statusCode,
			duration,
		)
	})
}

// SecurityHeadersMiddleware adds security headers to all responses
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip security headers for SSE endpoint
		if strings.Contains(r.URL.Path, "/sse") {
			next.ServeHTTP(w, r)
			return
		}

		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		next.ServeHTTP(w, r)
	})
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

// CORSMiddleware handles CORS preflight requests.
// The dashboard is same-origin only — CORS headers are only set on OPTIONS
// preflight responses to satisfy browsers that send them on same-origin
// requests with custom headers (e.g., X-API-Key).
// No Access-Control-Allow-Origin is set, so cross-origin requests are rejected.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// ApplyMiddleware chains all middleware to a handler
func ApplyMiddleware(handler http.Handler, middleware ...func(http.Handler) http.Handler) http.Handler {
	// Apply in reverse order so first middleware is outermost
	for i := len(middleware) - 1; i >= 0; i-- {
		handler = middleware[i](handler)
	}
	return handler
}
