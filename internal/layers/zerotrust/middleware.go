package zerotrust

import (
	"context"
	"fmt"
	"net/http"
)

// Middleware provides HTTP middleware for Zero Trust authentication.
type Middleware struct {
	service *Service
}

// NewMiddleware creates a new Zero Trust middleware.
func NewMiddleware(service *Service) *Middleware {
	return &Middleware{
		service: service,
	}
}

// Handler wraps an http.Handler with Zero Trust authentication.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if Zero Trust is enabled
		if m.service == nil || !m.service.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Check bypass paths
		for _, bypassPath := range m.service.config.AllowBypassPaths {
			if r.URL.Path == bypassPath {
				next.ServeHTTP(w, r)
				return
			}
		}

		// Try to get existing session
		sessionID := r.Header.Get("X-ZeroTrust-Session")
		if sessionID != "" {
			identity := m.service.GetClientIdentity(sessionID)
			if identity != nil {
				// Check access
				if err := m.service.CheckAccess(identity, r.URL.Path); err != nil {
					http.Error(w, "Access denied: "+err.Error(), http.StatusForbidden)
					return
				}

				// Add identity to context
				ctx := WithClientIdentity(r.Context(), identity)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// Check for client certificate (mTLS)
		if m.service.config.RequireMTLS {
			identity, err := m.authenticateWithCertificate(r)
			if err != nil {
				http.Error(w, "Authentication required: "+err.Error(), http.StatusUnauthorized)
				return
			}

			// Check access
			if err := m.service.CheckAccess(identity, r.URL.Path); err != nil {
				http.Error(w, "Access denied: "+err.Error(), http.StatusForbidden)
				return
			}

			// Return session ID in response header
			w.Header().Set("X-ZeroTrust-Session", identity.SessionID)

			// Add identity to context
			ctx := WithClientIdentity(r.Context(), identity)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// No authentication required or available
		next.ServeHTTP(w, r)
	})
}

// authenticateWithCertificate authenticates using client certificate.
func (m *Middleware) authenticateWithCertificate(r *http.Request) (*ClientIdentity, error) {
	// Check TLS connection state
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificate provided")
	}

	// Use the first certificate
	cert := r.TLS.PeerCertificates[0]

	// Verify certificate
	identity, err := m.service.VerifyClientCertificate(cert)
	if err != nil {
		return nil, err
	}

	return identity, nil
}

// contextKey is the key type for Zero Trust context values.
type contextKey string

const (
	// clientIdentityKey is the context key for client identity.
	clientIdentityKey contextKey = "zerotrust_client_identity"
)

// WithClientIdentity adds a client identity to the context.
func WithClientIdentity(ctx context.Context, identity *ClientIdentity) context.Context {
	return context.WithValue(ctx, clientIdentityKey, identity)
}

// GetClientIdentityFromContext retrieves the client identity from context.
func GetClientIdentityFromContext(ctx context.Context) *ClientIdentity {
	if identity, ok := ctx.Value(clientIdentityKey).(*ClientIdentity); ok {
		return identity
	}
	return nil
}

// GetSessionIDFromContext retrieves the session ID from context.
func GetSessionIDFromContext(ctx context.Context) string {
	identity := GetClientIdentityFromContext(ctx)
	if identity != nil {
		return identity.SessionID
	}
	return ""
}

// IsAuthenticated checks if the request has been authenticated.
func IsAuthenticated(ctx context.Context) bool {
	return GetClientIdentityFromContext(ctx) != nil
}

// GetTrustLevelFromContext retrieves the trust level from context.
func GetTrustLevelFromContext(ctx context.Context) TrustLevel {
	identity := GetClientIdentityFromContext(ctx)
	if identity != nil {
		return identity.TrustLevel
	}
	return TrustLevelNone
}

// RequireAuthentication middleware ensures the request is authenticated.
func RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsAuthenticated(r.Context()) {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireTrustLevel middleware ensures the request has at least the specified trust level.
func RequireTrustLevel(minLevel TrustLevel) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			level := GetTrustLevelFromContext(r.Context())
			if level < minLevel {
				http.Error(w, "Insufficient trust level", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
