package tenant

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// ContextKey is the key type for tenant context values.
type ContextKey string

const (
	// TenantContextKey is the context key for tenant information.
	TenantContextKey ContextKey = "gwaf_tenant"
)

// Middleware provides HTTP middleware for tenant resolution and isolation.
type Middleware struct {
	manager *Manager
}

// NewMiddleware creates a new tenant middleware.
func NewMiddleware(manager *Manager) *Middleware {
	return &Middleware{
		manager: manager,
	}
}

// Handler wraps an http.Handler with tenant resolution.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Resolve tenant
		tenant := m.manager.ResolveTenant(r)
		if tenant == nil {
			http.Error(w, "No tenant configured", http.StatusServiceUnavailable)
			return
		}

		// Check if tenant is active
		if !tenant.Active {
			http.Error(w, "Tenant is not active", http.StatusForbidden)
			return
		}

		// Check quota
		if err := m.manager.CheckQuota(tenant); err != nil {
			http.Error(w, err.Error(), http.StatusTooManyRequests)
			return
		}

		// Add tenant to context
		ctx := WithTenant(r.Context(), tenant)

		// Also add engine tenant context for WAF (breaks import cycle by using interface)
		tenantCtx := &engine.TenantContext{
			ID:            tenant.ID,
			WAFConfig:     &tenant.Config.WAF,
			VirtualHosts:  tenant.Config.VirtualHosts,
		}
		ctx = engine.WithTenantContext(ctx, tenantCtx)

		// Wrap response writer to capture stats
		wrapped := &tenantResponseWriter{
			ResponseWriter: w,
			tenant:         tenant,
			manager:        m.manager,
			wroteHeader:    false,
		}

		// Call next handler
		next.ServeHTTP(wrapped, r.WithContext(ctx))
	})
}

// tenantResponseWriter wraps http.ResponseWriter to track tenant stats.
type tenantResponseWriter struct {
	http.ResponseWriter
	tenant      *Tenant
	manager     *Manager
	wroteHeader bool
	bytesWritten int64
}

// Write captures bytes written for quota tracking.
func (w *tenantResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += int64(n)
	return n, err
}

// WriteHeader captures response status.
func (w *tenantResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(statusCode)

	// Record blocked requests
	if statusCode >= 400 {
		w.manager.RecordBlocked(w.tenant)
	}
}

// Flush implements http.Flusher.
func (w *tenantResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker.
func (w *tenantResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijacking not supported")
}

// GetTenant extracts the tenant from the context.
func GetTenant(ctx context.Context) *Tenant {
	if tenant, ok := ctx.Value(TenantContextKey).(*Tenant); ok {
		return tenant
	}
	return nil
}

// WithTenant adds a tenant to the context.
func WithTenant(ctx context.Context, tenant *Tenant) context.Context {
	return context.WithValue(ctx, TenantContextKey, tenant)
}

// GetTenantConfig extracts the tenant's config from the context.
func GetTenantConfig(ctx context.Context) *config.Config {
	tenant := GetTenant(ctx)
	if tenant != nil {
		return tenant.Config
	}
	return nil
}

// IsTenantRequest checks if the request has a valid tenant.
func IsTenantRequest(r *http.Request) bool {
	return GetTenant(r.Context()) != nil
}

// GetTenantID extracts the tenant ID from the context.
func GetTenantID(ctx context.Context) string {
	tenant := GetTenant(ctx)
	if tenant != nil {
		return tenant.ID
	}
	return ""
}

// RequireTenant middleware ensures a valid tenant is present.
func (m *Middleware) RequireTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := GetTenant(r.Context())
		if tenant == nil {
			http.Error(w, "Tenant required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin middleware ensures the request is from the admin tenant.
func (m *Middleware) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := GetTenant(r.Context())
		if tenant == nil {
			http.Error(w, "Tenant required", http.StatusUnauthorized)
			return
		}

		// Check if this is the default/admin tenant
		if m.manager.defaultTenantID != "" && tenant.ID != m.manager.defaultTenantID {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// TenantAwareRouter routes requests based on tenant.
type TenantAwareRouter struct {
	mu             sync.RWMutex
	manager        *Manager
	routes         map[string]http.Handler // key: tenant ID
	defaultHandler http.Handler
}

// NewTenantAwareRouter creates a new tenant-aware router.
func NewTenantAwareRouter(manager *Manager) *TenantAwareRouter {
	return &TenantAwareRouter{
		manager: manager,
		routes:  make(map[string]http.Handler),
	}
}

// Register registers a handler for a tenant.
func (r *TenantAwareRouter) Register(tenantID string, handler http.Handler) {
	r.mu.Lock()
	r.routes[tenantID] = handler
	r.mu.Unlock()
}

// SetDefault sets the default handler for unmatched tenants.
func (r *TenantAwareRouter) SetDefault(handler http.Handler) {
	r.mu.Lock()
	r.defaultHandler = handler
	r.mu.Unlock()
}

// ServeHTTP implements http.Handler.
func (r *TenantAwareRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	tenant := GetTenant(req.Context())
	if tenant == nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	// Find handler for tenant
	r.mu.RLock()
	handler, exists := r.routes[tenant.ID]
	if !exists {
		handler = r.defaultHandler
	}
	r.mu.RUnlock()

	if handler == nil {
		http.Error(w, "No handler for tenant", http.StatusNotFound)
		return
	}

	handler.ServeHTTP(w, req)
}

// TenantHeaderExtractor extracts tenant from custom headers.
type TenantHeaderExtractor struct {
	manager     *Manager
	headerName  string
}

// NewTenantHeaderExtractor creates a header-based extractor.
func NewTenantHeaderExtractor(manager *Manager, headerName string) *TenantHeaderExtractor {
	if headerName == "" {
		headerName = "X-GuardianWAF-Tenant"
	}
	return &TenantHeaderExtractor{
		manager:    manager,
		headerName: headerName,
	}
}

// Extract extracts tenant from request headers.
func (e *TenantHeaderExtractor) Extract(r *http.Request) *Tenant {
	// Try tenant ID header
	tenantID := r.Header.Get(e.headerName)
	if tenantID != "" {
		return e.manager.GetTenant(tenantID)
	}

	// Try API key header
	apiKey := r.Header.Get("X-GuardianWAF-Tenant-Key")
	if apiKey != "" {
		return e.manager.GetTenantByAPIKey(apiKey)
	}

	return nil
}

// PathPrefixRouter routes based on URL path prefix.
// e.g., /tenant/abc123/api -> routes to tenant abc123
type PathPrefixRouter struct {
	manager *Manager
	prefix  string
}

// NewPathPrefixRouter creates a path prefix router.
func NewPathPrefixRouter(manager *Manager, prefix string) *PathPrefixRouter {
	if prefix == "" {
		prefix = "/tenant/"
	}
	return &PathPrefixRouter{
		manager: manager,
		prefix:  prefix,
	}
}

// ExtractTenantID extracts tenant ID from path.
func (r *PathPrefixRouter) ExtractTenantID(path string) string {
	if !strings.HasPrefix(path, r.prefix) {
		return ""
	}

	// Remove prefix
	remaining := path[len(r.prefix):]

	// Get first segment
	if idx := strings.Index(remaining, "/"); idx > 0 {
		return remaining[:idx]
	}
	return remaining
}

// StripPrefix strips the tenant prefix from the path.
func (r *PathPrefixRouter) StripPrefix(path string) string {
	if !strings.HasPrefix(path, r.prefix) {
		return path
	}

	remaining := path[len(r.prefix):]
	if idx := strings.Index(remaining, "/"); idx >= 0 {
		return remaining[idx:]
	}
	return "/"
}
