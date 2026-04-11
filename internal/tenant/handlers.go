package tenant

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// Handlers provides HTTP handlers for tenant management.
type Handlers struct {
	manager *Manager
	apiKey  string
}

// NewHandlers creates new tenant management handlers.
func NewHandlers(manager *Manager) *Handlers {
	return &Handlers{manager: manager}
}

// SetAPIKey sets the API key for authenticating requests.
func (h *Handlers) SetAPIKey(key string) {
	h.apiKey = key
}

// verifyKey checks the request has a valid API key.
func (h *Handlers) verifyKey(r *http.Request) bool {
	if h.apiKey == "" {
		// This should never happen — API key must be set before registering routes.
		log.Printf("[ERROR] Tenant API key is not configured — refusing request. Set APIKey before starting the tenant handler.")
		return false
	}
	key := r.Header.Get("X-API-Key")
	if key == "" {
		key = r.Header.Get("X-Admin-Key")
	}
	return subtle.ConstantTimeCompare([]byte(key), []byte(h.apiKey)) == 1
}

// RegisterRoutes registers tenant management routes.
func (h *Handlers) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/tenants", h.handleTenants)
	mux.HandleFunc("/api/v1/tenants/", h.handleTenantRoutes) // handles both {id} and {id}/waf-config
}

// handleTenants handles list and create operations.
func (h *Handlers) handleTenants(w http.ResponseWriter, r *http.Request) {
	if !h.verifyKey(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.listTenants(w, r)
	case http.MethodPost:
		h.createTenant(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTenantRoutes dispatches /api/v1/tenants/{id} and /api/v1/tenants/{id}/waf-config.
func (h *Handlers) handleTenantRoutes(w http.ResponseWriter, r *http.Request) {
	if !h.verifyKey(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	// Extract tenant ID from path /api/v1/tenants/{id} or /api/v1/tenants/{id}/waf-config
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/tenants/")
	if path == "" {
		http.Error(w, "Tenant ID required", http.StatusBadRequest)
		return
	}

	tenantID := strings.Split(path, "/")[0]
		// Validate tenant ID — only allow alphanumeric, dash, underscore
		for _, c := range tenantID {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				http.Error(w, "Invalid tenant ID", http.StatusBadRequest)
				return
			}
		}

	// Check if this is a WAF config sub-path
	if strings.HasSuffix(path, "/waf-config") {
		h.handleWAFConfigRoutes(w, r, tenantID)
		return
	}

	// Regular tenant CRUD
	switch r.Method {
	case http.MethodGet:
		h.getTenant(w, r, tenantID)
	case http.MethodPut:
		h.updateTenant(w, r, tenantID)
	case http.MethodDelete:
		h.deleteTenant(w, r, tenantID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleWAFConfigRoutes handles GET/PUT for tenant WAF config.
func (h *Handlers) handleWAFConfigRoutes(w http.ResponseWriter, r *http.Request, tenantID string) {
	switch r.Method {
	case http.MethodGet:
		h.getTenantWAFConfig(w, r, tenantID)
	case http.MethodPut:
		h.updateTenantWAFConfig(w, r, tenantID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}


// CreateTenantRequest represents a create tenant request.
type CreateTenantRequest struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Domains     []string      `json:"domains"`
	Quota       *ResourceQuota `json:"quota,omitempty"`
}

// CreateTenantResponse represents the response when creating a tenant.
type CreateTenantResponse struct {
	Tenant any    `json:"tenant"`
	APIKey string `json:"api_key"`
}

// PublicTenant is a sanitized tenant view for API responses — excludes sensitive fields.
type PublicTenant struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Active      bool           `json:"active"`
	Domains     []string       `json:"domains"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	Quota       *ResourceQuota `json:"quota,omitempty"`
	WAFConfig   *config.Config `json:"waf_config,omitempty"`
}

func sanitizeTenant(t *Tenant) PublicTenant {
	return PublicTenant{
		ID:          t.ID,
		Name:        t.Name,
		Description: t.Description,
		Active:      t.Active,
		Domains:     t.Domains,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
		Quota:       &t.Quota,
		WAFConfig:   t.Config,
	}
}

func (h *Handlers) createTenant(w http.ResponseWriter, r *http.Request) {
	var req CreateTenantRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	if len(req.Domains) == 0 {
		http.Error(w, "At least one domain is required", http.StatusBadRequest)
		return
	}

	tenant, err := h.manager.CreateTenant(req.Name, req.Description, req.Domains, req.Quota)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	// Regenerate API key to return to user
	apiKey, _ := h.manager.RegenerateAPIKey(tenant.ID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(CreateTenantResponse{
		Tenant: sanitizeTenant(tenant),
		APIKey: apiKey,
	}); err != nil {
		// Client disconnected, nothing we can do
		_ = err
	}
}

func (h *Handlers) listTenants(w http.ResponseWriter, r *http.Request) {
	tenants := h.manager.ListTenants()

	public := make([]PublicTenant, 0, len(tenants))
	for _, t := range tenants {
		public = append(public, sanitizeTenant(t))
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"tenants": public,
		"count":   len(public),
	}); err != nil {
		// Client disconnected
		_ = err
	}
}

func (h *Handlers) getTenant(w http.ResponseWriter, r *http.Request, tenantID string) {
	tenant := h.manager.GetTenant(tenantID)
	if tenant == nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sanitizeTenant(tenant)); err != nil {
		// Client disconnected
		_ = err
	}
}

// UpdateTenantRequest represents an update tenant request.
type UpdateTenantRequest struct {
	Name        string           `json:"name,omitempty"`
	Description string           `json:"description,omitempty"`
	Active      *bool            `json:"active,omitempty"`
	Domains     []string         `json:"domains,omitempty"`
	Quota       *ResourceQuota   `json:"quota,omitempty"`
	Config      *config.Config   `json:"config,omitempty"` // Full tenant config (including WAF)
}

func (h *Handlers) updateTenant(w http.ResponseWriter, r *http.Request, tenantID string) {
	var req UpdateTenantRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	update := &TenantUpdate{
		Name:        req.Name,
		Description: req.Description,
		Active:      req.Active,
		Domains:     req.Domains,
		Quota:       req.Quota,
		Config:      req.Config,
	}

	if err := h.manager.UpdateTenant(tenantID, update); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	tenant := h.manager.GetTenant(tenantID)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tenant); err != nil {
		// Client disconnected
		_ = err
	}
}

func (h *Handlers) deleteTenant(w http.ResponseWriter, r *http.Request, tenantID string) {
	if err := h.manager.DeleteTenant(tenantID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}


// getTenantWAFConfig returns the WAF config for a tenant.
func (h *Handlers) getTenantWAFConfig(w http.ResponseWriter, r *http.Request, tenantID string) {
	tenant := h.manager.GetTenant(tenantID)
	if tenant == nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	cfg := tenant.Config
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	if err := json.NewEncoder(w).Encode(cfg); err != nil {
		// Client disconnected
		_ = err
	}
}

// updateTenantWAFConfig updates only the WAF config for a tenant (partial update).
func (h *Handlers) updateTenantWAFConfig(w http.ResponseWriter, r *http.Request, tenantID string) {
	var wafCfg config.WAFConfig
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&wafCfg); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	tenant := h.manager.GetTenant(tenantID)
	if tenant == nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	// Merge with existing config - only update WAF section
	// Copy to avoid mutating shared state between GetTenant and UpdateTenant
	updatedConfig := tenant.Config
	if updatedConfig == nil {
		updatedConfig = config.DefaultConfig()
	} else {
		cfg := *updatedConfig
		updatedConfig = &cfg
	}
	updatedConfig.WAF = wafCfg

	update := &TenantUpdate{
		Config: updatedConfig,
	}

	if err := h.manager.UpdateTenant(tenantID, update); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tenant = h.manager.GetTenant(tenantID)
	if tenant == nil {
		http.Error(w, "Tenant not found after update", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tenant); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

// RegenerateAPIKeyHandler regenerates API key for a tenant.
func (h *Handlers) RegenerateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract tenant ID from path /api/v1/tenants/{id}/regenerate-key
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/tenants/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "regenerate-key" {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	tenantID := parts[0]

	apiKey, err := h.manager.RegenerateAPIKey(tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"api_key": apiKey,
	}); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

// StatsHandler returns tenant statistics.
func (h *Handlers) StatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.manager.Stats()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

// UsageStats represents real-time usage statistics for a tenant.
type UsageStats struct {
	TenantID             string    `json:"tenant_id"`
	Name                 string    `json:"name"`
	Active               bool      `json:"active"`
	RequestsPerMinute    int64     `json:"requests_per_minute"`
	RequestsPerHour      int64     `json:"requests_per_hour"`
	TotalRequests        int64     `json:"total_requests"`
	BlockedRequests      int64     `json:"blocked_requests"`
	BytesTransferred     int64     `json:"bytes_transferred"`
	BandwidthMbps        float64   `json:"bandwidth_mbps"`
	LastRequestAt        time.Time `json:"last_request_at"`
	QuotaStatus          string    `json:"quota_status"`
	QuotaPercentage      float64   `json:"quota_percentage"`
}

// GetTenantUsage returns real-time usage for a specific tenant.
func (h *Handlers) GetTenantUsage(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.manager.GetTenant(tenantID)
	if tenant == nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	// Get current rate limiter count
	var requestsPerMinute int64
	if h.manager.rateLimiter != nil {
		requestsPerMinute = h.manager.rateLimiter.Count(tenantID)
	}

	tenant.mu.RLock()
	stats := UsageStats{
		TenantID:          tenantID,
		RequestsPerMinute: requestsPerMinute,
		TotalRequests:     tenant.RequestCount,
		BlockedRequests:   tenant.BlockedCount,
		BytesTransferred:  tenant.ByteCount,
		LastRequestAt:     tenant.LastRequestAt,
	}

	// Calculate bandwidth (simplified)
	if !tenant.LastRequestAt.IsZero() {
		duration := time.Since(tenant.CreatedAt).Seconds()
		if duration > 0 {
			stats.BandwidthMbps = float64(tenant.ByteCount*8) / duration / 1000000
		}
	}

	// Calculate quota status
	if tenant.Quota.MaxRequestsPerMinute > 0 {
		stats.QuotaPercentage = float64(requestsPerMinute) / float64(tenant.Quota.MaxRequestsPerMinute) * 100
		if requestsPerMinute >= tenant.Quota.MaxRequestsPerMinute {
			stats.QuotaStatus = "exceeded"
		} else if requestsPerMinute >= tenant.Quota.MaxRequestsPerMinute*80/100 {
			stats.QuotaStatus = "warning"
		} else {
			stats.QuotaStatus = "ok"
		}
	} else {
		stats.QuotaStatus = "unlimited"
	}
	tenant.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

// GetAllUsage returns usage for all tenants.
func (h *Handlers) GetAllUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenants := h.manager.ListTenants()
	usageStats := make([]UsageStats, 0, len(tenants))

	for _, tenant := range tenants {
		var requestsPerMinute int64
		if h.manager.rateLimiter != nil {
			requestsPerMinute = h.manager.rateLimiter.Count(tenant.ID)
		}

		tenant.mu.RLock()
		stats := UsageStats{
			TenantID:          tenant.ID,
			Name:              tenant.Name,
			RequestsPerMinute: requestsPerMinute,
			TotalRequests:     tenant.RequestCount,
			BlockedRequests:   tenant.BlockedCount,
			BytesTransferred:  tenant.ByteCount,
			LastRequestAt:     tenant.LastRequestAt,
			Active:            tenant.Active,
		}

		if tenant.Quota.MaxRequestsPerMinute > 0 {
			stats.QuotaPercentage = float64(requestsPerMinute) / float64(tenant.Quota.MaxRequestsPerMinute) * 100
			if requestsPerMinute >= tenant.Quota.MaxRequestsPerMinute {
				stats.QuotaStatus = "exceeded"
			} else if requestsPerMinute >= tenant.Quota.MaxRequestsPerMinute*80/100 {
				stats.QuotaStatus = "warning"
			} else {
				stats.QuotaStatus = "ok"
			}
		} else {
			stats.QuotaStatus = "unlimited"
		}
		tenant.mu.RUnlock()

		usageStats = append(usageStats, stats)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"tenants": usageStats,
		"count":   len(usageStats),
	}); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}
