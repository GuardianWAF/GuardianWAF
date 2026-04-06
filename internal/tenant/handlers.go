package tenant

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Handlers provides HTTP handlers for tenant management.
type Handlers struct {
	manager *Manager
}

// NewHandlers creates new tenant management handlers.
func NewHandlers(manager *Manager) *Handlers {
	return &Handlers{manager: manager}
}

// RegisterRoutes registers tenant management routes.
func (h *Handlers) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/tenants", h.handleTenants)
	mux.HandleFunc("/api/v1/tenants/", h.handleTenantDetail)
	mux.HandleFunc("/api/v1/tenants/", h.handleTenantDetail)
}

// handleTenants handles list and create operations.
func (h *Handlers) handleTenants(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listTenants(w, r)
	case http.MethodPost:
		h.createTenant(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTenantDetail handles get, update, delete operations.
func (h *Handlers) handleTenantDetail(w http.ResponseWriter, r *http.Request) {
	// Extract tenant ID from path /api/v1/tenants/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/tenants/")
	if path == "" {
		http.Error(w, "Tenant ID required", http.StatusBadRequest)
		return
	}

	tenantID := strings.Split(path, "/")[0]

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

// CreateTenantRequest represents a create tenant request.
type CreateTenantRequest struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Domains     []string      `json:"domains"`
	Quota       *ResourceQuota `json:"quota,omitempty"`
}

// CreateTenantResponse represents a create tenant response.
type CreateTenantResponse struct {
	Tenant *Tenant `json:"tenant"`
	APIKey string  `json:"api_key"`
}

func (h *Handlers) createTenant(w http.ResponseWriter, r *http.Request) {
	var req CreateTenantRequest
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
	json.NewEncoder(w).Encode(CreateTenantResponse{
		Tenant: tenant,
		APIKey: apiKey,
	})
}

func (h *Handlers) listTenants(w http.ResponseWriter, r *http.Request) {
	tenants := h.manager.ListTenants()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"tenants": tenants,
		"count":   len(tenants),
	})
}

func (h *Handlers) getTenant(w http.ResponseWriter, r *http.Request, tenantID string) {
	tenant := h.manager.GetTenant(tenantID)
	if tenant == nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tenant)
}

// UpdateTenantRequest represents an update tenant request.
type UpdateTenantRequest struct {
	Name        string        `json:"name,omitempty"`
	Description string        `json:"description,omitempty"`
	Active      *bool         `json:"active,omitempty"`
	Domains     []string      `json:"domains,omitempty"`
	Quota       *ResourceQuota `json:"quota,omitempty"`
}

func (h *Handlers) updateTenant(w http.ResponseWriter, r *http.Request, tenantID string) {
	var req UpdateTenantRequest
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
	}

	if err := h.manager.UpdateTenant(tenantID, update); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	tenant := h.manager.GetTenant(tenantID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tenant)
}

func (h *Handlers) deleteTenant(w http.ResponseWriter, r *http.Request, tenantID string) {
	if err := h.manager.DeleteTenant(tenantID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
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
	json.NewEncoder(w).Encode(map[string]string{
		"api_key": apiKey,
	})
}

// StatsHandler returns tenant statistics.
func (h *Handlers) StatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.manager.Stats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
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
	json.NewEncoder(w).Encode(stats)
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
	json.NewEncoder(w).Encode(map[string]any{
		"tenants": usageStats,
		"count":   len(usageStats),
	})
}
