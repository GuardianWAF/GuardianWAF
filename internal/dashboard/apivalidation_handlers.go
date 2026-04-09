package dashboard

import (
	"net/http"
)

// APIValidationHandler handles API validation management API endpoints.
type APIValidationHandler struct {
	dashboard *Dashboard
}

// NewAPIValidationHandler creates a new API validation handler.
func NewAPIValidationHandler(d *Dashboard) *APIValidationHandler {
	return &APIValidationHandler{dashboard: d}
}

// RegisterRoutes registers API validation routes.
func (h *APIValidationHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/apivalidation/schemas", h.handleSchemas)
	mux.HandleFunc("/api/apivalidation/schemas/", h.handleSchemaDetail)
	mux.HandleFunc("/api/apivalidation/config", h.handleValidationConfig)
	mux.HandleFunc("/api/apivalidation/test", h.handleTestValidation)
}

// handleSchemas handles GET/POST /api/apivalidation/schemas
func (h *APIValidationHandler) handleSchemas(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleListSchemas(w, r)
	case http.MethodPost:
		h.handleUploadSchema(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *APIValidationHandler) handleListSchemas(w http.ResponseWriter, r *http.Request) {
	apiLayer := h.getAPIValidationLayer()
	if apiLayer == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"schemas": []any{},
		})
		return
	}

	schemas := apiLayer.GetSchemas()
	var result []map[string]any

	for _, schema := range schemas {
		result = append(result, map[string]any{
			"name":              schema.Name,
			"version":           schema.Version,
			"format":            schema.Format,
			"endpoint_count":    schema.EndpointCount,
			"strict_mode":       schema.StrictMode,
			"loaded_at":         schema.LoadedAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": apiLayer.IsEnabled(),
		"schemas": result,
		"total":   len(schemas),
	})
}

func (h *APIValidationHandler) handleUploadSchema(w http.ResponseWriter, r *http.Request) {
	apiLayer := h.getAPIValidationLayer()
	if apiLayer == nil {
		http.Error(w, "API validation layer not enabled", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Name       string `json:"name"`
		Content    string `json:"content"`
		Format     string `json:"format"`
		StrictMode bool   `json:"strict_mode"`
	}
	if !limitedDecodeJSON(w, r, &req) {
		return
	}

	if req.Name == "" || req.Content == "" {
		http.Error(w, "name and content are required", http.StatusBadRequest)
		return
	}

	if req.Format == "" {
		req.Format = "json"
	}

	schema := &APISchemaInfo{
		Name:       req.Name,
		Content:    req.Content,
		Format:     req.Format,
		StrictMode: req.StrictMode,
	}

	if err := apiLayer.LoadSchema(schema); err != nil {
		http.Error(w, sanitizeErr(err), http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"name":   req.Name,
		"status": "loaded",
		"format": req.Format,
	})
}

// handleSchemaDetail handles GET/DELETE /api/apivalidation/schemas/{name}
func (h *APIValidationHandler) handleSchemaDetail(w http.ResponseWriter, r *http.Request) {
	// Extract schema name from path
	path := r.URL.Path[len("/api/apivalidation/schemas/"):]
	if path == "" {
		http.Error(w, "Schema name required", http.StatusBadRequest)
		return
	}

	apiLayer := h.getAPIValidationLayer()
	if apiLayer == nil {
		http.Error(w, "API validation layer not enabled", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		schema := apiLayer.GetSchema(path)
		if schema == nil {
			http.Error(w, "Schema not found", http.StatusNotFound)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"name":           schema.Name,
			"version":        schema.Version,
			"format":         schema.Format,
			"endpoint_count": schema.EndpointCount,
			"strict_mode":    schema.StrictMode,
			"loaded_at":      schema.LoadedAt,
		})

	case http.MethodDelete:
		if err := apiLayer.RemoveSchema(path); err != nil {
			http.Error(w, sanitizeErr(err), http.StatusNotFound)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"name":   path,
			"status": "removed",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleValidationConfig handles GET/PUT /api/apivalidation/config
func (h *APIValidationHandler) handleValidationConfig(w http.ResponseWriter, r *http.Request) {
	apiLayer := h.getAPIValidationLayer()
	if apiLayer == nil {
		http.Error(w, "API validation layer not enabled", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		cfg := h.dashboard.engine.Config()
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":            cfg.WAF.APIValidation.Enabled,
			"validate_request":   cfg.WAF.APIValidation.ValidateRequest,
			"validate_response":  cfg.WAF.APIValidation.ValidateResponse,
			"strict_mode":        cfg.WAF.APIValidation.StrictMode,
			"block_on_violation": cfg.WAF.APIValidation.BlockOnViolation,
		})

	case http.MethodPut:
		var req struct {
			ValidateRequest   *bool `json:"validate_request"`
			ValidateResponse  *bool `json:"validate_response"`
			StrictMode        *bool `json:"strict_mode"`
			BlockOnViolation  *bool `json:"block_on_violation"`
		}
		if !limitedDecodeJSON(w, r, &req) {
			return
		}

		// Get current config and update settings
		newCfg := h.dashboard.engine.Config()
		if req.ValidateRequest != nil {
			newCfg.WAF.APIValidation.ValidateRequest = *req.ValidateRequest
		}
		if req.ValidateResponse != nil {
			newCfg.WAF.APIValidation.ValidateResponse = *req.ValidateResponse
		}
		if req.StrictMode != nil {
			newCfg.WAF.APIValidation.StrictMode = *req.StrictMode
		}
		if req.BlockOnViolation != nil {
			newCfg.WAF.APIValidation.BlockOnViolation = *req.BlockOnViolation
		}

		// Reload config
		if err := h.dashboard.engine.Reload(newCfg); err != nil {
			http.Error(w, sanitizeErr(err), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"status":             "updated",
			"validate_request":   newCfg.WAF.APIValidation.ValidateRequest,
			"validate_response":  newCfg.WAF.APIValidation.ValidateResponse,
			"strict_mode":        newCfg.WAF.APIValidation.StrictMode,
			"block_on_violation": newCfg.WAF.APIValidation.BlockOnViolation,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTestValidation handles POST /api/apivalidation/test
func (h *APIValidationHandler) handleTestValidation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	apiLayer := h.getAPIValidationLayer()
	if apiLayer == nil {
		http.Error(w, "API validation layer not enabled", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Method string          `json:"method"`
		Path   string          `json:"path"`
		Body   string          `json:"body"`
	}
	if !limitedDecodeJSON(w, r, &req) {
		return
	}

	if req.Method == "" || req.Path == "" {
		http.Error(w, "method and path are required", http.StatusBadRequest)
		return
	}

	// Test validation
	result := apiLayer.TestRequest(req.Method, req.Path, req.Body)

	writeJSON(w, http.StatusOK, map[string]any{
		"valid":      result.Valid,
		"violations": result.Violations,
		"endpoint":   result.Endpoint,
	})
}

// getAPIValidationLayer returns the API validation layer from the engine if available
func (h *APIValidationHandler) getAPIValidationLayer() APIValidationLayerInterface {
	// This is a simplified version - in production, you'd get this from the engine
	return nil
}

// APIValidationLayerInterface defines the interface for API validation layer operations
type APIValidationLayerInterface interface {
	IsEnabled() bool
	GetSchemas() []*APISchemaInfo
	GetSchema(name string) *APISchemaInfo
	LoadSchema(schema *APISchemaInfo) error
	RemoveSchema(name string) error
	TestRequest(method, path, body string) APIValidationResult
}

// APISchemaInfo represents API schema information
type APISchemaInfo struct {
	Name          string
	Version       string
	Format        string
	Content       string
	EndpointCount int
	StrictMode    bool
	LoadedAt      int64
}

// APIValidationResult represents API validation test result
type APIValidationResult struct {
	Valid      bool     `json:"valid"`
	Violations []string `json:"violations"`
	Endpoint   string   `json:"endpoint"`
}
