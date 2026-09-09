package dashboard

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/apivalidation"
)

// APIValidationHandler handles API validation management API endpoints.
type APIValidationHandler struct {
	dashboard *Dashboard
}

// NewAPIValidationHandler creates a new API validation handler.
func NewAPIValidationHandler(d *Dashboard) *APIValidationHandler {
	return &APIValidationHandler{dashboard: d}
}

// RegisterRoutes registers API validation routes with authentication.
func (h *APIValidationHandler) RegisterRoutes(mux *http.ServeMux) {
	auth := h.dashboard.authAuditWrap
	mux.HandleFunc("/api/apivalidation/schemas", auth(h.handleSchemas))
	mux.HandleFunc("/api/apivalidation/schemas/", auth(h.handleSchemaDetail))
	mux.HandleFunc("/api/apivalidation/config", auth(h.handleValidationConfig))
	mux.HandleFunc("/api/apivalidation/test", h.dashboard.authWrap(h.handleTestValidation))
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
			"name":           schema.Name,
			"version":        schema.Version,
			"format":         schema.Format,
			"endpoint_count": schema.EndpointCount,
			"strict_mode":    schema.StrictMode,
			"loaded_at":      schema.LoadedAt,
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
			ValidateRequest  *bool `json:"validate_request"`
			ValidateResponse *bool `json:"validate_response"`
			StrictMode       *bool `json:"strict_mode"`
			BlockOnViolation *bool `json:"block_on_violation"`
		}
		if !limitedDecodeJSON(w, r, &req) {
			return
		}

		// Get current config and update settings. Keep the pre-update copy
		// for the persistence rollback below.
		oldCfg := deepCopyConfig(h.dashboard.engine.Config())
		newCfg := deepCopyConfig(h.dashboard.engine.Config())
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

		// Persist the full config to disk — same contract as
		// handleUpdateConfig. Without this the settings are runtime-only: a
		// restart silently reverts block_on_violation and the other
		// API-validation flags to the last value written to the config file,
		// disabling blocking the operator believes is active.
		if h.dashboard.routingCtrl != nil {
			if err := h.dashboard.routingCtrl.Save(); err != nil {
				if rollbackErr := h.dashboard.engine.Reload(oldCfg); rollbackErr != nil {
					dashboardLog.Error("configuration persistence and rollback failed", "save_error", err, "rollback_error", rollbackErr)
				} else {
					dashboardLog.Error("configuration persistence failed; runtime rolled back", "error", err)
				}
				http.Error(w, "configuration persistence failed; previous runtime configuration restored", http.StatusInternalServerError)
				return
			}
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
		Method string `json:"method"`
		Path   string `json:"path"`
		Body   string `json:"body"`
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
	if h.dashboard.apiValidationOverride != nil {
		return h.dashboard.apiValidationOverride
	}
	if h.dashboard.apiValidationLayer == nil {
		// Try to get from engine via FindLayer
		if h.dashboard.engine != nil {
			if layer := h.dashboard.engine.FindLayer("apivalidation"); layer != nil {
				if l, ok := layer.(*apivalidation.Layer); ok {
					return &apiValidationAdapter{layer: l}
				}
			}
		}
		return nil
	}
	return &apiValidationAdapter{layer: h.dashboard.apiValidationLayer}
}

// apiValidationAdapter wraps apivalidation.Layer to satisfy APIValidationLayerInterface
type apiValidationAdapter struct {
	layer *apivalidation.Layer
}

func (a *apiValidationAdapter) IsEnabled() bool {
	return a.layer != nil
}

// schemaName resolves the operator-assigned identity: the name set at
// upload wins; legacy config-file-loaded specs fall back to their OpenAPI
// title.
func schemaName(spec *apivalidation.CompiledSpec) string {
	if spec.Source.Name != "" {
		return spec.Source.Name
	}
	return spec.Spec.Info.Title
}

// compiledSpecToInfo maps the layer's compiled spec to the dashboard's
// schema view. The compiled spec does not retain the raw document, so
// Content is empty: list/detail show metadata only.
func compiledSpecToInfo(spec *apivalidation.CompiledSpec) *APISchemaInfo {
	return &APISchemaInfo{
		Name:          schemaName(spec),
		Version:       spec.Spec.Info.Version,
		Format:        spec.Source.Type,
		EndpointCount: len(spec.Routes),
	}
}

func (a *apiValidationAdapter) GetSchemas() []*APISchemaInfo {
	if a.layer == nil {
		return nil
	}
	specs := a.layer.GetSpecs()
	schemas := make([]*APISchemaInfo, 0, len(specs))
	for _, spec := range specs {
		schemas = append(schemas, compiledSpecToInfo(spec))
	}
	return schemas
}

func (a *apiValidationAdapter) GetSchema(name string) *APISchemaInfo {
	if a.layer == nil {
		return nil
	}
	for _, spec := range a.layer.GetSpecs() {
		if schemaName(spec) == name {
			return compiledSpecToInfo(spec)
		}
	}
	return nil
}

func (a *apiValidationAdapter) LoadSchema(schema *APISchemaInfo) error {
	if a.layer == nil {
		return nil
	}

	format := strings.ToLower(schema.Format)
	if format == "" || format == "json" {
		format = "jsonschema"
	}

	tmpFile, err := os.CreateTemp(".", "guardianwaf-apivalidation-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(schema.Content); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	return a.layer.LoadSchema(apivalidation.SchemaSource{
		Type: format,
		Path: tmpFile.Name(),
		Name: schema.Name,
	})
}

func (a *apiValidationAdapter) RemoveSchema(name string) error {
	if a.layer == nil {
		return nil
	}
	// The layer reports found/not-found honestly; map the miss to an error
	// so the handler's DELETE returns 404 instead of a fake "removed" for
	// names that never existed.
	if !a.layer.RemoveSchema(name) {
		return errors.New("schema not found")
	}
	return nil
}

func (a *apiValidationAdapter) TestRequest(method, path, body string) APIValidationResult {
	if a.layer == nil {
		return APIValidationResult{Valid: true, Endpoint: path}
	}

	// Run the layer's real production validation pipeline — the same path
	// live traffic takes. The previous stub returned Valid:true
	// unconditionally, manufacturing pass results for the test endpoint: an
	// operator could believe their API contracts enforce when nothing was
	// ever validated.
	ctx := &engine.RequestContext{
		Method:      method,
		Path:        path,
		Body:        []byte(body),
		BodyString:  body,
		ContentType: "application/json",
	}
	result := a.layer.Process(ctx)

	valid := len(result.Findings) == 0 && result.Action != engine.ActionBlock
	violations := make([]string, 0, len(result.Findings))
	for _, f := range result.Findings {
		violations = append(violations, f.Description)
	}
	return APIValidationResult{
		Valid:      valid,
		Violations: violations,
		Endpoint:   path,
	}
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
