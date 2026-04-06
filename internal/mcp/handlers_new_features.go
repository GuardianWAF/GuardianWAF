package mcp

import (
	"encoding/json"
	"fmt"
)

// RegisterNewFeatureHandlers registers handlers for the 6 new feature tools.
func (s *Server) RegisterNewFeatureHandlers() {
	// CRS Tools
	s.RegisterTool("guardianwaf_get_crs_rules", s.handleGetCRSRules)
	s.RegisterTool("guardianwaf_enable_crs_rule", s.handleEnableCRSRule)
	s.RegisterTool("guardianwaf_set_paranoia_level", s.handleSetParanoiaLevel)
	s.RegisterTool("guardianwaf_add_crs_exclusion", s.handleAddCRSExclusion)

	// Virtual Patch Tools
	s.RegisterTool("guardianwaf_get_virtual_patches", s.handleGetVirtualPatches)
	s.RegisterTool("guardianwaf_enable_virtual_patch", s.handleEnableVirtualPatch)
	s.RegisterTool("guardianwaf_add_custom_patch", s.handleAddCustomPatch)
	s.RegisterTool("guardianwaf_update_cve_database", s.handleUpdateCVEDatabase)

	// API Validation Tools
	s.RegisterTool("guardianwaf_get_api_schemas", s.handleGetAPISchemas)
	s.RegisterTool("guardianwaf_upload_api_schema", s.handleUploadAPISchema)
	s.RegisterTool("guardianwaf_remove_api_schema", s.handleRemoveAPISchema)
	s.RegisterTool("guardianwaf_set_api_validation_mode", s.handleSetAPIValidationMode)
	s.RegisterTool("guardianwaf_test_api_schema", s.handleTestAPISchema)

	// Client-Side Protection Tools
	s.RegisterTool("guardianwaf_get_clientside_stats", s.handleGetClientSideStats)
	s.RegisterTool("guardianwaf_set_clientside_mode", s.handleSetClientSideMode)
	s.RegisterTool("guardianwaf_add_skimming_domain", s.handleAddSkimmingDomain)
	s.RegisterTool("guardianwaf_get_csp_report", s.handleGetCSPReports)

	// Advanced DLP Tools
	s.RegisterTool("guardianwaf_get_dlp_alerts", s.handleGetDLPAlerts)
	s.RegisterTool("guardianwaf_add_dlp_pattern", s.handleAddDLPPattern)
	s.RegisterTool("guardianwaf_remove_dlp_pattern", s.handleRemoveDLPPattern)
	s.RegisterTool("guardianwaf_test_dlp_pattern", s.handleTestDLPPattern)

	// HTTP/3 Tools
	s.RegisterTool("guardianwaf_get_http3_status", s.handleGetHTTP3Status)
	s.RegisterTool("guardianwaf_set_http3_config", s.handleSetHTTP3Config)
}

// --- CRS Handlers ---

type crsRulesParam struct {
	Phase    int    `json:"phase"`
	Severity string `json:"severity"`
}

func (s *Server) handleGetCRSRules(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p crsRulesParam
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
	}
	return eng.GetCRSRules(p.Phase, p.Severity)
}

type enableCRSRuleParam struct {
	RuleID  string `json:"rule_id"`
	Enabled bool   `json:"enabled"`
}

func (s *Server) handleEnableCRSRule(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p enableCRSRuleParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.RuleID == "" {
		return nil, fmt.Errorf("rule_id is required")
	}
	if err := eng.EnableCRSRule(p.RuleID, p.Enabled); err != nil {
		return nil, err
	}
	status := "disabled"
	if p.Enabled {
		status = "enabled"
	}
	return map[string]any{"status": "ok", "rule_id": p.RuleID, "action": status}, nil
}

type paranoiaLevelParam struct {
	Level int `json:"level"`
}

func (s *Server) handleSetParanoiaLevel(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p paranoiaLevelParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Level < 1 || p.Level > 4 {
		return nil, fmt.Errorf("level must be between 1 and 4")
	}
	if err := eng.SetParanoiaLevel(p.Level); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "paranoia_level": p.Level}, nil
}

type crsExclusionParam struct {
	RuleID    string `json:"rule_id"`
	Path      string `json:"path"`
	Parameter string `json:"parameter"`
	Reason    string `json:"reason"`
}

func (s *Server) handleAddCRSExclusion(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p crsExclusionParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.RuleID == "" {
		return nil, fmt.Errorf("rule_id is required")
	}
	if err := eng.AddCRSExclusion(p.RuleID, p.Path, p.Parameter, p.Reason); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "rule_id": p.RuleID, "action": "exclusion added"}, nil
}

// --- Virtual Patch Handlers ---

type virtualPatchesParam struct {
	Severity   string `json:"severity"`
	ActiveOnly bool   `json:"active_only"`
}

func (s *Server) handleGetVirtualPatches(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p virtualPatchesParam
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
	}
	return eng.GetVirtualPatches(p.Severity, p.ActiveOnly)
}

type enableVirtualPatchParam struct {
	PatchID string `json:"patch_id"`
	Enabled bool   `json:"enabled"`
}

func (s *Server) handleEnableVirtualPatch(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p enableVirtualPatchParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.PatchID == "" {
		return nil, fmt.Errorf("patch_id is required")
	}
	if err := eng.EnableVirtualPatch(p.PatchID, p.Enabled); err != nil {
		return nil, err
	}
	status := "disabled"
	if p.Enabled {
		status = "enabled"
	}
	return map[string]any{"status": "ok", "patch_id": p.PatchID, "action": status}, nil
}

type customPatchParam struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	CVEID        string `json:"cve_id"`
	Pattern      string `json:"pattern"`
	PatternType  string `json:"pattern_type"`
	Target       string `json:"target"`
	Action       string `json:"action"`
	Severity     string `json:"severity"`
	Score        int    `json:"score"`
}

func (s *Server) handleAddCustomPatch(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p customPatchParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.ID == "" {
		return nil, fmt.Errorf("id is required")
	}
	if p.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if p.Pattern == "" {
		return nil, fmt.Errorf("pattern is required")
	}
	if p.PatternType == "" {
		return nil, fmt.Errorf("pattern_type is required")
	}
	if p.Target == "" {
		return nil, fmt.Errorf("target is required")
	}
	if p.Action == "" {
		return nil, fmt.Errorf("action is required")
	}
	if err := eng.AddCustomPatch(p.ID, p.Name, p.Description, p.CVEID, p.Pattern, p.PatternType, p.Target, p.Action, p.Severity, p.Score); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "patch_id": p.ID, "action": "custom patch added"}, nil
}

func (s *Server) handleUpdateCVEDatabase(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	if err := eng.UpdateCVEDatabase(); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "action": "CVE database update triggered"}, nil
}

// --- API Validation Handlers ---

func (s *Server) handleGetAPISchemas(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	return eng.GetAPISchemas()
}

type uploadAPISchemaParam struct {
	Name       string `json:"name"`
	Content    string `json:"content"`
	Format     string `json:"format"`
	StrictMode bool   `json:"strict_mode"`
}

func (s *Server) handleUploadAPISchema(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p uploadAPISchemaParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if p.Content == "" {
		return nil, fmt.Errorf("content is required")
	}
	if p.Format == "" {
		p.Format = "json"
	}
	if err := eng.UploadAPISchema(p.Name, p.Content, p.Format, p.StrictMode); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "schema": p.Name, "action": "schema uploaded"}, nil
}

type removeAPISchemaParam struct {
	Name string `json:"name"`
}

func (s *Server) handleRemoveAPISchema(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p removeAPISchemaParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if err := eng.RemoveAPISchema(p.Name); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "schema": p.Name, "action": "schema removed"}, nil
}

type apiValidationModeParam struct {
	ValidateRequest   *bool `json:"validate_request"`
	ValidateResponse  *bool `json:"validate_response"`
	StrictMode        *bool `json:"strict_mode"`
	BlockOnViolation  *bool `json:"block_on_violation"`
}

func (s *Server) handleSetAPIValidationMode(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p apiValidationModeParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := eng.SetAPIValidationMode(p.ValidateRequest, p.ValidateResponse, p.StrictMode, p.BlockOnViolation); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "action": "API validation mode updated"}, nil
}

type testAPISchemaParam struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   string `json:"body"`
}

func (s *Server) handleTestAPISchema(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p testAPISchemaParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Method == "" {
		return nil, fmt.Errorf("method is required")
	}
	if p.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	return eng.TestAPISchema(p.Method, p.Path, p.Body)
}

// --- Client-Side Protection Handlers ---

func (s *Server) handleGetClientSideStats(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	return eng.GetClientSideStats()
}

type clientSideModeParam struct {
	Mode              string `json:"mode"`
	MagecartDetection *bool  `json:"magecart_detection"`
	AgentInjection    *bool  `json:"agent_injection"`
	CSPEnabled        *bool  `json:"csp_enabled"`
}

func (s *Server) handleSetClientSideMode(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p clientSideModeParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Mode == "" {
		return nil, fmt.Errorf("mode is required")
	}
	if err := eng.SetClientSideMode(p.Mode, p.MagecartDetection, p.AgentInjection, p.CSPEnabled); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "mode": p.Mode, "action": "client-side mode updated"}, nil
}

type skimmingDomainParam struct {
	Domain string `json:"domain"`
}

func (s *Server) handleAddSkimmingDomain(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p skimmingDomainParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if err := eng.AddSkimmingDomain(p.Domain); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "domain": p.Domain, "action": "skimming domain added"}, nil
}

type cspReportParam struct {
	Limit int `json:"limit"`
}

func (s *Server) handleGetCSPReports(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p cspReportParam
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
	}
	if p.Limit <= 0 {
		p.Limit = 100
	}
	return eng.GetCSPReports(p.Limit)
}

// --- DLP Handlers ---

type dlpAlertsParam struct {
	Limit       int    `json:"limit"`
	PatternType string `json:"pattern_type"`
}

func (s *Server) handleGetDLPAlerts(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p dlpAlertsParam
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
	}
	if p.Limit <= 0 {
		p.Limit = 50
	}
	return eng.GetDLPAlerts(p.Limit, p.PatternType)
}

type dlpPatternParam struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Action      string `json:"action"`
	Score       int    `json:"score"`
}

func (s *Server) handleAddDLPPattern(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p dlpPatternParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.ID == "" {
		return nil, fmt.Errorf("id is required")
	}
	if p.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if p.Pattern == "" {
		return nil, fmt.Errorf("pattern is required")
	}
	if p.Action == "" {
		return nil, fmt.Errorf("action is required")
	}
	if err := eng.AddDLPPattern(p.ID, p.Name, p.Pattern, p.Description, p.Action, p.Score); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "pattern_id": p.ID, "action": "DLP pattern added"}, nil
}

type removeDLPPatternParam struct {
	ID string `json:"id"`
}

func (s *Server) handleRemoveDLPPattern(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p removeDLPPatternParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.ID == "" {
		return nil, fmt.Errorf("id is required")
	}
	if err := eng.RemoveDLPPattern(p.ID); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "pattern_id": p.ID, "action": "DLP pattern removed"}, nil
}

type testDLPPatternParam struct {
	Pattern  string `json:"pattern"`
	TestData string `json:"test_data"`
}

func (s *Server) handleTestDLPPattern(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p testDLPPatternParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Pattern == "" {
		return nil, fmt.Errorf("pattern is required")
	}
	if p.TestData == "" {
		return nil, fmt.Errorf("test_data is required")
	}
	return eng.TestDLPPattern(p.Pattern, p.TestData)
}

// --- HTTP/3 Handlers ---

func (s *Server) handleGetHTTP3Status(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	return eng.GetHTTP3Status()
}

type http3ConfigParam struct {
	Enabled         *bool `json:"enabled"`
	Enable0RTT      *bool `json:"enable_0rtt"`
	AdvertiseAltSvc *bool `json:"advertise_alt_svc"`
}

func (s *Server) handleSetHTTP3Config(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p http3ConfigParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := eng.SetHTTP3Config(p.Enabled, p.Enable0RTT, p.AdvertiseAltSvc); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "action": "HTTP/3 config updated"}, nil
}
