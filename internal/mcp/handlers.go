package mcp

import (
	"encoding/json"
	"fmt"
)

// RegisterAllTools registers all GuardianWAF MCP tool handlers on the server.
func (s *Server) RegisterAllTools() {
	s.registerBaseTools()
	s.RegisterNewFeatureHandlers()
}

// registerBaseTools registers the base set of MCP tools.
func (s *Server) registerBaseTools() {
	s.RegisterTool("guardianwaf_get_stats", s.handleGetStats)
	s.RegisterTool("guardianwaf_get_events", s.handleGetEvents)
	s.RegisterTool("guardianwaf_add_whitelist", s.handleAddWhitelist)
	s.RegisterTool("guardianwaf_remove_whitelist", s.handleRemoveWhitelist)
	s.RegisterTool("guardianwaf_add_blacklist", s.handleAddBlacklist)
	s.RegisterTool("guardianwaf_remove_blacklist", s.handleRemoveBlacklist)
	s.RegisterTool("guardianwaf_add_ratelimit", s.handleAddRateLimit)
	s.RegisterTool("guardianwaf_remove_ratelimit", s.handleRemoveRateLimit)
	s.RegisterTool("guardianwaf_add_exclusion", s.handleAddExclusion)
	s.RegisterTool("guardianwaf_remove_exclusion", s.handleRemoveExclusion)
	s.RegisterTool("guardianwaf_set_mode", s.handleSetMode)
	s.RegisterTool("guardianwaf_get_config", s.handleGetConfig)
	s.RegisterTool("guardianwaf_test_request", s.handleTestRequest)
	s.RegisterTool("guardianwaf_get_top_ips", s.handleGetTopIPs)
	s.RegisterTool("guardianwaf_get_detectors", s.handleGetDetectors)
	s.RegisterTool("guardianwaf_get_alerting_status", s.handleGetAlertingStatus)
	s.RegisterTool("guardianwaf_add_webhook", s.handleAddWebhook)
	s.RegisterTool("guardianwaf_remove_webhook", s.handleRemoveWebhook)
	s.RegisterTool("guardianwaf_add_email_target", s.handleAddEmailTarget)
	s.RegisterTool("guardianwaf_remove_email_target", s.handleRemoveEmailTarget)
	s.RegisterTool("guardianwaf_test_alert", s.handleTestAlert)
}

func (s *Server) getEngine() (EngineInterface, error) {
	s.mu.Lock()
	eng := s.engine
	s.mu.Unlock()
	if eng == nil {
		return nil, fmt.Errorf("engine not available")
	}
	return eng, nil
}

func (s *Server) handleGetStats(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	return eng.GetStats(), nil
}

func (s *Server) handleGetEvents(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	return eng.GetEvents(params)
}

type ipParam struct {
	IP string `json:"ip"`
}

func (s *Server) handleAddWhitelist(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p ipParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.IP == "" {
		return nil, fmt.Errorf("ip is required")
	}
	if err := eng.AddWhitelist(p.IP); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "ip": p.IP, "action": "added to whitelist"}, nil
}

func (s *Server) handleRemoveWhitelist(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p ipParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.IP == "" {
		return nil, fmt.Errorf("ip is required")
	}
	if err := eng.RemoveWhitelist(p.IP); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "ip": p.IP, "action": "removed from whitelist"}, nil
}

func (s *Server) handleAddBlacklist(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p ipParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.IP == "" {
		return nil, fmt.Errorf("ip is required")
	}
	if err := eng.AddBlacklist(p.IP); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "ip": p.IP, "action": "added to blacklist"}, nil
}

func (s *Server) handleRemoveBlacklist(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p ipParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.IP == "" {
		return nil, fmt.Errorf("ip is required")
	}
	if err := eng.RemoveBlacklist(p.IP); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "ip": p.IP, "action": "removed from blacklist"}, nil
}

type rateLimitParam struct {
	ID     string `json:"id"`
	Scope  string `json:"scope"`
	Limit  int    `json:"limit"`
	Window string `json:"window"`
	Action string `json:"action"`
}

func (s *Server) handleAddRateLimit(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p rateLimitParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.ID == "" {
		return nil, fmt.Errorf("id is required")
	}
	if p.Limit <= 0 {
		return nil, fmt.Errorf("limit must be > 0")
	}
	if p.Window == "" {
		return nil, fmt.Errorf("window is required")
	}
	if p.Scope == "" {
		p.Scope = "ip"
	}
	if p.Action == "" {
		p.Action = "block"
	}
	if err := eng.AddRateLimit(p); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "id": p.ID, "action": "rate limit rule added"}, nil
}

type removeRateLimitParam struct {
	ID string `json:"id"`
}

func (s *Server) handleRemoveRateLimit(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p removeRateLimitParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.ID == "" {
		return nil, fmt.Errorf("id is required")
	}
	if err := eng.RemoveRateLimit(p.ID); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "id": p.ID, "action": "rate limit rule removed"}, nil
}

type exclusionParam struct {
	Path      string   `json:"path"`
	Detectors []string `json:"detectors"`
	Reason    string   `json:"reason"`
}

func (s *Server) handleAddExclusion(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p exclusionParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	if len(p.Detectors) == 0 {
		return nil, fmt.Errorf("detectors is required")
	}
	if err := eng.AddExclusion(p.Path, p.Detectors, p.Reason); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "path": p.Path, "action": "exclusion added"}, nil
}

type removeExclusionParam struct {
	Path string `json:"path"`
}

func (s *Server) handleRemoveExclusion(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p removeExclusionParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	if err := eng.RemoveExclusion(p.Path); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "path": p.Path, "action": "exclusion removed"}, nil
}

type modeParam struct {
	Mode string `json:"mode"`
}

func (s *Server) handleSetMode(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p modeParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Mode == "" {
		return nil, fmt.Errorf("mode is required")
	}
	switch p.Mode {
	case "enforce", "monitor", "disabled":
		// valid
	default:
		return nil, fmt.Errorf("mode must be one of: enforce, monitor, disabled")
	}
	if err := eng.SetMode(p.Mode); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "mode": p.Mode}, nil
}

func (s *Server) handleGetConfig(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	return eng.GetConfig(), nil
}

type testRequestParam struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

func (s *Server) handleTestRequest(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p testRequestParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.URL == "" {
		return nil, fmt.Errorf("url is required")
	}
	if p.Method == "" {
		p.Method = "GET"
	}
	return eng.TestRequest(p.Method, p.URL, p.Headers)
}

type topIPsParam struct {
	Count int `json:"count"`
}

func (s *Server) handleGetTopIPs(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p topIPsParam
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
	}
	if p.Count <= 0 {
		p.Count = 10
	}
	return eng.GetTopIPs(p.Count), nil
}

func (s *Server) handleGetDetectors(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	return eng.GetDetectors(), nil
}

func (s *Server) handleGetAlertingStatus(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	return eng.GetAlertingStatus(), nil
}

type webhookParam struct {
	Name     string   `json:"name"`
	URL      string   `json:"url"`
	Type     string   `json:"type"`
	Events   []string `json:"events"`
	MinScore int      `json:"min_score"`
	Cooldown string   `json:"cooldown"`
}

func (s *Server) handleAddWebhook(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p webhookParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if p.URL == "" {
		return nil, fmt.Errorf("url is required")
	}
	if p.Type == "" {
		return nil, fmt.Errorf("type is required")
	}
	if err := eng.AddWebhook(p.Name, p.URL, p.Type, p.Events, p.MinScore, p.Cooldown); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "name": p.Name, "action": "webhook added"}, nil
}

type removeWebhookParam struct {
	Name string `json:"name"`
}

func (s *Server) handleRemoveWebhook(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p removeWebhookParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if err := eng.RemoveWebhook(p.Name); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "name": p.Name, "action": "webhook removed"}, nil
}

type emailTargetParam struct {
	Name     string   `json:"name"`
	SMTPHost string   `json:"smtp_host"`
	SMTPPort int      `json:"smtp_port"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	UseTLS   bool     `json:"use_tls"`
	Events   []string `json:"events"`
	MinScore int      `json:"min_score"`
}

func (s *Server) handleAddEmailTarget(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p emailTargetParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if p.SMTPHost == "" {
		return nil, fmt.Errorf("smtp_host is required")
	}
	if p.From == "" {
		return nil, fmt.Errorf("from is required")
	}
	if len(p.To) == 0 {
		return nil, fmt.Errorf("to is required")
	}
	if err := eng.AddEmailTarget(p.Name, p.SMTPHost, p.SMTPPort, p.Username, p.Password, p.From, p.To, p.UseTLS, p.Events, p.MinScore); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "name": p.Name, "action": "email target added"}, nil
}

type removeEmailTargetParam struct {
	Name string `json:"name"`
}

func (s *Server) handleRemoveEmailTarget(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p removeEmailTargetParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if err := eng.RemoveEmailTarget(p.Name); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "name": p.Name, "action": "email target removed"}, nil
}

type testAlertParam struct {
	Target string `json:"target"`
}

func (s *Server) handleTestAlert(params json.RawMessage) (any, error) {
	eng, err := s.getEngine()
	if err != nil {
		return nil, err
	}
	var p testAlertParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Target == "" {
		return nil, fmt.Errorf("target is required")
	}
	if err := eng.TestAlert(p.Target); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "target": p.Target, "action": "test alert sent"}, nil
}
