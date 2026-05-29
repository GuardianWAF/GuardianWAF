package mcp

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
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

// handleWithParams is a generic adapter that unmarshals typed params, validates
// required fields, and calls the given engine method. It eliminates the repetitive
// getEngine → json.Unmarshal → error-check → call pattern across all 44 handlers.
func handleWithParams[T any, R any](
	s *Server,
	params json.RawMessage,
	required []string, // field names that must be non-zero
	call func(EngineInterface, T) (R, error),
) (R, error) {
	var zero R
	eng, err := s.getEngine()
	if err != nil {
		return zero, err
	}
	var p T
	if err := json.Unmarshal(params, &p); err != nil {
		return zero, fmt.Errorf("invalid params: %w", err)
	}
	v := reflect.ValueOf(p)
	for _, field := range required {
		f := v.FieldByName(field)
		if !f.IsValid() {
			continue
		}
		zeroVal := reflect.Zero(f.Type())
		if reflect.DeepEqual(f.Interface(), zeroVal.Interface()) {
			return zero, fmt.Errorf("%s is required", field)
		}
	}
	return call(eng, p)
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
	return handleWithParams[ipParam](s, params, []string{"IP"}, func(eng EngineInterface, p ipParam) (any, error) {
		if err := eng.AddWhitelist(p.IP); err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "ip": p.IP, "action": "added to whitelist"}, nil
	})
}

func (s *Server) handleRemoveWhitelist(params json.RawMessage) (any, error) {
	return handleWithParams[ipParam](s, params, []string{"IP"}, func(eng EngineInterface, p ipParam) (any, error) {
		if err := eng.RemoveWhitelist(p.IP); err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "ip": p.IP, "action": "removed from whitelist"}, nil
	})
}

func (s *Server) handleAddBlacklist(params json.RawMessage) (any, error) {
	return handleWithParams[ipParam](s, params, []string{"IP"}, func(eng EngineInterface, p ipParam) (any, error) {
		if err := eng.AddBlacklist(p.IP); err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "ip": p.IP, "action": "added to blacklist"}, nil
	})
}

func (s *Server) handleRemoveBlacklist(params json.RawMessage) (any, error) {
	return handleWithParams[ipParam](s, params, []string{"IP"}, func(eng EngineInterface, p ipParam) (any, error) {
		if err := eng.RemoveBlacklist(p.IP); err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "ip": p.IP, "action": "removed from blacklist"}, nil
	})
}

type rateLimitParam struct {
	ID     string `json:"id"`
	Scope  string `json:"scope"`
	Limit  int    `json:"limit"`
	Window string `json:"window"`
	Action string `json:"action"`
}

func (s *Server) handleAddRateLimit(params json.RawMessage) (any, error) {
	return handleWithParams[rateLimitParam](s, params, []string{"ID", "Limit", "Window"}, func(eng EngineInterface, p rateLimitParam) (any, error) {
		if p.Limit <= 0 {
			return nil, fmt.Errorf("limit must be > 0")
		}
		if p.Window == "" {
			p.Window = "60s" // default
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
	})
}

type removeRateLimitParam struct {
	ID string `json:"id"`
}

func (s *Server) handleRemoveRateLimit(params json.RawMessage) (any, error) {
	return handleWithParams[removeRateLimitParam](s, params, []string{"ID"}, func(eng EngineInterface, p removeRateLimitParam) (any, error) {
		if err := eng.RemoveRateLimit(p.ID); err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "id": p.ID, "action": "rate limit rule removed"}, nil
	})
}

type exclusionParam struct {
	Path      string   `json:"path"`
	Detectors []string `json:"detectors"`
	Reason    string   `json:"reason"`
}

func (s *Server) handleAddExclusion(params json.RawMessage) (any, error) {
	return handleWithParams[exclusionParam](s, params, []string{"Path"}, func(eng EngineInterface, p exclusionParam) (any, error) {
		if len(p.Detectors) == 0 {
			return nil, fmt.Errorf("detectors is required")
		}
		if err := eng.AddExclusion(p.Path, p.Detectors, p.Reason); err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "path": p.Path, "action": "exclusion added"}, nil
	})
}

type removeExclusionParam struct {
	Path string `json:"path"`
}

func (s *Server) handleRemoveExclusion(params json.RawMessage) (any, error) {
	return handleWithParams[removeExclusionParam](s, params, []string{"Path"}, func(eng EngineInterface, p removeExclusionParam) (any, error) {
		if err := eng.RemoveExclusion(p.Path); err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "path": p.Path, "action": "exclusion removed"}, nil
	})
}

type modeParam struct {
	Mode string `json:"mode"`
}

func (s *Server) handleSetMode(params json.RawMessage) (any, error) {
	return handleWithParams[modeParam](s, params, []string{"Mode"}, func(eng EngineInterface, p modeParam) (any, error) {
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
	})
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
	return handleWithParams[testRequestParam](s, params, []string{"URL"}, func(eng EngineInterface, p testRequestParam) (any, error) {
		if p.Method == "" {
			p.Method = "GET"
		}
		return eng.TestRequest(p.Method, p.URL, p.Headers)
	})
}

type topIPsParam struct {
	Count int `json:"count"`
}

func (s *Server) handleGetTopIPs(params json.RawMessage) (any, error) {
	return handleWithParams[topIPsParam](s, params, nil, func(eng EngineInterface, p topIPsParam) (any, error) {
		if p.Count <= 0 {
			p.Count = 10
		}
		return eng.GetTopIPs(p.Count), nil
	})
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
	return handleWithParams[webhookParam](s, params, []string{"Name", "URL", "Type"}, func(eng EngineInterface, p webhookParam) (any, error) {
		// Validate URL scheme to prevent SSRF via gopher://, file://, etc.
		if !strings.HasPrefix(p.URL, "https://") && !strings.HasPrefix(p.URL, "http://") {
			return nil, fmt.Errorf("url must use http:// or https:// scheme")
		}
		if err := eng.AddWebhook(p.Name, p.URL, p.Type, p.Events, p.MinScore, p.Cooldown); err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "name": p.Name, "action": "webhook added"}, nil
	})
}

type removeWebhookParam struct {
	Name string `json:"name"`
}

func (s *Server) handleRemoveWebhook(params json.RawMessage) (any, error) {
	return handleWithParams[removeWebhookParam](s, params, []string{"Name"}, func(eng EngineInterface, p removeWebhookParam) (any, error) {
		if err := eng.RemoveWebhook(p.Name); err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "name": p.Name, "action": "webhook removed"}, nil
	})
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
	return handleWithParams[emailTargetParam](s, params, []string{"Name", "SMTPHost", "From"}, func(eng EngineInterface, p emailTargetParam) (any, error) {
		if len(p.To) == 0 {
			return nil, fmt.Errorf("to is required")
		}
		if err := eng.AddEmailTarget(p.Name, p.SMTPHost, p.SMTPPort, p.Username, p.Password, p.From, p.To, p.UseTLS, p.Events, p.MinScore); err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "name": p.Name, "action": "email target added"}, nil
	})
}

type removeEmailTargetParam struct {
	Name string `json:"name"`
}

func (s *Server) handleRemoveEmailTarget(params json.RawMessage) (any, error) {
	return handleWithParams[removeEmailTargetParam](s, params, []string{"Name"}, func(eng EngineInterface, p removeEmailTargetParam) (any, error) {
		if err := eng.RemoveEmailTarget(p.Name); err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "name": p.Name, "action": "email target removed"}, nil
	})
}

type testAlertParam struct {
	Target string `json:"target"`
}

func (s *Server) handleTestAlert(params json.RawMessage) (any, error) {
	return handleWithParams[testAlertParam](s, params, []string{"Target"}, func(eng EngineInterface, p testAlertParam) (any, error) {
		if err := eng.TestAlert(p.Target); err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "target": p.Target, "action": "test alert sent"}, nil
	})
}
