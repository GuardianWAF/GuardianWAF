package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/alerting"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection"
	"github.com/guardianwaf/guardianwaf/internal/layers/ipacl"
	"github.com/guardianwaf/guardianwaf/internal/layers/ratelimit"
)

// mcpEngineAdapter adapts the engine.Engine to the mcp.EngineInterface.
type mcpEngineAdapter struct {
	engine     *engine.Engine
	cfg        *config.Config
	eventStore events.EventStore
	alertMgr   *alerting.Manager
}

func (a *mcpEngineAdapter) GetStats() any {
	s := a.engine.Stats()
	return map[string]any{
		"total_requests":   s.TotalRequests,
		"blocked_requests": s.BlockedRequests,
		"logged_requests":  s.LoggedRequests,
		"passed_requests":  s.PassedRequests,
		"avg_latency_us":   s.AvgLatencyUs,
	}
}

func (a *mcpEngineAdapter) GetConfig() any {
	cfg := a.engine.Config()
	return map[string]any{
		"mode":   cfg.Mode,
		"listen": cfg.Listen,
		"waf": map[string]any{
			"ip_acl_enabled":     cfg.WAF.IPACL.Enabled,
			"rate_limit_enabled": cfg.WAF.RateLimit.Enabled,
			"sanitizer_enabled":  cfg.WAF.Sanitizer.Enabled,
			"detection_enabled":  cfg.WAF.Detection.Enabled,
			"bot_detect_enabled": cfg.WAF.BotDetection.Enabled,
			"threshold_block":    cfg.WAF.Detection.Threshold.Block,
			"threshold_log":      cfg.WAF.Detection.Threshold.Log,
		},
		"dashboard": map[string]any{
			"enabled": cfg.Dashboard.Enabled,
			"listen":  cfg.Dashboard.Listen,
		},
		"mcp": map[string]any{
			"enabled":   cfg.MCP.Enabled,
			"transport": cfg.MCP.Transport,
		},
	}
}

func (a *mcpEngineAdapter) GetMode() string {
	return a.engine.Config().Mode
}

func (a *mcpEngineAdapter) SetMode(mode string) error {
	cfg := a.engine.Config()
	cfg.Mode = mode
	return a.engine.Reload(cfg)
}

func (a *mcpEngineAdapter) AddWhitelist(ip string) error {
	if !isValidIPOrCIDR(ip) {
		return fmt.Errorf("invalid IP or CIDR: %s", ip)
	}
	layer := a.engine.FindLayer("ipacl")
	if layer == nil {
		return fmt.Errorf("IP ACL layer not available")
	}
	ipaclLayer := layer.(*ipacl.Layer)
	return ipaclLayer.AddWhitelist(ip)
}

func (a *mcpEngineAdapter) RemoveWhitelist(ip string) error {
	layer := a.engine.FindLayer("ipacl")
	if layer == nil {
		return fmt.Errorf("IP ACL layer not available")
	}
	ipaclLayer := layer.(*ipacl.Layer)
	return ipaclLayer.RemoveWhitelist(ip)
}

func (a *mcpEngineAdapter) AddBlacklist(ip string) error {
	if !isValidIPOrCIDR(ip) {
		return fmt.Errorf("invalid IP or CIDR: %s", ip)
	}
	layer := a.engine.FindLayer("ipacl")
	if layer == nil {
		return fmt.Errorf("IP ACL layer not available")
	}
	ipaclLayer := layer.(*ipacl.Layer)
	return ipaclLayer.AddBlacklist(ip)
}

func (a *mcpEngineAdapter) RemoveBlacklist(ip string) error {
	layer := a.engine.FindLayer("ipacl")
	if layer == nil {
		return fmt.Errorf("IP ACL layer not available")
	}
	ipaclLayer := layer.(*ipacl.Layer)
	return ipaclLayer.RemoveBlacklist(ip)
}

func (a *mcpEngineAdapter) AddRateLimit(rule any) error {
	layer := a.engine.FindLayer("ratelimit")
	if layer == nil {
		return fmt.Errorf("rate limit layer not available")
	}
	rlLayer := layer.(*ratelimit.Layer)

	data, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("invalid rule: %w", err)
	}
	var p struct {
		ID     string `json:"id"`
		Scope  string `json:"scope"`
		Limit  int    `json:"limit"`
		Window string `json:"window"`
		Action string `json:"action"`
	}
	if unmarshalErr := json.Unmarshal(data, &p); unmarshalErr != nil {
		return fmt.Errorf("invalid rule format: %w", unmarshalErr)
	}

	window, err := time.ParseDuration(p.Window)
	if err != nil {
		return fmt.Errorf("invalid window duration: %w", err)
	}

	rlLayer.AddRule(ratelimit.Rule{
		ID:     p.ID,
		Scope:  p.Scope,
		Limit:  p.Limit,
		Window: window,
		Action: p.Action,
	})
	return nil
}

func (a *mcpEngineAdapter) RemoveRateLimit(id string) error {
	layer := a.engine.FindLayer("ratelimit")
	if layer == nil {
		return fmt.Errorf("rate limit layer not available")
	}
	rlLayer := layer.(*ratelimit.Layer)
	if !rlLayer.RemoveRule(id) {
		return fmt.Errorf("rate limit rule %s not found", id)
	}
	return nil
}

func (a *mcpEngineAdapter) AddExclusion(path string, detectors []string, reason string) error {
	layer := a.engine.FindLayer("detection")
	if layer == nil {
		return fmt.Errorf("detection layer not available")
	}
	detLayer := layer.(*detection.Layer)
	detLayer.AddExclusion(detection.Exclusion{
		PathPrefix: path,
		Detectors:  detectors,
		Reason:     reason,
	})
	return nil
}

func (a *mcpEngineAdapter) RemoveExclusion(path string) error {
	layer := a.engine.FindLayer("detection")
	if layer == nil {
		return fmt.Errorf("detection layer not available")
	}
	detLayer := layer.(*detection.Layer)
	if !detLayer.RemoveExclusion(path) {
		return fmt.Errorf("exclusion for path %s not found", path)
	}
	return nil
}

func (a *mcpEngineAdapter) GetEvents(params json.RawMessage) (any, error) {
	if a.eventStore == nil {
		return map[string]any{"events": []any{}, "total": 0}, nil
	}

	var p struct {
		Limit    int    `json:"limit"`
		Offset   int    `json:"offset"`
		Action   string `json:"action"`
		ClientIP string `json:"client_ip"`
		MinScore int    `json:"min_score"`
		Path     string `json:"path"`
	}
	if len(params) > 0 {
		_ = json.Unmarshal(params, &p) // nolint:errcheck // already validated len(params)>0; empty is valid
	}
	if p.Limit <= 0 {
		p.Limit = 50
	}

	evts, total, err := a.eventStore.Query(events.EventFilter{
		Limit:    p.Limit,
		Offset:   p.Offset,
		Action:   p.Action,
		ClientIP: p.ClientIP,
		MinScore: p.MinScore,
		Path:     p.Path,
	})
	if err != nil {
		return nil, fmt.Errorf("querying events: %w", err)
	}

	items := make([]map[string]any, len(evts))
	for i, ev := range evts {
		items[i] = map[string]any{
			"id":        ev.ID,
			"timestamp": ev.Timestamp,
			"client_ip": ev.ClientIP,
			"method":    ev.Method,
			"path":      ev.Path,
			"action":    ev.Action.String(),
			"score":     ev.Score,
			"findings":  len(ev.Findings),
		}
	}

	return map[string]any{"events": items, "total": total}, nil
}

func (a *mcpEngineAdapter) GetTopIPs(n int) any {
	if a.eventStore == nil {
		return []any{}
	}

	evts, _ := a.eventStore.Recent(10000)
	ipCounts := make(map[string]int)
	ipScores := make(map[string]int)
	for _, ev := range evts {
		ipCounts[ev.ClientIP]++
		ipScores[ev.ClientIP] += ev.Score
	}

	type ipStat struct {
		IP       string `json:"ip"`
		Requests int    `json:"requests"`
		Score    int    `json:"total_score"`
	}
	stats := make([]ipStat, 0, len(ipCounts))
	for ip, count := range ipCounts {
		stats = append(stats, ipStat{IP: ip, Requests: count, Score: ipScores[ip]})
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].Requests > stats[j].Requests })
	if n > 0 && n < len(stats) {
		stats = stats[:n]
	}
	return stats
}

func (a *mcpEngineAdapter) GetDetectors() any {
	cfg := a.engine.Config()
	detectors := make([]map[string]any, 0, len(cfg.WAF.Detection.Detectors))
	for name, dc := range cfg.WAF.Detection.Detectors {
		detectors = append(detectors, map[string]any{
			"name":       name,
			"enabled":    dc.Enabled,
			"multiplier": dc.Multiplier,
		})
	}
	return detectors
}

func (a *mcpEngineAdapter) TestRequest(method, urlStr string, headers map[string]string) (any, error) {
	fullURL := urlStr
	if !strings.HasPrefix(fullURL, "http://") && !strings.HasPrefix(fullURL, "https://") {
		fullURL = "http://localhost" + fullURL
	}

	req, err := http.NewRequestWithContext(context.Background(), method, fullURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.RemoteAddr = "127.0.0.1:0"

	event := a.engine.Check(req)
	findings := make([]map[string]any, 0, len(event.Findings))
	for _, f := range event.Findings {
		findings = append(findings, map[string]any{
			"detector":    f.DetectorName,
			"category":    f.Category,
			"severity":    f.Severity.String(),
			"score":       f.Score,
			"description": f.Description,
			"location":    f.Location,
		})
	}

	return map[string]any{
		"action":   event.Action.String(),
		"score":    event.Score,
		"findings": findings,
		"duration": event.Duration.String(),
	}, nil
}

func (a *mcpEngineAdapter) GetAlertingStatus() any {
	if a.alertMgr == nil {
		return map[string]any{
			"enabled":       false,
			"webhook_count": 0,
			"email_count":   0,
			"sent":          0,
			"failed":        0,
		}
	}
	stats := a.alertMgr.GetStats()
	return map[string]any{
		"enabled":       true,
		"webhook_count": stats.WebhookCount,
		"email_count":   stats.EmailCount,
		"sent":          stats.Sent,
		"failed":        stats.Failed,
	}
}

func (a *mcpEngineAdapter) AddWebhook(name, url, webhookType string, events []string, minScore int, cooldown string) error {
	if a.alertMgr == nil {
		return fmt.Errorf("alerting manager not available")
	}
	if err := alerting.ValidateWebhookURL(url); err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	d, err := time.ParseDuration(cooldown)
	if err != nil && cooldown != "" {
		return fmt.Errorf("invalid cooldown duration: %w", err)
	}
	target := alerting.WebhookTarget{
		Name:     name,
		URL:      url,
		Type:     webhookType,
		Events:   events,
		MinScore: minScore,
		Cooldown: d,
	}
	a.alertMgr.AddWebhook(target)
	return nil
}

func (a *mcpEngineAdapter) RemoveWebhook(name string) error {
	if a.alertMgr == nil {
		return fmt.Errorf("alerting manager not available")
	}
	if !a.alertMgr.RemoveWebhook(name) {
		return fmt.Errorf("webhook %s not found", name)
	}
	return nil
}

func (a *mcpEngineAdapter) AddEmailTarget(name, smtpHost string, smtpPort int, username, password, from string, to []string, useTLS bool, events []string, minScore int) error {
	if a.alertMgr == nil {
		return fmt.Errorf("alerting manager not available")
	}
	cfg := config.EmailConfig{
		Name:     name,
		SMTPHost: smtpHost,
		SMTPPort: smtpPort,
		Username: username,
		Password: password,
		From:     from,
		To:       to,
		UseTLS:   useTLS,
		Events:   events,
		MinScore: minScore,
	}
	a.alertMgr.AddEmailTarget(cfg)
	return nil
}

func (a *mcpEngineAdapter) RemoveEmailTarget(name string) error {
	if a.alertMgr == nil {
		return fmt.Errorf("alerting manager not available")
	}
	if !a.alertMgr.RemoveEmailTarget(name) {
		return fmt.Errorf("email target %s not found", name)
	}
	return nil
}

func (a *mcpEngineAdapter) TestAlert(target string) error {
	if a.alertMgr == nil {
		return fmt.Errorf("alerting manager not available")
	}
	return a.alertMgr.TestAlert(target)
}
