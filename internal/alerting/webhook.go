// Package alerting provides webhook and email-based alert delivery for GuardianWAF.
// Sends notifications to Slack, Discord, custom HTTP endpoints, or via SMTP email when
// security events occur (blocks, challenges, high-score events).
package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// WebhookTarget defines a single webhook target for the alerting manager.
type WebhookTarget struct {
	Name     string
	URL      string
	Type     string   // "slack", "discord", "generic", "pagerduty"
	Events   []string // "block", "challenge", "log", "all"
	MinScore int
	Cooldown time.Duration
	Headers  map[string]string
}

// Alert is the payload sent to webhooks.
type Alert struct {
	Timestamp string   `json:"timestamp"`
	EventID   string   `json:"event_id"`
	ClientIP  string   `json:"client_ip"`
	Method    string   `json:"method"`
	Path      string   `json:"path"`
	Action    string   `json:"action"`
	Score     int      `json:"score"`
	Findings  []string `json:"findings"`
	UserAgent string   `json:"user_agent,omitempty"`
}

// Manager manages webhook and email delivery for security events.
type Manager struct {
	webhooks     []webhook
	emailTargets []*EmailTarget
	httpClient   *http.Client
	logFn        func(level, msg string)

	// Stats
	sent   atomic.Int64
	failed atomic.Int64
}

type webhook struct {
	config   WebhookTarget
	cooldown time.Duration
	lastFire *sync.Map // IP → time.Time
}

// Stats holds alerting statistics.
type Stats struct {
	Sent         int64      `json:"sent"`
	Failed       int64      `json:"failed"`
	WebhookCount int        `json:"webhook_count"`
	EmailCount   int        `json:"email_count"`
	Email        EmailStats `json:"email,omitempty"`
}

// NewManager creates an alerting manager with the given webhook targets.
func NewManager(targets []WebhookTarget) *Manager {
	m := &Manager{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		logFn:      func(_, _ string) {},
	}

	for _, t := range targets {
		wh := webhook{config: t, lastFire: &sync.Map{}}
		wh.cooldown = t.Cooldown
		if wh.cooldown <= 0 {
			wh.cooldown = 30 * time.Second
		}
		m.webhooks = append(m.webhooks, wh)
	}

	return m
}

// NewManagerWithEmail creates an alerting manager with both webhook and email targets.
func NewManagerWithEmail(targets []WebhookTarget, emails []config.EmailConfig) *Manager {
	m := NewManager(targets)

	for _, cfg := range emails {
		if cfg.SMTPHost != "" && len(cfg.To) > 0 {
			m.emailTargets = append(m.emailTargets, NewEmailTarget(cfg))
		}
	}

	return m
}

// SetLogger sets the log callback.
func (m *Manager) SetLogger(fn func(level, msg string)) {
	m.logFn = fn
}

// GetStats returns alerting statistics.
func (m *Manager) GetStats() Stats {
	return Stats{
		Sent:         m.sent.Load(),
		Failed:       m.failed.Load(),
		WebhookCount: len(m.webhooks),
		EmailCount:   len(m.emailTargets),
		Email:        GetEmailStats(),
	}
}

// HandleEvent processes a WAF event and fires matching webhooks and emails.
func (m *Manager) HandleEvent(event *engine.Event) {
	action := event.Action.String()

	findings := make([]string, 0, len(event.Findings))
	for _, f := range event.Findings {
		findings = append(findings, fmt.Sprintf("%s: %s (score=%d)", f.DetectorName, f.Description, f.Score))
	}

	alert := Alert{
		Timestamp: event.Timestamp.Format(time.RFC3339),
		EventID:   event.ID,
		ClientIP:  event.ClientIP,
		Method:    event.Method,
		Path:      event.Path,
		Action:    action,
		Score:     event.Score,
		Findings:  findings,
		UserAgent: event.UserAgent,
	}

	// Process webhooks
	for i := range m.webhooks {
		wh := &m.webhooks[i]

		// Check if this webhook cares about this event type
		if !matchesEvent(wh.config.Events, action) {
			continue
		}

		// Check minimum score
		if wh.config.MinScore > 0 && event.Score < wh.config.MinScore {
			continue
		}

		// Cooldown per IP
		if wh.cooldown > 0 {
			if last, ok := wh.lastFire.Load(event.ClientIP); ok {
				if time.Since(last.(time.Time)) < wh.cooldown {
					continue
				}
			}
			wh.lastFire.Store(event.ClientIP, time.Now())
		}

		// Fire async
		go m.send(&wh.config, &alert)
	}

	// Process email alerts
	for _, et := range m.emailTargets {
		cfg := et.config

		// Check if this email target cares about this event type
		if !matchesEvent(cfg.Events, action) {
			continue
		}

		// Check minimum score
		if cfg.MinScore > 0 && event.Score < cfg.MinScore {
			continue
		}

		// Cooldown per IP
		if et.cooldown > 0 {
			if last, ok := et.lastFire.Load(event.ClientIP); ok {
				if time.Since(last.(time.Time)) < et.cooldown {
					continue
				}
			}
			et.lastFire.Store(event.ClientIP, time.Now())
		}

		// Send email async
		go m.SendEmail(et, event)
	}
}

// send delivers an alert to a webhook endpoint.
func (m *Manager) send(wc *WebhookTarget, alert *Alert) {
	var body []byte
	switch wc.Type {
	case "slack":
		body, _ = json.Marshal(slackPayload(alert))
	case "discord":
		body, _ = json.Marshal(discordPayload(alert))
	case "pagerduty":
		body, _ = json.Marshal(pagerdutyPayload(alert))
	default:
		body, _ = json.Marshal(alert)
	}

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wc.URL, bytes.NewReader(body))
	if err != nil {
		m.failed.Add(1)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GuardianWAF-Alerting/1.0")

	// Custom headers for generic webhooks
	for k, v := range wc.Headers {
		req.Header.Set(k, v)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		m.failed.Add(1)
		m.logFn("warn", fmt.Sprintf("Webhook %s failed: %v", wc.Name, err))
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		m.failed.Add(1)
		m.logFn("warn", fmt.Sprintf("Webhook %s returned %d", wc.Name, resp.StatusCode))
		return
	}

	m.sent.Add(1)
}

func matchesEvent(events []string, action string) bool {
	if len(events) == 0 {
		return action == "block" // default: only blocks
	}
	for _, e := range events {
		if e == action || e == "all" {
			return true
		}
	}
	return false
}

// --- Slack format ---

func slackPayload(a *Alert) map[string]any {
	color := "#ff0000"
	if a.Action == "log" {
		color = "#ffaa00"
	} else if a.Action == "challenge" {
		color = "#0066ff"
	}

	findingsText := ""
	for _, f := range a.Findings {
		findingsText += "• " + f + "\n"
	}
	if findingsText == "" {
		findingsText = "No specific findings"
	}

	return map[string]any{
		"attachments": []map[string]any{
			{
				"color": color,
				"title": fmt.Sprintf("GuardianWAF — %s", a.Action),
				"text":  fmt.Sprintf("**%s** `%s %s` from `%s` (score: %d)", a.Action, a.Method, a.Path, a.ClientIP, a.Score),
				"fields": []map[string]any{
					{"title": "IP", "value": a.ClientIP, "short": true},
					{"title": "Score", "value": fmt.Sprintf("%d", a.Score), "short": true},
					{"title": "Path", "value": fmt.Sprintf("%s %s", a.Method, a.Path), "short": false},
					{"title": "Findings", "value": findingsText, "short": false},
				},
				"footer": "GuardianWAF",
				"ts":     a.Timestamp,
			},
		},
	}
}

// --- Discord format ---

func discordPayload(a *Alert) map[string]any {
	color := 0xff0000
	if a.Action == "log" {
		color = 0xffaa00
	} else if a.Action == "challenge" {
		color = 0x0066ff
	}

	findingsText := ""
	for _, f := range a.Findings {
		findingsText += "• " + f + "\n"
	}
	if findingsText == "" {
		findingsText = "No specific findings"
	}

	return map[string]any{
		"embeds": []map[string]any{
			{
				"title":       fmt.Sprintf("GuardianWAF — %s", a.Action),
				"description": fmt.Sprintf("**%s** `%s %s` from `%s` (score: %d)", a.Action, a.Method, a.Path, a.ClientIP, a.Score),
				"color":       color,
				"fields": []map[string]any{
					{"name": "IP", "value": a.ClientIP, "inline": true},
					{"name": "Score", "value": fmt.Sprintf("%d", a.Score), "inline": true},
					{"name": "Findings", "value": findingsText, "inline": false},
				},
				"footer":    map[string]any{"text": "GuardianWAF"},
				"timestamp": a.Timestamp,
			},
		},
	}
}

// --- PagerDuty Events API v2 format ---

func pagerdutyPayload(a *Alert) map[string]any {
	// Map action to PagerDuty severity
	severity := "warning"
	switch a.Action {
	case "block":
		severity = "critical"
	case "challenge":
		severity = "warning"
	case "log":
		severity = "info"
	}

	// Create dedup key based on IP and action
	dedupKey := fmt.Sprintf("guardianwaf-%s-%s", a.ClientIP, a.Action)

	return map[string]any{
		"routing_key":  "", // Will be set via custom header or URL
		"event_action": "trigger",
		"dedup_key":    dedupKey,
		"payload": map[string]any{
			"summary":   fmt.Sprintf("GuardianWAF %s: %s %s from %s", a.Action, a.Method, a.Path, a.ClientIP),
			"severity":  severity,
			"source":    a.ClientIP,
			"timestamp": a.Timestamp,
			"component": "WAF",
			"group":     "security",
			"class":     a.Action,
			"custom_details": map[string]any{
				"event_id":   a.EventID,
				"client_ip":  a.ClientIP,
				"method":     a.Method,
				"path":       a.Path,
				"score":      a.Score,
				"action":     a.Action,
				"user_agent": a.UserAgent,
				"findings":   a.Findings,
			},
		},
	}
}

// AddWebhook adds a new webhook target at runtime.
func (m *Manager) AddWebhook(target WebhookTarget) {
	wh := webhook{
		config:   target,
		cooldown: target.Cooldown,
		lastFire: &sync.Map{},
	}
	if wh.cooldown <= 0 {
		wh.cooldown = 30 * time.Second
	}
	m.webhooks = append(m.webhooks, wh)
	m.logFn("info", fmt.Sprintf("Webhook target added: %s", target.Name))
}

// RemoveWebhook removes a webhook target by name. Returns true if found and removed.
func (m *Manager) RemoveWebhook(name string) bool {
	for i, wh := range m.webhooks {
		if wh.config.Name == name {
			m.webhooks = append(m.webhooks[:i], m.webhooks[i+1:]...)
			m.logFn("info", fmt.Sprintf("Webhook target removed: %s", name))
			return true
		}
	}
	return false
}

// AddEmailTarget adds a new email target at runtime.
func (m *Manager) AddEmailTarget(cfg config.EmailConfig) {
	if cfg.SMTPHost != "" && len(cfg.To) > 0 {
		m.emailTargets = append(m.emailTargets, NewEmailTarget(cfg))
		m.logFn("info", fmt.Sprintf("Email target added: %s", cfg.Name))
	}
}

// RemoveEmailTarget removes an email target by name. Returns true if found and removed.
func (m *Manager) RemoveEmailTarget(name string) bool {
	for i, et := range m.emailTargets {
		if et.config.Name == name {
			m.emailTargets = append(m.emailTargets[:i], m.emailTargets[i+1:]...)
			m.logFn("info", fmt.Sprintf("Email target removed: %s", name))
			return true
		}
	}
	return false
}

// TestAlert sends a test alert to the specified target.
func (m *Manager) TestAlert(targetName string) error {
	testAlert := Alert{
		Timestamp: time.Now().Format(time.RFC3339),
		EventID:   "test-" + time.Now().Format("20060102150405"),
		ClientIP:  "127.0.0.1",
		Method:    "GET",
		Path:      "/test/alert",
		Action:    "block",
		Score:     75,
		Findings:  []string{"Test alert from GuardianWAF MCP"},
		UserAgent: "GuardianWAF-Test/1.0",
	}

	// Try webhooks first
	for i := range m.webhooks {
		if m.webhooks[i].config.Name == targetName {
			m.send(&m.webhooks[i].config, &testAlert)
			return nil
		}
	}

	// Try email targets
	for _, et := range m.emailTargets {
		if et.config.Name == targetName {
			event := engine.Event{
				ID:        testAlert.EventID,
				Timestamp: time.Now(),
				ClientIP:  testAlert.ClientIP,
				Method:    testAlert.Method,
				Path:      testAlert.Path,
				Score:     testAlert.Score,
				UserAgent: testAlert.UserAgent,
			}
			m.SendEmail(et, &event)
			return nil
		}
	}

	return fmt.Errorf("target %s not found", targetName)
}
