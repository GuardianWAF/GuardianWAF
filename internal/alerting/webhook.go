// Package alerting provides webhook-based alert delivery for GuardianWAF.
// Sends notifications to Slack, Discord, or custom HTTP endpoints when
// security events occur (blocks, challenges, high-score events).
package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// WebhookTarget defines a single webhook target for the alerting manager.
type WebhookTarget struct {
	Name     string
	URL      string
	Type     string            // "slack", "discord", "generic"
	Events   []string          // "block", "challenge", "log", "all"
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

// Manager manages webhook delivery for security events.
type Manager struct {
	mu         sync.RWMutex
	webhooks   []webhook
	httpClient *http.Client
	logFn      func(level, msg string)

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
	Sent          int64 `json:"sent"`
	Failed        int64 `json:"failed"`
	WebhookCount  int   `json:"webhook_count"`
}

// NewManager creates an alerting manager from config.
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
	}
}

// HandleEvent processes a WAF event and fires matching webhooks.
func (m *Manager) HandleEvent(event engine.Event) {
	action := event.Action.String()

	var findings []string
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
		go m.send(wh.config, alert)
	}
}

// send delivers an alert to a webhook endpoint.
func (m *Manager) send(wc WebhookTarget, alert Alert) {
	var body []byte
	var err error

	switch wc.Type {
	case "slack":
		body, err = json.Marshal(slackPayload(alert))
	case "discord":
		body, err = json.Marshal(discordPayload(alert))
	default:
		body, err = json.Marshal(alert)
	}
	if err != nil {
		m.failed.Add(1)
		return
	}

	req, err := http.NewRequest("POST", wc.URL, bytes.NewReader(body))
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
	io.Copy(io.Discard, resp.Body)

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

func slackPayload(a Alert) map[string]any {
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
				"color":  color,
				"title":  fmt.Sprintf("GuardianWAF — %s", a.Action),
				"text":   fmt.Sprintf("**%s** `%s %s` from `%s` (score: %d)", a.Action, a.Method, a.Path, a.ClientIP, a.Score),
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

func discordPayload(a Alert) map[string]any {
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
