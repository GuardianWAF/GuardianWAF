// Package alerting provides security event notifications via webhooks and email
package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

// Manager handles alert routing and delivery
type Manager struct {
	config Config

	mu        sync.RWMutex
	webhooks  map[string]*WebhookTarget
	emails    map[string]*EmailTarget
	history   []AlertRecord
	historyMu sync.RWMutex

	// Cooldown tracking
	cooldowns   map[string]time.Time
	cooldownsMu sync.Mutex

	// Stats
	sentCount   int64
	failedCount int64
}

// Config for alerting
type Config struct {
	Enabled      bool          `json:"enabled"`
	MaxHistory   int           `json:"max_history"`
	DefaultCooldown time.Duration `json:"default_cooldown"`
}

// DefaultConfig returns default alerting config
func DefaultConfig() Config {
	return Config{
		Enabled:         true,
		MaxHistory:      10000,
		DefaultCooldown: 30 * time.Second,
	}
}

// WebhookTarget represents a webhook destination
type WebhookTarget struct {
	Name     string            `json:"name"`
	URL      string            `json:"url"`
	Type     string            `json:"type"` // generic, slack, discord, pagerduty
	Events   []string          `json:"events"`
	MinScore int               `json:"min_score"`
	Cooldown string            `json:"cooldown"`
	Headers  map[string]string `json:"headers,omitempty"`

	parsedCooldown time.Duration
}

// EmailTarget represents an SMTP email configuration
type EmailTarget struct {
	Name     string   `json:"name"`
	SMTPHost string   `json:"smtp_host"`
	SMTPPort int      `json:"smtp_port"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	UseTLS   bool     `json:"use_tls"`
	Events   []string `json:"events"`
	MinScore int      `json:"min_score"`
	Cooldown string   `json:"cooldown"`
	Subject  string   `json:"subject,omitempty"`
	Template string   `json:"template,omitempty"`

	parsedCooldown time.Duration
}

// AlertRecord represents a sent alert
type AlertRecord struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Target    string    `json:"target"`
	Type      string    `json:"type"` // webhook, email
	Event     string    `json:"event"`
	Score     int       `json:"score"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
}

// Event represents a security event that can trigger alerts
type Event struct {
	ID          string            `json:"id"`
	Timestamp   time.Time         `json:"timestamp"`
	Type        string            `json:"type"`        // block, challenge, log
	Score       int               `json:"score"`
	ClientIP    string            `json:"client_ip"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Host        string            `json:"host"`
	UserAgent   string            `json:"user_agent"`
	RuleHits    []string          `json:"rule_hits,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
}

// NewManager creates a new alerting manager
func NewManager(config Config) *Manager {
	m := &Manager{
		config:    config,
		webhooks:  make(map[string]*WebhookTarget),
		emails:    make(map[string]*EmailTarget),
		history:   make([]AlertRecord, 0, config.MaxHistory),
		cooldowns: make(map[string]time.Time),
	}
	return m
}

// AddWebhook adds a webhook target
func (m *Manager) AddWebhook(target *WebhookTarget) error {
	if target.Name == "" {
		return fmt.Errorf("webhook name is required")
	}
	if target.URL == "" {
		return fmt.Errorf("webhook URL is required")
	}

	// Parse cooldown
	duration, err := parseDuration(target.Cooldown)
	if err != nil {
		duration = m.config.DefaultCooldown
	}
	target.parsedCooldown = duration

	m.mu.Lock()
	defer m.mu.Unlock()

	m.webhooks[target.Name] = target
	return nil
}

// RemoveWebhook removes a webhook target
func (m *Manager) RemoveWebhook(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.webhooks[name]; !ok {
		return fmt.Errorf("webhook not found: %s", name)
	}

	delete(m.webhooks, name)
	return nil
}

// GetWebhooks returns all webhook targets
func (m *Manager) GetWebhooks() []*WebhookTarget {
	m.mu.RLock()
	defer m.mu.RUnlock()

	targets := make([]*WebhookTarget, 0, len(m.webhooks))
	for _, w := range m.webhooks {
		targets = append(targets, w)
	}
	return targets
}

// AddEmail adds an email target
func (m *Manager) AddEmail(target *EmailTarget) error {
	if target.Name == "" {
		return fmt.Errorf("email name is required")
	}
	if target.SMTPHost == "" {
		return fmt.Errorf("SMTP host is required")
	}
	if target.From == "" {
		return fmt.Errorf("from address is required")
	}
	if len(target.To) == 0 {
		return fmt.Errorf("to addresses are required")
	}

	// Parse cooldown
	duration, err := parseDuration(target.Cooldown)
	if err != nil {
		duration = m.config.DefaultCooldown
	}
	target.parsedCooldown = duration

	m.mu.Lock()
	defer m.mu.Unlock()

	m.emails[target.Name] = target
	return nil
}

// RemoveEmail removes an email target
func (m *Manager) RemoveEmail(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.emails[name]; !ok {
		return fmt.Errorf("email target not found: %s", name)
	}

	delete(m.emails, name)
	return nil
}

// GetEmails returns all email targets
func (m *Manager) GetEmails() []*EmailTarget {
	m.mu.RLock()
	defer m.mu.RUnlock()

	targets := make([]*EmailTarget, 0, len(m.emails))
	for _, e := range m.emails {
		targets = append(targets, e)
	}
	return targets
}

// SendAlert processes and sends alerts for an event
func (m *Manager) SendAlert(event *Event) {
	if !m.config.Enabled {
		return
	}

	// Send to webhooks
	webhooks := m.GetWebhooks()
	for _, webhook := range webhooks {
		if m.shouldSend(webhook, event) {
			go m.sendWebhook(webhook, event)
		}
	}

	// Send to emails
	emails := m.GetEmails()
	for _, email := range emails {
		if m.shouldSendEmail(email, event) {
			go m.sendEmail(email, event)
		}
	}
}

// shouldSend checks if an event should trigger a webhook
func (m *Manager) shouldSend(webhook *WebhookTarget, event *Event) bool {
	// Check score threshold
	if event.Score < webhook.MinScore {
		return false
	}

	// Check event type
	if !containsEvent(webhook.Events, event.Type) && !containsEvent(webhook.Events, "all") {
		return false
	}

	// Check cooldown
	return m.checkCooldown(webhook.Name, webhook.parsedCooldown)
}

// shouldSendEmail checks if an event should trigger an email
func (m *Manager) shouldSendEmail(email *EmailTarget, event *Event) bool {
	// Check score threshold
	if event.Score < email.MinScore {
		return false
	}

	// Check event type
	if !containsEvent(email.Events, event.Type) && !containsEvent(email.Events, "all") {
		return false
	}

	// Check cooldown
	return m.checkCooldown(email.Name, email.parsedCooldown)
}

// checkCooldown returns true if enough time has passed since last alert
func (m *Manager) checkCooldown(key string, cooldown time.Duration) bool {
	m.cooldownsMu.Lock()
	defer m.cooldownsMu.Unlock()

	lastSent, ok := m.cooldowns[key]
	if !ok {
		m.cooldowns[key] = time.Now()
		return true
	}

	if time.Since(lastSent) >= cooldown {
		m.cooldowns[key] = time.Now()
		return true
	}

	return false
}

// sendWebhook sends a webhook notification
func (m *Manager) sendWebhook(webhook *WebhookTarget, event *Event) {
	payload := m.formatWebhookPayload(webhook.Type, event)

	req, err := http.NewRequest("POST", webhook.URL, bytes.NewReader(payload))
	if err != nil {
		m.recordAlert(webhook.Name, "webhook", event, false, err.Error())
		return
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range webhook.Headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		m.recordAlert(webhook.Name, "webhook", event, false, err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		m.recordAlert(webhook.Name, "webhook", event, true, "")
	} else {
		m.recordAlert(webhook.Name, "webhook", event, false, fmt.Sprintf("HTTP %d", resp.StatusCode))
	}
}

// formatWebhookPayload formats event for different webhook types
func (m *Manager) formatWebhookPayload(webhookType string, event *Event) []byte {
	switch webhookType {
	case "slack":
		return m.formatSlackPayload(event)
	case "discord":
		return m.formatDiscordPayload(event)
	case "pagerduty":
		return m.formatPagerDutyPayload(event)
	default:
		return m.formatGenericPayload(event)
	}
}

// formatSlackPayload formats for Slack webhook
func (m *Manager) formatSlackPayload(event *Event) []byte {
	color := "warning"
	if event.Type == "block" {
		color = "danger"
	} else if event.Type == "log" {
		color = "good"
	}

	payload := map[string]any{
		"attachments": []map[string]any{
			{
				"color":      color,
				"title":      fmt.Sprintf("GuardianWAF Alert: %s", strings.ToUpper(event.Type)),
				"text":       fmt.Sprintf("Suspicious request detected with score %d", event.Score),
				"fields": []map[string]string{
					{"title": "Client IP", "value": event.ClientIP, "short": "true"},
					{"title": "Method", "value": event.Method, "short": "true"},
					{"title": "Path", "value": event.Path, "short": "true"},
					{"title": "Host", "value": event.Host, "short": "true"},
					{"title": "Score", "value": fmt.Sprintf("%d", event.Score), "short": "true"},
					{"title": "Time", "value": event.Timestamp.Format(time.RFC3339), "short": "true"},
				},
				"footer": "GuardianWAF",
				"ts":     event.Timestamp.Unix(),
			},
		},
	}

	data, _ := json.Marshal(payload)
	return data
}

// formatDiscordPayload formats for Discord webhook
func (m *Manager) formatDiscordPayload(event *Event) []byte {
	color := 16776960 // Yellow
	if event.Type == "block" {
		color = 16711680 // Red
	} else if event.Type == "log" {
		color = 3066993 // Green
	}

	payload := map[string]any{
		"embeds": []map[string]any{
			{
				"title":       fmt.Sprintf("🛡️ GuardianWAF Alert: %s", strings.ToUpper(event.Type)),
				"description": fmt.Sprintf("Suspicious request detected with score **%d**", event.Score),
				"color":       color,
				"fields": []map[string]any{
					{"name": "Client IP", "value": event.ClientIP, "inline": true},
					{"name": "Method", "value": event.Method, "inline": true},
					{"name": "Path", "value": event.Path, "inline": true},
					{"name": "Host", "value": event.Host, "inline": true},
					{"name": "Score", "value": event.Score, "inline": true},
					{"name": "Time", "value": event.Timestamp.Format(time.RFC3339), "inline": true},
				},
				"timestamp": event.Timestamp.Format(time.RFC3339),
				"footer":    map[string]string{"text": "GuardianWAF Security"},
			},
		},
	}

	data, _ := json.Marshal(payload)
	return data
}

// formatPagerDutyPayload formats for PagerDuty webhook
func (m *Manager) formatPagerDutyPayload(event *Event) []byte {
	severity := "warning"
	if event.Score >= 80 {
		severity = "critical"
	} else if event.Score >= 50 {
		severity = "error"
	}

	payload := map[string]any{
		"routing_key": "", // Will be in URL or headers
		"event_action": "trigger",
		"dedup_key":   fmt.Sprintf("guardianwaf-%s-%s", event.ClientIP, event.ID),
		"payload": map[string]any{
			"summary":  fmt.Sprintf("GuardianWAF: %s request from %s", event.Type, event.ClientIP),
			"severity": severity,
			"source":   event.ClientIP,
			"custom_details": map[string]any{
				"score":     event.Score,
				"method":    event.Method,
				"path":      event.Path,
				"host":      event.Host,
				"user_agent": event.UserAgent,
				"rule_hits": event.RuleHits,
			},
		},
	}

	data, _ := json.Marshal(payload)
	return data
}

// formatGenericPayload formats for generic webhook
func (m *Manager) formatGenericPayload(event *Event) []byte {
	data, _ := json.Marshal(event)
	return data
}

// sendEmail sends an email notification
func (m *Manager) sendEmail(target *EmailTarget, event *Event) {
	subject := target.Subject
	if subject == "" {
		subject = fmt.Sprintf("[GuardianWAF] %s Alert - Score %d", strings.ToUpper(event.Type), event.Score)
	}

	body := m.formatEmailBody(target, event)

	// Build email content
	var auth smtp.Auth
	if target.Username != "" && target.Password != "" {
		auth = smtp.PlainAuth("", target.Username, target.Password, target.SMTPHost)
	}

	addr := fmt.Sprintf("%s:%d", target.SMTPHost, target.SMTPPort)
	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		strings.Join(target.To, ", "), subject, body))

	var err error
	if target.UseTLS {
		err = smtp.SendMail(addr, auth, target.From, target.To, msg)
	} else {
		// Plain text SMTP (not recommended for production)
		err = smtp.SendMail(addr, auth, target.From, target.To, msg)
	}

	if err != nil {
		m.recordAlert(target.Name, "email", event, false, err.Error())
	} else {
		m.recordAlert(target.Name, "email", event, true, "")
	}
}

// formatEmailBody formats HTML email body
func (m *Manager) formatEmailBody(target *EmailTarget, event *Event) string {
	if target.Template != "" {
		// Simple template substitution could be implemented here
		return target.Template
	}

	color := "#f59e0b" // Yellow
	if event.Type == "block" {
		color = "#ef4444" // Red
	} else if event.Type == "log" {
		color = "#10b981" // Green
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: %s; color: white; padding: 20px; border-radius: 5px; }
        .content { background: #f5f5f5; padding: 20px; margin-top: 20px; border-radius: 5px; }
        .field { margin: 10px 0; }
        .label { font-weight: bold; color: #666; }
        .value { color: #333; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>🛡️ GuardianWAF Alert</h2>
            <p>%s detected with score %d</p>
        </div>
        <div class="content">
            <div class="field"><span class="label">Event Type:</span> <span class="value">%s</span></div>
            <div class="field"><span class="label">Client IP:</span> <span class="value">%s</span></div>
            <div class="field"><span class="label">Method:</span> <span class="value">%s</span></div>
            <div class="field"><span class="label">Path:</span> <span class="value">%s</span></div>
            <div class="field"><span class="label">Host:</span> <span class="value">%s</span></div>
            <div class="field"><span class="label">Score:</span> <span class="value">%d</span></div>
            <div class="field"><span class="label">Time:</span> <span class="value">%s</span></div>
        </div>
    </div>
</body>
</html>`, color, strings.ToUpper(event.Type), event.Score, strings.ToUpper(event.Type),
		event.ClientIP, event.Method, event.Path, event.Host, event.Score,
		event.Timestamp.Format(time.RFC1123))

	return html
}

// SendTestAlert sends a test alert to a target
func (m *Manager) SendTestAlert(targetName string) error {
	testEvent := &Event{
		ID:        "test-" + fmt.Sprintf("%d", time.Now().Unix()),
		Timestamp: time.Now(),
		Type:      "block",
		Score:     75,
		ClientIP:  "127.0.0.1",
		Method:    "GET",
		Path:      "/test-alert",
		Host:      "example.com",
		UserAgent: "GuardianWAF-Test/1.0",
		RuleHits:  []string{"test-rule-1", "test-rule-2"},
	}

	// Check if it's a webhook
	m.mu.RLock()
	webhook, ok := m.webhooks[targetName]
	m.mu.RUnlock()

	if ok {
		// Bypass cooldown for test
		m.sendWebhook(webhook, testEvent)
		return nil
	}

	// Check if it's an email
	m.mu.RLock()
	email, ok := m.emails[targetName]
	m.mu.RUnlock()

	if ok {
		// Bypass cooldown for test
		m.sendEmail(email, testEvent)
		return nil
	}

	return fmt.Errorf("target not found: %s", targetName)
}

// recordAlert records an alert in history
func (m *Manager) recordAlert(target, targetType string, event *Event, success bool, errorMsg string) {
	m.historyMu.Lock()
	defer m.historyMu.Unlock()

	record := AlertRecord{
		ID:        fmt.Sprintf("alert-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		Target:    target,
		Type:      targetType,
		Event:     event.Type,
		Score:     event.Score,
		Success:   success,
		Error:     errorMsg,
	}

	m.history = append(m.history, record)

	// Trim history if too large
	if len(m.history) > m.config.MaxHistory {
		m.history = m.history[len(m.history)-m.config.MaxHistory:]
	}

	// Update stats
	if success {
		m.sentCount++
	} else {
		m.failedCount++
	}
}

// GetHistory returns alert history
func (m *Manager) GetHistory(limit int) []AlertRecord {
	m.historyMu.RLock()
	defer m.historyMu.RUnlock()

	if limit <= 0 || limit > len(m.history) {
		limit = len(m.history)
	}

	// Return most recent first
	start := len(m.history) - limit
	if start < 0 {
		start = 0
	}

	result := make([]AlertRecord, limit)
	for i := 0; i < limit; i++ {
		result[i] = m.history[len(m.history)-1-i]
	}

	return result
}

// GetStats returns alerting statistics
func (m *Manager) GetStats() (sent, failed int64) {
	return m.sentCount, m.failedCount
}

// GetStatus returns overall alerting status
func (m *Manager) GetStatus() map[string]any {
	m.mu.RLock()
	m.historyMu.RLock()
	defer m.mu.RUnlock()
	defer m.historyMu.RUnlock()

	sent, failed := m.GetStats()

	return map[string]any{
		"enabled":       m.config.Enabled,
		"sent":          sent,
		"failed":        failed,
		"webhook_count": len(m.webhooks),
		"email_count":   len(m.emails),
		"history_count": len(m.history),
	}
}

// Helper functions

func containsEvent(events []string, event string) bool {
	for _, e := range events {
		if strings.EqualFold(e, "all") {
			return true
		}
		if strings.EqualFold(e, event) {
			return true
		}
	}
	return false
}

func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	return time.ParseDuration(s)
}
