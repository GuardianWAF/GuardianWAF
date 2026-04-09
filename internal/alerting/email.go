// Package alerting provides webhook and email-based alert delivery.
package alerting

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// EmailTarget defines an SMTP email alert target.
type EmailTarget struct {
	config   config.EmailConfig
	cooldown time.Duration
	lastFire *sync.Map // IP → time.Time
}

// EmailStats holds email alerting statistics.
type EmailStats struct {
	Sent        int64 `json:"sent"`
	Failed      int64 `json:"failed"`
	TargetCount int   `json:"target_count"`
}

// emailSent and emailFailed are atomic counters for email stats.
var (
	emailSent   atomic.Int64
	emailFailed atomic.Int64
)

// SendEmail sends an alert via SMTP.
func (m *Manager) SendEmail(target *EmailTarget, event *engine.Event) {
	cfg := target.config

	// Build email body
	subject := cfg.Subject
	if subject == "" {
		subject = fmt.Sprintf("[GuardianWAF] %s from %s", event.Action.String(), event.ClientIP)
	}

	body := m.buildEmailBody(cfg, event)

	// Connect to SMTP server
	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	if cfg.SMTPPort == 0 {
		addr = fmt.Sprintf("%s:587", cfg.SMTPHost)
	}

	// Authentication
	var auth smtp.Auth
	if cfg.Username != "" && cfg.Password != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.SMTPHost)
	}

	// Build message
	msg := m.buildSMTPMessage(cfg.From, cfg.To, subject, body)

	// Send with or without TLS
	var err error
	if cfg.UseTLS {
		err = m.sendTLS(addr, auth, cfg.From, cfg.To, msg)
	} else {
		err = smtp.SendMail(addr, auth, cfg.From, cfg.To, msg)
	}

	if err != nil {
		emailFailed.Add(1)
		m.logFn("error", fmt.Sprintf("failed to send email alert: %v", err))
	} else {
		emailSent.Add(1)
		m.logFn("info", fmt.Sprintf("email alert sent to %s for event %s", strings.Join(cfg.To, ", "), event.ID))
	}
}

// sendTLS sends email with TLS encryption.
func (m *Manager) sendTLS(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: addr[:strings.LastIndex(addr, ":")]})
	if err != nil {
		return fmt.Errorf("TLS dial failed: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, addr[:strings.LastIndex(addr, ":")])
	if err != nil {
		return fmt.Errorf("SMTP client creation failed: %w", err)
	}
	defer client.Close()

	if auth != nil {
		if authErr := client.Auth(auth); authErr != nil {
			return fmt.Errorf("SMTP auth failed: %w", authErr)
		}
	}

	if mailErr := client.Mail(from); mailErr != nil {
		return fmt.Errorf("SMTP MAIL command failed: %w", mailErr)
	}

	for _, rcpt := range to {
		if rcptErr := client.Rcpt(rcpt); rcptErr != nil {
			return fmt.Errorf("SMTP RCPT command failed: %w", rcptErr)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA command failed: %w", err)
	}

	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("SMTP data write failed: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("SMTP data close failed: %w", err)
	}

	return client.Quit()
}

// sanitizeHeader strips CRLF characters to prevent SMTP header injection.
func sanitizeHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return s
}

// buildSMTPMessage constructs an SMTP-compliant message.
func (m *Manager) buildSMTPMessage(from string, to []string, subject, body string) []byte {
	headers := make([]string, 0, 5)
	headers = append(headers, fmt.Sprintf("From: %s", sanitizeHeader(from)))
	headers = append(headers, fmt.Sprintf("To: %s", sanitizeHeader(strings.Join(to, ", "))))
	headers = append(headers, fmt.Sprintf("Subject: %s", sanitizeHeader(subject)))
	headers = append(headers, "MIME-Version: 1.0")
	headers = append(headers, "Content-Type: text/plain; charset=\"utf-8\"")
	headers = append(headers, "")

	return []byte(strings.Join(headers, "\r\n") + body)
}

// buildEmailBody constructs the email body from template or default format.
func (m *Manager) buildEmailBody(cfg config.EmailConfig, event *engine.Event) string {
	if cfg.Template != "" {
		// Simple template substitution
		body := cfg.Template
		body = strings.ReplaceAll(body, "{{EventID}}", event.ID)
		body = strings.ReplaceAll(body, "{{ClientIP}}", event.ClientIP)
		body = strings.ReplaceAll(body, "{{Method}}", event.Method)
		body = strings.ReplaceAll(body, "{{Path}}", event.Path)
		body = strings.ReplaceAll(body, "{{Action}}", event.Action.String())
		body = strings.ReplaceAll(body, "{{Score}}", fmt.Sprintf("%d", event.Score))
		body = strings.ReplaceAll(body, "{{Timestamp}}", event.Timestamp.Format(time.RFC3339))
		body = strings.ReplaceAll(body, "{{UserAgent}}", event.UserAgent)
		return body
	}

	// Default template
	var findings []string
	for _, f := range event.Findings {
		findings = append(findings, fmt.Sprintf("  - %s: %s (score=%d)", f.DetectorName, f.Description, f.Score))
	}

	return fmt.Sprintf(`GuardianWAF Security Alert

Event Details:
  ID:        %s
  Timestamp: %s
  Action:    %s
  Score:     %d

Request:
  Client IP: %s
  Method:    %s
  Path:      %s
  User-Agent: %s

Findings:
%s

---
This alert was generated by GuardianWAF.
`, event.ID, event.Timestamp.Format(time.RFC3339), event.Action.String(), event.Score,
		event.ClientIP, event.Method, event.Path, event.UserAgent, strings.Join(findings, "\n"))
}

// NewEmailTarget creates an email target from config.
func NewEmailTarget(cfg config.EmailConfig) *EmailTarget {
	cooldown := cfg.Cooldown
	if cooldown <= 0 {
		cooldown = 5 * time.Minute // Default 5 minute cooldown for emails
	}
	return &EmailTarget{
		config:   cfg,
		cooldown: cooldown,
		lastFire: &sync.Map{},
	}
}

// GetEmailStats returns email alerting statistics.
func GetEmailStats() EmailStats {
	return EmailStats{
		Sent:   emailSent.Load(),
		Failed: emailFailed.Load(),
	}
}

// ResetEmailStats resets email statistics (for testing).
func ResetEmailStats() {
	emailSent.Store(0)
	emailFailed.Store(0)
}
