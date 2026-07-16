package dashboard

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/alerting"
	"github.com/guardianwaf/guardianwaf/internal/config"
)

// --- Alerting Handlers ---

func (d *Dashboard) handleAlertingStatus(w http.ResponseWriter, r *http.Request) {
	cfg := d.engine.Config()
	webhooks := make([]any, 0, len(cfg.Alerting.Webhooks))
	for _, w := range cfg.Alerting.Webhooks {
		webhooks = append(webhooks, map[string]any{
			"name":      w.Name,
			"url":       maskURL(w.URL),
			"type":      w.Type,
			"events":    w.Events,
			"min_score": w.MinScore,
			"cooldown":  w.Cooldown.String(),
		})
	}
	emails := make([]any, 0, len(cfg.Alerting.Emails))
	for _, e := range cfg.Alerting.Emails {
		emails = append(emails, map[string]any{
			"name":      e.Name,
			"smtp_host": e.SMTPHost,
			"smtp_port": e.SMTPPort,
			"from":      e.From,
			"use_tls":   e.UseTLS,
			"events":    e.Events,
			"min_score": e.MinScore,
			"cooldown":  e.Cooldown.String(),
		})
	}

	result := map[string]any{
		"enabled":       cfg.Alerting.Enabled,
		"webhook_count": len(cfg.Alerting.Webhooks),
		"email_count":   len(cfg.Alerting.Emails),
		"webhooks":      webhooks,
		"emails":        emails,
	}

	if d.alertingStats != nil {
		stats := d.alertingStats.GetAlertingStats()
		if s, ok := stats.(map[string]any); ok {
			result["sent"] = s["sent"]
			result["failed"] = s["failed"]
		}
	}

	writeJSON(w, http.StatusOK, result)
}

func (d *Dashboard) handleGetWebhooks(w http.ResponseWriter, r *http.Request) {
	cfg := d.engine.Config()
	webhooks := make([]any, 0, len(cfg.Alerting.Webhooks))
	for _, w := range cfg.Alerting.Webhooks {
		webhooks = append(webhooks, map[string]any{
			"name":      w.Name,
			"url":       maskURL(w.URL),
			"type":      w.Type,
			"events":    w.Events,
			"min_score": w.MinScore,
			"cooldown":  w.Cooldown.String(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"webhooks": webhooks})
}

func (d *Dashboard) handleAddWebhook(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string            `json:"name"`
		URL      string            `json:"url"`
		Type     string            `json:"type"`
		Events   []string          `json:"events"`
		MinScore int               `json:"min_score"`
		Cooldown string            `json:"cooldown"`
		Headers  map[string]string `json:"headers"`
	}
	if !limitedDecodeJSON(w, r, &body) {
		return
	}
	if body.Name == "" || body.URL == "" {
		writeError(w, http.StatusBadRequest, "name and url are required")
		return
	}

	// Validate webhook URL to prevent SSRF (reject private/loopback IPs)
	if err := alerting.ValidateWebhookURL(body.URL); err != nil {
		writeError(w, http.StatusBadRequest, sanitizeErr(err))
		return
	}

	cooldown, err := time.ParseDuration(body.Cooldown)
	if err != nil && body.Cooldown != "" {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid cooldown duration: %q", body.Cooldown))
		return
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}

	if !d.reloadAndPersist(w, func(cfg *config.Config) {
		cfg.Alerting.Webhooks = append(cfg.Alerting.Webhooks, config.WebhookConfig{
			Name:     body.Name,
			URL:      body.URL,
			Type:     body.Type,
			Events:   body.Events,
			MinScore: body.MinScore,
			Cooldown: cooldown,
			Headers:  body.Headers,
		})
	}) {
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "name": body.Name})
}

func (d *Dashboard) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Check existence first for proper 404
	current := d.engine.Config()
	exists := false
	for _, wh := range current.Alerting.Webhooks {
		if wh.Name == name {
			exists = true
			break
		}
	}
	if !exists {
		writeError(w, http.StatusNotFound, "webhook not found")
		return
	}

	if !d.reloadAndPersist(w, func(cfg *config.Config) {
		for i, wh := range cfg.Alerting.Webhooks {
			if wh.Name == name {
				cfg.Alerting.Webhooks = append(cfg.Alerting.Webhooks[:i], cfg.Alerting.Webhooks[i+1:]...)
				return
			}
		}
	}) {
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleGetEmails(w http.ResponseWriter, r *http.Request) {
	cfg := d.engine.Config()
	emails := make([]any, 0, len(cfg.Alerting.Emails))
	for _, e := range cfg.Alerting.Emails {
		emails = append(emails, map[string]any{
			"name":      e.Name,
			"smtp_host": e.SMTPHost,
			"smtp_port": e.SMTPPort,
			"from":      e.From,
			"to":        e.To,
			"use_tls":   e.UseTLS,
			"events":    e.Events,
			"min_score": e.MinScore,
			"cooldown":  e.Cooldown.String(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"emails": emails})
}

func (d *Dashboard) handleAddEmail(w http.ResponseWriter, r *http.Request) {
	var body struct {
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
		Cooldown string   `json:"cooldown"`
		Subject  string   `json:"subject"`
		Template string   `json:"template"`
	}
	if !limitedDecodeJSON(w, r, &body) {
		return
	}
	if body.Name == "" || body.SMTPHost == "" || body.From == "" || len(body.To) == 0 {
		writeError(w, http.StatusBadRequest, "name, smtp_host, from, and to are required")
		return
	}

	cooldown, err := time.ParseDuration(body.Cooldown)
	if err != nil && body.Cooldown != "" {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid cooldown duration: %q", body.Cooldown))
		return
	}
	if cooldown <= 0 {
		cooldown = 5 * time.Minute
	}

	if !d.reloadAndPersist(w, func(cfg *config.Config) {
		cfg.Alerting.Emails = append(cfg.Alerting.Emails, config.EmailConfig{
			Name:     body.Name,
			SMTPHost: body.SMTPHost,
			SMTPPort: body.SMTPPort,
			Username: body.Username,
			Password: body.Password,
			From:     body.From,
			To:       body.To,
			UseTLS:   body.UseTLS,
			Events:   body.Events,
			MinScore: body.MinScore,
			Cooldown: cooldown,
			Subject:  body.Subject,
			Template: body.Template,
		})
	}) {
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "name": body.Name})
}

func (d *Dashboard) handleDeleteEmail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Check existence first for proper 404
	current := d.engine.Config()
	exists := false
	for _, em := range current.Alerting.Emails {
		if em.Name == name {
			exists = true
			break
		}
	}
	if !exists {
		writeError(w, http.StatusNotFound, "email target not found")
		return
	}

	if !d.reloadAndPersist(w, func(cfg *config.Config) {
		for i, em := range cfg.Alerting.Emails {
			if em.Name == name {
				cfg.Alerting.Emails = append(cfg.Alerting.Emails[:i], cfg.Alerting.Emails[i+1:]...)
				return
			}
		}
	}) {
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleTestAlert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target string `json:"target"`
	}
	if !limitedDecodeJSON(w, r, &body) || body.Target == "" {
		writeError(w, http.StatusBadRequest, "target is required")
		return
	}

	// This would ideally call the alerting manager's TestAlert method
	// For now, we just return a success message
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Test alert functionality requires MCP or direct alerting manager access"})
}

// reloadAndPersist applies a config mutation, reloads the engine, and persists
// to disk. Returns true on success, false on failure (error already written to w).
// The caller must provide a function that mutates the deep-copied config.
func (d *Dashboard) reloadAndPersist(w http.ResponseWriter, mutate func(cfg *config.Config)) bool {
	oldCfg := d.engine.Config()
	cfg := deepCopyConfig(oldCfg)
	mutate(cfg)

	if err := d.engine.Reload(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return false
	}

	if d.routingCtrl != nil {
		if err := d.routingCtrl.Save(); err != nil {
			if rollbackErr := d.engine.Reload(oldCfg); rollbackErr != nil {
				dashboardLog.Error("configuration mutation persistence and rollback failed", "save_error", err, "rollback_error", rollbackErr)
			} else {
				dashboardLog.Error("configuration mutation persistence failed; runtime rolled back", "error", err)
			}
			writeError(w, http.StatusInternalServerError, "configuration persistence failed; previous runtime configuration restored")
			return false
		}
	}
	return true
}

// maskURL masks sensitive parts of a URL, showing only scheme and host.
// e.g. "https://user:pass@hooks.example.com/v1/secret?token=abc" → "https://hooks.example.com"
func maskURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "***"
	}
	return u.Scheme + "://" + u.Host
}
