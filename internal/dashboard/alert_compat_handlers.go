package dashboard

import "net/http"

func (d *Dashboard) handleAlertsCompat(w http.ResponseWriter, r *http.Request) {
	cfg := d.engine.Config()
	alerts := make([]any, 0, len(cfg.Alerting.Webhooks)+len(cfg.Alerting.Emails))
	for _, webhook := range cfg.Alerting.Webhooks {
		alerts = append(alerts, map[string]any{
			"name":      webhook.Name,
			"type":      "webhook",
			"target":    webhook.Type,
			"enabled":   true,
			"events":    webhook.Events,
			"min_score": webhook.MinScore,
			"cooldown":  webhook.Cooldown.String(),
		})
	}
	for _, email := range cfg.Alerting.Emails {
		alerts = append(alerts, map[string]any{
			"name":      email.Name,
			"type":      "email",
			"target":    email.SMTPHost,
			"enabled":   true,
			"events":    email.Events,
			"min_score": email.MinScore,
			"cooldown":  email.Cooldown.String(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}

func (d *Dashboard) handleAddAlertCompat(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusBadRequest, "use /api/v1/alerting/webhooks or /api/v1/alerting/emails with a concrete alert target")
}

func (d *Dashboard) handleUpdateAlertCompat(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "alert not found")
}

func (d *Dashboard) handleDeleteAlertCompat(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "alert not found")
}

func (d *Dashboard) handleAlertHistoryCompat(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"history": []any{}})
}
