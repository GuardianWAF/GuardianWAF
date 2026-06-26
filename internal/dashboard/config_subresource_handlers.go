package dashboard

import (
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func (d *Dashboard) handleGetRateLimitConfig(w http.ResponseWriter, r *http.Request) {
	rl := d.engine.Config().WAF.RateLimit
	rules := make([]map[string]any, 0, len(rl.Rules))
	for _, rule := range rl.Rules {
		rules = append(rules, map[string]any{
			"id":             rule.ID,
			"scope":          rule.Scope,
			"paths":          rule.Paths,
			"limit":          rule.Limit,
			"window":         rule.Window.String(),
			"burst":          rule.Burst,
			"action":         rule.Action,
			"auto_ban_after": rule.AutoBanAfter,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": rl.Enabled,
		"rules":   rules,
	})
}

func (d *Dashboard) handleUpdateRateLimitConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled      *bool  `json:"enabled"`
		DefaultLimit int    `json:"default_limit"`
		Window       string `json:"window"`
		Burst        int    `json:"burst"`
		Action       string `json:"action"`
	}
	if !limitedDecodeJSON(w, r, &body) {
		return
	}

	cfg := deepCopyConfig(d.engine.Config())
	if body.Enabled != nil {
		cfg.WAF.RateLimit.Enabled = *body.Enabled
	}
	if body.DefaultLimit > 0 {
		ensureDefaultRateLimitRule(cfg)
		cfg.WAF.RateLimit.Rules[0].Limit = clampInt(body.DefaultLimit, 1, 1000000)
	}
	if body.Burst > 0 {
		ensureDefaultRateLimitRule(cfg)
		cfg.WAF.RateLimit.Rules[0].Burst = clampInt(body.Burst, 1, 1000000)
	}
	if body.Window != "" {
		window, err := time.ParseDuration(body.Window)
		if err != nil || window <= 0 {
			writeError(w, http.StatusBadRequest, "invalid window duration")
			return
		}
		ensureDefaultRateLimitRule(cfg)
		cfg.WAF.RateLimit.Rules[0].Window = window
	}
	if body.Action != "" {
		if body.Action != "block" && body.Action != "log" {
			writeError(w, http.StatusBadRequest, "invalid action")
			return
		}
		ensureDefaultRateLimitRule(cfg)
		cfg.WAF.RateLimit.Rules[0].Action = body.Action
	}

	if err := validateRuntimeReloadableConfig(d.engine.Config(), cfg); err != nil {
		writeError(w, http.StatusConflict, sanitizeErr(err))
		return
	}

	if err := d.engine.Reload(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleGetBotConfig(w http.ResponseWriter, r *http.Request) {
	bot := d.engine.Config().WAF.BotDetection
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": bot.Enabled,
		"mode":    bot.Mode,
		"tls_fingerprint": map[string]any{
			"enabled":           bot.TLSFingerprint.Enabled,
			"known_bots_action": bot.TLSFingerprint.KnownBotsAction,
			"unknown_action":    bot.TLSFingerprint.UnknownAction,
			"mismatch_action":   bot.TLSFingerprint.MismatchAction,
		},
		"user_agent": map[string]any{
			"enabled":              bot.UserAgent.Enabled,
			"block_empty":          bot.UserAgent.BlockEmpty,
			"block_known_scanners": bot.UserAgent.BlockKnownScanners,
		},
		"behavior": map[string]any{
			"enabled":              bot.Behavior.Enabled,
			"window":               bot.Behavior.Window.String(),
			"rps_threshold":        bot.Behavior.RPSThreshold,
			"error_rate_threshold": bot.Behavior.ErrorRateThreshold,
		},
	})
}

func (d *Dashboard) handleUpdateBotConfig(w http.ResponseWriter, r *http.Request) {
	var patch map[string]any
	if !limitedDecodeJSON(w, r, &patch) {
		return
	}
	cfg := deepCopyConfig(d.engine.Config())
	applyWAFPatch(cfg, map[string]any{"bot_detection": patch})
	if err := validateRuntimeReloadableConfig(d.engine.Config(), cfg); err != nil {
		writeError(w, http.StatusConflict, sanitizeErr(err))
		return
	}
	if err := d.engine.Reload(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleUploadCertificateCompat(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Cert string `json:"cert"`
		Key  string `json:"key"`
	}
	if !limitedDecodeJSON(w, r, &body) {
		return
	}
	if body.Name == "" || body.Cert == "" || body.Key == "" {
		writeError(w, http.StatusBadRequest, "name, cert, and key are required")
		return
	}
	certBytes, err := base64.StdEncoding.DecodeString(body.Cert)
	if err != nil {
		writeError(w, http.StatusBadRequest, "cert must be base64 encoded PEM")
		return
	}
	keyBytes, err := base64.StdEncoding.DecodeString(body.Key)
	if err != nil {
		writeError(w, http.StatusBadRequest, "key must be base64 encoded PEM")
		return
	}
	certBlock, _ := pem.Decode(certBytes)
	keyBlock, _ := pem.Decode(keyBytes)
	if certBlock == nil || keyBlock == nil {
		writeError(w, http.StatusBadRequest, "cert and key must decode to PEM blocks")
		return
	}
	writeError(w, http.StatusNotImplemented, "certificate storage backend is not configured")
}

func (d *Dashboard) handleDeleteCertificateCompat(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "certificate not found")
}

func ensureDefaultRateLimitRule(cfg *config.Config) {
	if len(cfg.WAF.RateLimit.Rules) == 0 {
		cfg.WAF.RateLimit.Rules = append(cfg.WAF.RateLimit.Rules, config.RateLimitRule{
			ID:     "default",
			Scope:  "ip",
			Limit:  100,
			Window: time.Minute,
			Burst:  20,
			Action: "block",
		})
	}
}
