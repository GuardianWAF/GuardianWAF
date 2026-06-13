package main

import (
	"strings"
	"testing"
)

func TestSetupWizard_BuildConfig_Basic(t *testing.T) {
	w := newSetupWizard("test-api-key-123")
	w.listen = ":8088"
	w.mode = "enforce"
	w.tlsConfig = "\ntls:\n  enabled: false"
	w.numBackends = 1
	w.lb = "weighted"
	w.hcConfig = ""
	w.targets = []string{`      - url: "http://localhost:3000"
        weight: 1`}
	w.routeHost = "*"
	w.routePath = "/"
	w.blockThresh = "50"
	w.logThresh = "25"
	w.detectors = []string{"sqli", "xss"}
	w.detectorCfg = `      sqli:
        enabled: true
        multiplier: 1.0
      xss:
        enabled: true
        multiplier: 1.0`
	w.botConfig = "\n  bot_detection:\n    enabled: false"
	w.botEnabled = false
	w.rateLimitCfg = "\n  rate_limit:\n    enabled: false"
	w.rateLimitOn = false
	w.corsConfig = "\n  cors:\n  enabled: false"
	w.atoConfig = "\n  ato_protection:\n  enabled: false"
	w.alertConfig = "\nalerting:\n  enabled: false"
	w.alertEnabled = false
	w.dockerConfig = "\ndocker:\n  enabled: false"
	w.dockerEnabled = false
	w.dashboardListen = ":9443"
	w.rlAutoBan = false
	w.rlBanDur = "15m"

	cfg := w.buildConfig()

	// Verify key sections exist
	checks := []struct {
		name    string
		needle  string
		wantLen int
	}{
		{"mode", "mode: enforce", 1},
		{"listen", `listen: ":8088"`, 1},
		{"api_key", `api_key: "test-api-key-123"`, 1},
		{"dashboard_listen", `listen: ":9443"`, 1},
		{"block_threshold", "block: 50", 1},
		{"log_threshold", "log: 25", 1},
		{"detector_sqli", "sqli:", 1},
		{"detector_xss", "xss:", 1},
		{"bot_disabled", "bot_detection:\n    enabled: false", 1},
		{"rate_limit_disabled", "rate_limit:\n    enabled: false", 1},
		{"cors_disabled", "cors:\n  enabled: false", 1},
		{"alerting_disabled", "alerting:\n  enabled: false", 1},
		{"docker_disabled", "docker:\n  enabled: false", 1},
		{"mcp_enabled", "transport: stdio", 1},
		{"upstream_url", `url: "http://localhost:3000"`, 1},
		{"sanitizer_enabled", "sanitizer:", 1},
		{"ip_acl_enabled", "ip_acl:", 1},
		{"logging_section", "logging:", 1},
	}

	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			count := strings.Count(cfg, c.needle)
			if count != c.wantLen {
				t.Errorf("buildConfig() output: expected %d occurrence(s) of %q, got %d", c.wantLen, c.needle, count)
			}
		})
	}
}

func TestSetupWizard_BuildConfig_WithTLS(t *testing.T) {
	w := newSetupWizard("key123")
	w.listen = ":8088"
	w.mode = "enforce"
	w.tlsConfig = "\ntls:\n  enabled: true\n  listen: \":8443\""
	w.tlsListen = ":8443"
	w.numBackends = 1
	w.lb = "round_robin"
	w.hcConfig = ""
	w.targets = []string{`      - url: "http://backend:3000"
        weight: 1`}
	w.routePath = "/"
	w.blockThresh = "30"
	w.logThresh = "15"
	w.detectors = []string{"sqli"}
	w.detectorCfg = `      sqli:
        enabled: true
        multiplier: 1.0`
	w.botConfig = "\n  bot_detection:\n    enabled: true"
	w.rateLimitCfg = "\n  rate_limit:\n    enabled: true"
	w.corsConfig = "\n  cors:\n  enabled: true"
	w.atoConfig = "\n  ato_protection:\n  enabled: false"
	w.alertConfig = "\nalerting:\n  enabled: false"
	w.dockerConfig = "\ndocker:\n  enabled: false"
	w.dashboardListen = ":9443"
	w.rlAutoBan = true
	w.rlBanDur = "30m"

	cfg := w.buildConfig()

	if !strings.Contains(cfg, "enabled: true") {
		t.Error("expected TLS enabled in config output")
	}
	if !strings.Contains(cfg, "listen: \":8443\"") {
		t.Error("expected TLS listen address in config output")
	}
	if !strings.Contains(cfg, "round_robin") {
		t.Error("expected round_robin load balancer in config output")
	}
	if !strings.Contains(cfg, "block: 30") {
		t.Error("expected block threshold 30")
	}
	if !strings.Contains(cfg, "url: \"http://backend:3000\"") {
		t.Error("expected backend URL in config")
	}
	// auto_ban enabled true
	if !strings.Contains(cfg, "enabled: true") {
		t.Error("expected auto_ban enabled true")
	}
}

func TestNewSetupWizard_Defaults(t *testing.T) {
	w := newSetupWizard("pass123")
	if w.dashboardPassword != "pass123" {
		t.Errorf("expected password 'pass123', got %q", w.dashboardPassword)
	}
	if w.rlBanDur != "15m" {
		t.Errorf("expected default rlBanDur '15m', got %q", w.rlBanDur)
	}
}
