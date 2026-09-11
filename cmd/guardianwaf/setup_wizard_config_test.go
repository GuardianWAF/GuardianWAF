package main

// Regression tests for round 18/25: the setup wizard's CORS and ATO section
// templates were mis-indented — `cors:` / `ato_protection:` at 2 spaces with
// their `enabled:` keys at the same indent, so YAML parsed them as siblings
// and `enabled`, `allow_origins`, `brute_force`, ... escaped to the `waf:`
// level, where populateWAF's strict-key check rejected the whole config: any
// daemon started with CORS or ATO enabled through the wizard failed at
// config load. The templates now live in corsConfigYAML/atoConfigYAML so
// tests can assert the generated YAML end-to-end through buildConfig and
// the real loader (config.LoadFile).

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func wizardConfigFixture(t *testing.T, cors, ato string) string {
	t.Helper()
	w := newSetupWizard("proof-password-12345")
	w.listen = "0.0.0.0:8088"
	w.mode = "enforce"
	w.tlsConfig = "\ntls:\n  enabled: false"
	w.numBackends = 1
	w.targets = []string{"      - url: \"http://127.0.0.1:3000\"\n        weight: 1"}
	w.lb = "weighted"
	w.routePath = "/"
	w.blockThresh = "50"
	w.logThresh = "25"
	w.detectorCfg = "      sqli:\n        enabled: true\n        multiplier: 1.0"
	w.botConfig = "\n  bot_detection:\n    enabled: true\n    mode: block"
	w.rateLimitCfg = "\n  rate_limit:\n    enabled: true\n    rules:\n      - id: global\n        scope: ip\n        limit: 100\n        window: 1m\n        burst: 20\n        action: block"
	w.corsConfig = cors
	w.atoConfig = ato
	w.alertConfig = "\nalerting:\n  enabled: false"
	w.dockerConfig = "\ndocker:\n  enabled: false"
	w.dashboardListen = "0.0.0.0:9443"

	yamlOut := w.buildConfig()
	tmp := filepath.Join(t.TempDir(), "gwaf-wizard.yaml")
	if err := os.WriteFile(tmp, []byte(yamlOut), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return tmp
}

func TestWizardGeneratedConfigLoadsAndCarriesCORSAndATO(t *testing.T) {
	tmp := wizardConfigFixture(t,
		corsConfigYAML("https://app.example.com", "GET,POST"),
		atoConfigYAML("5", "10m", "30m"))

	loaded, err := config.LoadFile(tmp)
	if err != nil {
		yamlOut, _ := os.ReadFile(tmp)
		t.Fatalf("wizard-generated config must load: %v\n--- generated ---\n%s", err, yamlOut)
	}
	if !loaded.WAF.CORS.Enabled {
		t.Fatalf("FAIL cors-discarded: waf.cors.enabled is false — the CORS section is not reaching the parsed config")
	}
	foundOrigin := false
	for _, o := range loaded.WAF.CORS.AllowOrigins {
		if o == "https://app.example.com" {
			foundOrigin = true
		}
	}
	if !foundOrigin {
		t.Fatalf("FAIL cors-origins-lost: allow_origins = %v", loaded.WAF.CORS.AllowOrigins)
	}
	if loaded.WAF.CORS.MaxAgeSeconds != 86400 {
		t.Fatalf("FAIL cors-maxage-lost: max_age_seconds = %d, want 86400", loaded.WAF.CORS.MaxAgeSeconds)
	}
	if !loaded.WAF.ATOProtection.Enabled {
		t.Fatalf("FAIL ato-discarded: waf.ato_protection.enabled is false — the ATO section is not reaching the parsed config")
	}
	if loaded.WAF.ATOProtection.BruteForce.MaxAttemptsPerIP != 5 {
		t.Fatalf("FAIL ato-maxattempts-lost: brute_force.max_attempts_per_ip = %d, want 5", loaded.WAF.ATOProtection.BruteForce.MaxAttemptsPerIP)
	}
	if loaded.WAF.ATOProtection.BruteForce.BlockDuration != 30*time.Minute {
		t.Fatalf("FAIL ato-blockduration-lost: brute_force.block_duration = %v, want 30m", loaded.WAF.ATOProtection.BruteForce.BlockDuration)
	}
}

func TestWizardDisabledCORSAndATOParseCleanly(t *testing.T) {
	tmp := wizardConfigFixture(t, "\n  cors:\n    enabled: false", "\n  ato_protection:\n    enabled: false")

	loaded, err := config.LoadFile(tmp)
	if err != nil {
		t.Fatalf("disabled-section wizard config must load: %v", err)
	}
	if loaded.WAF.CORS.Enabled {
		t.Fatalf("FAIL cors-unexpectedly-enabled")
	}
	if loaded.WAF.ATOProtection.Enabled {
		t.Fatalf("FAIL ato-unexpectedly-enabled")
	}
}
