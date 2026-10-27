package config

// Regression (round 2026-10-13-r17-maincfg-glob): the r2026-09-18 malformed
// glob fix probes patterns in parseRateLimitRule, which only the rules.d and
// virtual-host load paths reach (appendRulesFromDir, loadVirtualHostWAF).
// The MAIN config file path populates rules via defaults.go populateRateLimit
// (no probe) and validateRateLimit checked id/limit/window/scope/action but
// never the patterns — so a rule with a malformed glob in guardianwaf.yaml
// loaded cleanly and silently never fired at request time (ratelimit's
// matchPath maps path.Match errors to "no match"), disarming a DoS defense
// the operator believed was active. validateRateLimit now probes every
// rule's patterns, covering all load paths uniformly at validation time.
// The probe uses path.Match itself, so its accepted set (including quirks
// like reversed ranges [z-a]) cannot diverge from what the layer parses.

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRateLimitConfig(t *testing.T, name, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestValidateRateLimitMainConfigGlobProbe(t *testing.T) {
	malformed := writeRateLimitConfig(t, "malformed.yaml", `mode: enforce
listen: "127.0.0.1:8088"
waf:
  rate_limit:
    enabled: true
    rules:
      - id: api-limit
        scope: ip
        paths:
          - "/api/["
        limit: 100
        window: 1m
        action: block
`)
	cfg, err := LoadFile(malformed)
	if err != nil {
		t.Fatalf("load malformed config: %v", err)
	}
	if err := Validate(cfg); err == nil {
		t.Fatal("malformed rate-limit glob in the main config file validated cleanly — the rule would load and silently never apply at request time")
	}

	// Control: well-formed globs (prefix wildcard, literal) keep validating
	// cleanly through the same path.
	control := writeRateLimitConfig(t, "control.yaml", `mode: enforce
listen: "127.0.0.1:8088"
waf:
  rate_limit:
    enabled: true
    rules:
      - id: api-limit
        scope: ip
        paths:
          - "/api/*"
          - "/login"
        limit: 100
        window: 1m
        action: block
`)
	cfg, err = LoadFile(control)
	if err != nil {
		t.Fatalf("load control config: %v", err)
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("well-formed glob rejected by Validate: %v", err)
	}
}
