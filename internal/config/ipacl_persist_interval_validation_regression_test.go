package config

// Regression (new-series round 10): a NEGATIVE auto-ban persist interval was
// accepted by config validation.
//
// waf.ip_acl.auto_ban.persist_interval is an operator-supplied duration. The
// IP-ACL layer starts its ban-persistence goroutine with it
// (internal/layers/ipacl/ipacl.go:99) and only floored a ZERO value, so a
// negative interval reached time.NewTicker — which panics on a non-positive
// duration — inside an unrecovered goroutine, taking the whole WAF process
// down at startup instead of the configuration being refused.
//
// Every comparable bound in this repo refuses a negative value:
// validateAIAnalysis rejects auto_block_ttl < 0, validateIPACL rejects
// auto_ban.default_ttl <= 0, and the dashboard rejects a non-positive ban
// duration outright. The persist interval was the one bound with neither a
// validation nor a floor.
//
// This test drives the production path: a YAML file -> config.LoadFile ->
// config.Validate, the same path `guardianwaf serve` runs at startup
// (cmd/guardianwaf/main.go:227).

import (
	"os"
	"path/filepath"
	"testing"
)

const ipaclPersistIntervalYAML = `
waf:
  ip_acl:
    enabled: true
    auto_ban:
      enabled: true
      default_ttl: 1h
      persist_path: /tmp/gwaf-proof-bans.json
`

func writeIPACLPersistIntervalConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "guardianwaf.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

func TestIPACLPersistIntervalValidation(t *testing.T) {
	// A negative persist interval must be refused with a clear configuration
	// error instead of being accepted and crashing the process.
	t.Run("negative persist interval is rejected", func(t *testing.T) {
		cfg, err := LoadFile(writeIPACLPersistIntervalConfig(t, ipaclPersistIntervalYAML+"      persist_interval: -5s\n"))
		if err != nil {
			t.Fatalf("the config did not load: %v", err)
		}
		if got := cfg.WAF.IPACL.AutoBan.PersistInterval; got >= 0 {
			t.Fatalf("the negative persist_interval was not parsed (got %v) — the fixture "+
				"cannot prove the defect", got)
		}
		if err := Validate(cfg); err == nil {
			t.Fatalf("a negative waf.ip_acl.auto_ban.persist_interval (%v) was accepted by "+
				"config validation; it reaches time.NewTicker in the ban-persistence loop and "+
				"panics the process", cfg.WAF.IPACL.AutoBan.PersistInterval)
		}
	})

	// A positive interval stays valid — the check cannot pass merely because
	// the field is rejected wholesale.
	t.Run("positive persist interval is accepted", func(t *testing.T) {
		cfg, err := LoadFile(writeIPACLPersistIntervalConfig(t, ipaclPersistIntervalYAML+"      persist_interval: 45s\n"))
		if err != nil {
			t.Fatalf("control: the config did not load: %v", err)
		}
		if err := Validate(cfg); err != nil {
			t.Fatalf("control: a positive persist_interval was rejected: %v", err)
		}
		if got := cfg.WAF.IPACL.AutoBan.PersistInterval; got.String() != "45s" {
			t.Fatalf("control: the persist interval was not parsed as 45s (got %v)", got)
		}
	})

	// An UNSET interval stays valid — 0 means "unset, use the layer default",
	// not "invalid".
	t.Run("unset persist interval is accepted", func(t *testing.T) {
		cfg, err := LoadFile(writeIPACLPersistIntervalConfig(t, ipaclPersistIntervalYAML))
		if err != nil {
			t.Fatalf("control: the config did not load: %v", err)
		}
		if err := Validate(cfg); err != nil {
			t.Fatalf("control: an unset persist_interval was rejected: %v", err)
		}
	})
}
