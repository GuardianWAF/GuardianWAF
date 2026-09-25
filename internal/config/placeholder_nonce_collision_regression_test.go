package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression (chimera round-25 review, SAGE 01M3CT7173ZGNC3W1RA4PDSY2N): the
// placeholder un-double pass ReplaceAlls the doubled Original over the WHOLE
// document, so an ordinary scalar whose doubled value merely CONTAINS that
// text gets partially un-doubled — and reload expands it.
func TestSaveFile_OrdinaryValueEmbeddingPlaceholderStaysLiteral(t *testing.T) {
	t.Setenv("GWAF_SMTP_PASSWORD", "s3cret-value")

	cfg := DefaultConfig()
	cfg.Alerting.Enabled = true
	cfg.Alerting.Emails = []EmailConfig{{
		Name:     "ops",
		SMTPHost: "smtp.example.com",
		Username: "ops",
		Password: "secret-from-env", // unchanged → placeholder binding
		Subject:  "GuardianWAF alert",
	}}
	cfg.Alerting.Webhooks = []WebhookConfig{{
		Name: "hook",
		URL:  "smtps://user:${GWAF_SMTP_PASSWORD}@host", // ordinary value EMBEDDING the placeholder text
	}}
	cfg.SetPlaceholderBindings(map[string]PlaceholderBinding{
		"alerting.emails[0].password": {Original: "${GWAF_SMTP_PASSWORD}", Resolved: "secret-from-env"},
	})

	path := filepath.Join(t.TempDir(), "guardianwaf.yaml")
	if err := SaveFile(path, cfg); err != nil {
		t.Fatalf("SaveFile() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)

	// The webhook URL is an ORDINARY value: it must stay dollar-doubled in
	// the file so reload preserves the literal text.
	if !strings.Contains(out, `url: "smtps://user:$${GWAF_SMTP_PASSWORD}@host"`) {
		t.Fatalf("FAIL: webhook URL was un-doubled by the placeholder restore (substring collision):\n%s", out)
	}

	// End-to-end: reload and compare. The literal URL survives; the
	// unchanged secret loads expanded with its placeholder re-captured as
	// the binding's Original (the documented load contract).
	cfg2, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if len(cfg2.Alerting.Webhooks) != 1 || cfg2.Alerting.Webhooks[0].URL != "smtps://user:${GWAF_SMTP_PASSWORD}@host" {
		t.Fatalf("FAIL: reloaded webhook URL corrupted: %q", cfg2.Alerting.Webhooks[0].URL)
	}
	if cfg2.Alerting.Emails[0].Password != "s3cret-value" {
		t.Fatalf("reloaded password changed: %q", cfg2.Alerting.Emails[0].Password)
	}
	if got := cfg2.placeholderBindings()["alerting.emails[0].password"].Original; got != "${GWAF_SMTP_PASSWORD}" {
		t.Fatalf("placeholder binding not re-captured: %q", got)
	}
}
