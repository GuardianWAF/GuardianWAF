package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFile_CapturesPlaceholderBindings(t *testing.T) {
	t.Setenv("GWAF_SMTP_PASSWORD", "secret-from-env")
	dir := t.TempDir()
	path := filepath.Join(dir, "guardianwaf.yaml")
	content := strings.Join([]string{
		"mode: enforce",
		"alerting:",
		"  emails:",
		"    - name: ops",
		"      smtp_host: smtp.example.com",
		"      from: ops@example.com",
		"      to: [team@example.com]",
		"      password: ${GWAF_SMTP_PASSWORD}",
		"      subject: ${GWAF_SUBJECT:-GuardianWAF alert}",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	bindings := cfg.placeholderBindings()
	if got := bindings["alerting.emails[0].password"]; got.Original != "${GWAF_SMTP_PASSWORD}" || got.Resolved != "secret-from-env" {
		t.Fatalf("password binding = %#v", got)
	}
	if got := bindings["alerting.emails[0].subject"]; got.Original != "${GWAF_SUBJECT:-GuardianWAF alert}" || got.Resolved != "GuardianWAF alert" {
		t.Fatalf("subject binding = %#v", got)
	}
}

func TestSaveFile_PreservesPlaceholderWhenValueUnchanged(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Alerting.Enabled = true
	cfg.Alerting.Emails = []EmailConfig{{
		Name:     "ops",
		SMTPHost: "smtp.example.com",
		From:     "ops@example.com",
		To:       []string{"team@example.com"},
		Password: "secret-from-env",
		Subject:  "GuardianWAF alert",
	}}
	cfg.SetPlaceholderBindings(map[string]PlaceholderBinding{
		"alerting.emails[0].password": {Original: "${GWAF_SMTP_PASSWORD}", Resolved: "secret-from-env"},
		"alerting.emails[0].subject":  {Original: "${GWAF_SUBJECT:-GuardianWAF alert}", Resolved: "GuardianWAF alert"},
	})

	path := filepath.Join(t.TempDir(), "guardianwaf.yaml")
	if err := SaveFile(path, cfg); err != nil {
		t.Fatalf("SaveFile() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	out := string(data)
	if !strings.Contains(out, `password: "${GWAF_SMTP_PASSWORD}"`) {
		t.Fatalf("saved YAML did not preserve password placeholder:\n%s", out)
	}
	if !strings.Contains(out, `subject: "${GWAF_SUBJECT:-GuardianWAF alert}"`) {
		t.Fatalf("saved YAML did not preserve subject placeholder:\n%s", out)
	}
}

func TestSaveFile_DoesNotRestorePlaceholderAfterIntentionalEdit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Alerting.Enabled = true
	cfg.Alerting.Emails = []EmailConfig{{
		Name:     "ops",
		SMTPHost: "smtp.example.com",
		From:     "ops@example.com",
		To:       []string{"team@example.com"},
		Password: "manually-updated",
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
		t.Fatalf("ReadFile() error = %v", err)
	}
	out := string(data)
	if strings.Contains(out, "${GWAF_SMTP_PASSWORD}") {
		t.Fatalf("saved YAML incorrectly restored old placeholder after edit:\n%s", out)
	}
	if !strings.Contains(out, `password: manually-updated`) {
		t.Fatalf("saved YAML lost edited password value:\n%s", out)
	}
}
