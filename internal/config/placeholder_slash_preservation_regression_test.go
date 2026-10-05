package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlaceholderEscapedDefaultsSurviveSave(t *testing.T) {
	t.Setenv("GWAF_AUDIT_SUBJECT", "")
	for _, value := range []string{"ordinary", `C:\temp`, `C:\new\file`, `hello "world"`, `literal\t`} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		raw := "alerting:\n  emails:\n    - name: ops\n      subject: ${GWAF_AUDIT_SUBJECT:-" + value + "}\n"
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Alerting.Emails[0].Subject != value {
			t.Fatalf("input value %q", cfg.Alerting.Emails[0].Subject)
		}
		for range 2 {
			if err = SaveFile(path, cfg); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), "${GWAF_AUDIT_SUBJECT:-") {
				t.Fatal("binding was lost")
			}
			cfg, err = LoadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Alerting.Emails[0].Subject; got != value {
				t.Fatalf("got=%q want=%q", got, value)
			}
		}
	}
}
