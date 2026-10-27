package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDirPropagatesOptionalDirectoryReadErrors(t *testing.T) {
	for _, subdir := range []string{"rules.d", "domains.d", "tenants.d"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, subdir), []byte("not a directory"), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadDir(dir)
		if cfg != nil || err == nil || !strings.Contains(err.Error(), subdir) {
			t.Fatalf("%s EXPECTED: named read error, nil config | ACTUAL: %v, nil=%v", subdir, err, cfg == nil)
		}
		var pathErr *os.PathError
		if !errors.As(err, &pathErr) {
			t.Fatalf("lost underlying filesystem error: %v", err)
		}
	}
	for _, name := range []string{"absent", "empty", "populated"} {
		dir := t.TempDir()
		if name != "absent" {
			if err := os.Mkdir(filepath.Join(dir, "rules.d"), 0700); err != nil {
				t.Fatal(err)
			}
		}
		if name == "populated" {
			if err := os.WriteFile(filepath.Join(dir, "rules.d", "example.yaml"), []byte("ipacl:\n  blacklist: [192.0.2.1]\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		cfg, err := LoadDir(dir)
		if err != nil || cfg == nil {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "populated" && len(cfg.WAF.IPACL.Blacklist) != 1 {
			t.Fatalf("rules not loaded: %v", cfg.WAF.IPACL.Blacklist)
		}
	}
}
