package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Compliance reporting was removed in v0.7.0. A config that still carries a
// compliance section must fail loudly instead of silently losing the feature.
func TestRemovedComplianceSectionIsRejected(t *testing.T) {
	if _, ok := reflect.TypeFor[Config]().FieldByName("Compliance"); ok {
		t.Fatal("Config.Compliance was re-introduced; compliance reporting was removed")
	}
	path := filepath.Join(t.TempDir(), "guardianwaf.yaml")
	if err := os.WriteFile(path, []byte("compliance:\n  enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "compliance: unknown top-level key") {
		t.Fatalf("LoadFile error = %v, want compliance: unknown top-level key", err)
	}
}
