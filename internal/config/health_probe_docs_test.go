package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHealthProbeDocsCoverProfileReadinessPolicy(t *testing.T) {
	root := filepath.Join("..", "..")
	profiles, err := filepath.Glob(filepath.Join(root, "examples", "profiles", "*.yaml"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(profiles) == 0 {
		t.Fatal("no production config profiles found")
	}

	data, err := os.ReadFile(filepath.Join(root, "docs", "health-probes.md"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(data)

	required := []string{
		"## Profile Readiness Policy",
		"`/livez` for process restart decisions",
		"`/readyz` for traffic admission",
		"dashboard.enabled: true",
		"waf.geoip.require_ready: true",
		"config load",
		"engine startup",
		"event-store startup",
		"router construction",
		"upstream health",
		"Do not make outbound integrations",
	}
	for _, want := range required {
		if !strings.Contains(content, want) {
			t.Fatalf("docs/health-probes.md missing readiness policy text %q", want)
		}
	}

	for _, profile := range profiles {
		name := filepath.Base(profile)
		if !strings.Contains(content, "`"+name+"`") {
			t.Fatalf("docs/health-probes.md missing profile readiness policy for %s", name)
		}
	}
}
