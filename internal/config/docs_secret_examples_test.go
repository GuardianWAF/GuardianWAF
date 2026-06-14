package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicAPIExamplesAvoidWeakDashboardKeyLiterals(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "api-examples.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(data)

	for _, weak := range []string{
		"secret123",
		"X-API-Key: secret",
		"'your-api-key'",
		"\"your-api-key\"",
	} {
		if strings.Contains(content, weak) {
			t.Fatalf("%s contains weak dashboard API key example %q; use GWAF_DASHBOARD_API_KEY instead", path, weak)
		}
	}

	if !strings.Contains(content, "GWAF_DASHBOARD_API_KEY") {
		t.Fatalf("%s must demonstrate reading dashboard API keys from GWAF_DASHBOARD_API_KEY", path)
	}
}

func TestConfigurationDocsWarnBeforeBodyLogging(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "configuration.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(data)
	for _, want := range []string{
		"log_body: false",
		"Security risk",
		"credentials/PII",
		"controlled environment",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("%s missing body logging warning %q", path, want)
		}
	}
}
