package config

import (
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestLoadEnvRejectsInvalidTypedOverrides(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{name: "boolean", key: "GWAF_TLS_ENABLED", value: "tru", want: "must be a valid boolean"},
		{name: "alerting boolean", key: "GWAF_ALERTING_ENABLED", value: "perhaps", want: "must be a valid boolean"},
		{name: "integer", key: "GWAF_EVENTS_MAX_EVENTS", value: "many", want: "must be a valid integer"},
		{name: "number", key: "GWAF_TRACING_SAMPLING_RATE", value: "half", want: "must be a valid number"},
		{name: "NaN", key: "GWAF_TRACING_SAMPLING_RATE", value: "NaN", want: "must be a valid number"},
		{name: "infinity", key: "GWAF_TRACING_SAMPLING_RATE", value: "+Inf", want: "must be a valid number"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			t.Setenv(tt.key, tt.value)

			err := LoadEnv(cfg)
			if err == nil {
				t.Fatalf("LoadEnv() accepted invalid %s override", tt.key)
			}
			if !strings.Contains(err.Error(), tt.key) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("LoadEnv() error = %q, want field %q and message %q", err, tt.key, tt.want)
			}
		})
	}
}

func TestLoadEnvAppliesDocumentedListAndAlertingOverrides(t *testing.T) {
	cfg := DefaultConfig()
	t.Setenv("GWAF_TRUSTED_PROXIES", "10.0.0.0/8, 192.0.2.10 ,, ")
	t.Setenv("GWAF_ALERTING_ENABLED", "true")

	if err := LoadEnv(cfg); err != nil {
		t.Fatalf("LoadEnv() error = %v", err)
	}
	if got, want := strings.Join(cfg.TrustedProxies, ","), "10.0.0.0/8,192.0.2.10"; got != want {
		t.Fatalf("TrustedProxies = %q, want %q", got, want)
	}
	if !cfg.Alerting.Enabled {
		t.Fatal("Alerting.Enabled = false, want true")
	}
}

func TestLoadEnvInvalidOverrideIsAtomic(t *testing.T) {
	cfg := DefaultConfig()
	originalMode := cfg.Mode
	originalTLS := cfg.TLS.Enabled
	t.Setenv("GWAF_MODE", "monitor")
	t.Setenv("GWAF_TLS_ENABLED", "tru")

	if err := LoadEnv(cfg); err == nil {
		t.Fatal("LoadEnv() accepted an invalid typed override")
	}
	if cfg.Mode != originalMode {
		t.Fatalf("Mode changed to %q despite rejected environment overlay", cfg.Mode)
	}
	if cfg.TLS.Enabled != originalTLS {
		t.Fatalf("TLS enabled changed to %t despite rejected environment overlay", cfg.TLS.Enabled)
	}
}

func TestLoadEnvNilConfig(t *testing.T) {
	if err := LoadEnv(nil); err == nil {
		t.Fatal("LoadEnv(nil) returned no error")
	}
}

func TestValidateRejectsInvalidTracingConfiguration(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*TracingConfig)
		want      string
	}{
		{name: "NaN rate", configure: func(c *TracingConfig) { c.SamplingRate = math.NaN() }, want: "tracing.sampling_rate"},
		{name: "infinite rate", configure: func(c *TracingConfig) { c.SamplingRate = math.Inf(1) }, want: "tracing.sampling_rate"},
		{name: "negative rate", configure: func(c *TracingConfig) { c.SamplingRate = -0.1 }, want: "tracing.sampling_rate"},
		{name: "oversized rate", configure: func(c *TracingConfig) { c.SamplingRate = 1.1 }, want: "tracing.sampling_rate"},
		{name: "unsupported exporter", configure: func(c *TracingConfig) { c.ExporterType = "otlp" }, want: "tracing.exporter_type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.configure(&cfg.Tracing)
			err := Validate(cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want %s", err, tt.want)
			}
		})
	}
}

func TestValidateNilConfig(t *testing.T) {
	if err := Validate(nil); err == nil {
		t.Fatal("Validate(nil) returned no error")
	}
}

func TestDocumentedEnvironmentOverrideContractMatchesRuntime(t *testing.T) {
	validateSource, err := os.ReadFile("validate.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(validateSource)
	mapStart := strings.Index(source, "envMap := map[string]func(string){")
	if mapStart < 0 {
		t.Fatal("could not locate LoadEnv runtime map")
	}
	mapEnd := strings.Index(source[mapStart:], "\n\tfor key, setter := range envMap")
	if mapEnd < 0 {
		t.Fatal("could not locate the end of the LoadEnv runtime map")
	}
	runtimeBlock := source[mapStart : mapStart+mapEnd]

	docPath := filepath.Join("..", "..", "docs", "configuration.md")
	docBytes, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(docBytes)
	docStart := strings.Index(doc, "## Environment Variable Overrides")
	if docStart < 0 {
		t.Fatal("could not locate documented environment override table")
	}
	docEnd := strings.Index(doc[docStart:], "## Migrating Legacy Config Keys")
	if docEnd < 0 {
		t.Fatal("could not locate the end of the documented environment override table")
	}
	docBlock := doc[docStart : docStart+docEnd]

	keyPattern := regexp.MustCompile(`GWAF_[A-Z0-9_]+`)
	runtimeKeys := uniqueSortedStrings(keyPattern.FindAllString(runtimeBlock, -1))
	documentedKeys := uniqueSortedStrings(keyPattern.FindAllString(docBlock, -1))
	if strings.Join(runtimeKeys, "\n") != strings.Join(documentedKeys, "\n") {
		t.Fatalf("documented environment overrides do not match runtime\nruntime: %v\ndocumented: %v", runtimeKeys, documentedKeys)
	}
}

func TestPrimaryOperatorDocsRejectUnsupportedEnvironmentNames(t *testing.T) {
	root := filepath.Join("..", "..")
	checks := map[string][]string{
		"docs/production-deployment.md":   {"GWAF_LOG_LEVEL"},
		"docs/security-best-practices.md": {"GWAF_LOG_LEVEL"},
		"docs/api-examples.md":            {"GWAF_MCP_API_KEY"},
		"docker-compose.prod.yml":         {"GWAF_DOCKER_TLS"},
	}
	for relativePath, unsupported := range checks {
		content, err := os.ReadFile(filepath.Join(root, relativePath))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range unsupported {
			if strings.Contains(string(content), name) {
				t.Errorf("%s documents unsupported environment variable %s", relativePath, name)
			}
		}
	}
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
