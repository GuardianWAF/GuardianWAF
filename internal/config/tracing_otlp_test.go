package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTracingOTLPConfigLoadsFromYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardianwaf.yaml")
	yaml := `tracing:
  enabled: true
  exporter_type: otlp
  otlp:
    endpoint: https://otel-collector.observability:4318/v1/traces
    headers:
      Authorization: "Bearer abc"
    timeout: 3s
    batch_size: 256
    flush_interval: 2s
    queue_size: 4096
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	o := cfg.Tracing.OTLP
	if o.Endpoint != "https://otel-collector.observability:4318/v1/traces" || o.Headers["Authorization"] != "Bearer abc" ||
		o.Timeout != 3*time.Second || o.BatchSize != 256 || o.FlushInterval != 2*time.Second || o.QueueSize != 4096 {
		t.Fatalf("tracing.otlp loaded as %+v", o)
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	copied := cfg.DeepCopy()
	copied.Tracing.OTLP.Headers["Authorization"] = "changed"
	if cfg.Tracing.OTLP.Headers["Authorization"] != "Bearer abc" {
		t.Fatal("DeepCopy shares the OTLP headers map")
	}
}

func TestTracingOTLPEnvOverrides(t *testing.T) {
	cfg := DefaultConfig()
	t.Setenv("GWAF_TRACING_EXPORTER_TYPE", "otlp")
	t.Setenv("GWAF_TRACING_OTLP_ENDPOINT", "http://127.0.0.1:4318/v1/traces")
	t.Setenv("GWAF_TRACING_OTLP_HEADERS", "x-api-key=k1, x-tenant = a%2Cb ,malformed")
	if err := LoadEnv(cfg); err != nil {
		t.Fatal(err)
	}
	o := cfg.Tracing.OTLP
	if o.Endpoint != "http://127.0.0.1:4318/v1/traces" || o.Headers["x-api-key"] != "k1" || o.Headers["x-tenant"] != "a,b" || len(o.Headers) != 2 {
		t.Fatalf("env overrides loaded as %+v", o)
	}
}

func TestTracingOTLPValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Tracing.ExporterType = "otlp"
	cfg.Tracing.OTLP.Endpoint = "https://user:pass@collector/v1/traces"
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "tracing.otlp") {
		t.Fatalf("credentials in the endpoint URL must be rejected, got %v", err)
	}

	cfg.Tracing.OTLP.Endpoint = ""
	cfg.Tracing.OTLP.Headers = map[string]string{"X-Token": "a\nb"}
	if err := Validate(cfg); err == nil {
		t.Fatal("header values with newlines must be rejected")
	}

	cfg.Tracing.ExporterType = "jaeger"
	cfg.Tracing.OTLP.Headers = nil
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "noop, stdout, otlp") {
		t.Fatalf("unknown exporter must list otlp as an option, got %v", err)
	}
}
