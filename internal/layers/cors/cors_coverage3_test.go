package cors

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestOrder(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	if got := layer.Order(); got != engine.OrderCORS {
		t.Fatalf("Order() = %d, want %d", got, engine.OrderCORS)
	}
}

func TestProcess_TenantDisablesCORS(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://example.com"},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	ctx := &engine.RequestContext{
		Method:   "GET",
		Headers:  map[string][]string{"Origin": {"https://example.com"}},
		Metadata: make(map[string]any),
		TenantWAFConfig: &config.WAFConfig{
			CORS: config.CORSConfig{Enabled: false},
		},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected pass when tenant disables CORS, got %v", result.Action)
	}
	if _, ok := ctx.Metadata["cors_headers"]; ok {
		t.Fatal("expected no cors_headers when tenant disables CORS")
	}
}

func TestProcess_NullOriginWithCredentials(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		AllowOrigins:     []string{"null"},
		AllowCredentials: true,
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	ctx := &engine.RequestContext{
		Method:   "GET",
		Headers:  map[string][]string{"Origin": {"null"}},
		Metadata: make(map[string]any),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected pass for null origin with credentials, got %v", result.Action)
	}
	if _, ok := ctx.Metadata["cors_headers"]; ok {
		t.Fatal("expected no cors_headers for null origin when credentials are enabled")
	}
}
