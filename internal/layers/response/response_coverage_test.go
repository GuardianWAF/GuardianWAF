package response

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestSetSafeHeader_RejectsCRLF(t *testing.T) {
	w := httptest.NewRecorder()

	setSafeHeader(w, "X-Test", "safe\r\nInjected: bad")

	if got := w.Header().Get("X-Test"); got != "" {
		t.Fatalf("expected unsafe header to be rejected, got %q", got)
	}
}

func TestLayer_Order(t *testing.T) {
	cfg := DefaultConfig()
	layer := NewLayer(&cfg)

	if got := layer.Order(); got != engine.OrderResponse {
		t.Fatalf("Order() = %d, want %d", got, engine.OrderResponse)
	}
}

func TestLayer_Process_MaskFunction(t *testing.T) {
	cfg := DefaultConfig()
	layer := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/test"},
		},
		Method:      "GET",
		Path:        "/test",
		Accumulator: engine.NewScoreAccumulator(2),
		Metadata:    make(map[string]any),
		StartTime:   time.Now(),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected ActionPass, got %v", result.Action)
	}

	maskFn, ok := ctx.Metadata["response_mask_fn"].(func(string) string)
	if !ok {
		t.Fatalf("expected response_mask_fn metadata to contain func(string) string")
	}

	masked := maskFn("Card: 4111111111111111")
	if masked == "Card: 4111111111111111" {
		t.Fatal("expected response_mask_fn to mask the response body")
	}
}

func TestLayer_Process_TenantDisablesFeatures(t *testing.T) {
	cfg := DefaultConfig()
	layer := NewLayer(&cfg)

	tenantCfg := config.DefaultWAFConfig()
	tenantCfg.Response.SecurityHeaders.Enabled = false
	tenantCfg.Response.DataMasking.Enabled = false

	ctx := &engine.RequestContext{
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/test"},
		},
		Method:          "GET",
		Path:            "/test",
		Accumulator:     engine.NewScoreAccumulator(2),
		Metadata:        make(map[string]any),
		StartTime:       time.Now(),
		TenantWAFConfig: &tenantCfg,
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected ActionPass, got %v", result.Action)
	}

	stored, ok := ctx.Metadata["response_config"].(Config)
	if !ok {
		t.Fatalf("expected response_config metadata to contain Config")
	}
	if stored.SecurityHeadersEnabled {
		t.Fatal("expected tenant config to disable security headers")
	}
	if stored.DataMaskingEnabled {
		t.Fatal("expected tenant config to disable data masking")
	}
	if _, ok := ctx.Metadata["response_hook"]; ok {
		t.Fatal("expected no response_hook when tenant disables security headers")
	}
	if _, ok := ctx.Metadata["response_mask_fn"]; ok {
		t.Fatal("expected no response_mask_fn when tenant disables data masking")
	}
}
