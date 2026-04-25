package zerotrust

import (
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestLayer_Name(t *testing.T) {
	l := NewLayer(nil)
	if got := l.Name(); got != "zero_trust" {
		t.Errorf("Name() = %q, want %q", got, "zero_trust")
	}
}

func TestLayer_PassesWhenDisabled(t *testing.T) {
	l := NewLayer(nil)
	ctx := &engine.RequestContext{Path: "/api/test"}
	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("disabled layer should pass, got %v", result.Action)
	}
}

func TestLayer_PassesWhenServiceDisabled(t *testing.T) {
	svc, err := NewService(&Config{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	l := NewLayer(svc)
	ctx := &engine.RequestContext{Path: "/api/test"}
	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("disabled service should pass, got %v", result.Action)
	}
}

func TestLayer_BypassPaths(t *testing.T) {
	svc, err := NewService(&Config{
		Enabled:          true,
		RequireMTLS:      true,
		AllowBypassPaths: []string{"/healthz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	l := NewLayer(svc)
	ctx := &engine.RequestContext{Path: "/healthz"}
	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("bypass path should pass, got %v", result.Action)
	}
}

func TestLayer_BlocksWhenMTLSRequired(t *testing.T) {
	svc, err := NewService(&Config{Enabled: true, RequireMTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	l := NewLayer(svc)
	ctx := &engine.RequestContext{
		Path:    "/api/secure",
		Headers: map[string][]string{},
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("should block without mTLS, got %v", result.Action)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings")
	}
	if result.Findings[0].DetectorName != "zero_trust" {
		t.Errorf("detector = %q, want zero_trust", result.Findings[0].DetectorName)
	}
}

func TestLayer_InvalidSessionBlocksWhenMTLS(t *testing.T) {
	svc, err := NewService(&Config{Enabled: true, RequireMTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	l := NewLayer(svc)
	ctx := &engine.RequestContext{
		Path:    "/api/secure",
		Headers: map[string][]string{"X-Zerotrust-Session": {"invalid-session-id"}},
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("should block with invalid session + mTLS required, got %v", result.Action)
	}
}

func TestLayer_PassesWithoutMTLS(t *testing.T) {
	svc, err := NewService(&Config{Enabled: true, RequireMTLS: false})
	if err != nil {
		t.Fatal(err)
	}
	l := NewLayer(svc)
	ctx := &engine.RequestContext{
		Path:    "/api/test",
		Headers: map[string][]string{},
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("should pass without mTLS requirement, got %v", result.Action)
	}
}

func TestLayer_ValidSessionPasses(t *testing.T) {
	svc, err := NewService(&Config{Enabled: true, RequireMTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	// Register a valid session
	identity := &ClientIdentity{
		ClientID:        "client-1",
		TrustLevel:      TrustLevelHigh,
		SessionID:       "sess-123",
		AuthenticatedAt: time.Now(),
	}
	svc.mu.Lock()
	svc.sessions["sess-123"] = identity
	svc.mu.Unlock()

	l := NewLayer(svc)
	ctx := &engine.RequestContext{
		Path:    "/api/test",
		Headers: map[string][]string{"X-Zerotrust-Session": {"sess-123"}},
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("valid session should pass, got %v", result.Action)
	}
	if ctx.Metadata["zt_trust_level"] != "high" {
		t.Errorf("trust level = %v, want high", ctx.Metadata["zt_trust_level"])
	}
	if ctx.Metadata["zt_client_id"] != "client-1" {
		t.Errorf("client id = %v, want client-1", ctx.Metadata["zt_client_id"])
	}
}
