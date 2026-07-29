package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

func TestMCPSSEUsesLiveDashboardKeyAfterRotation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Dashboard.APIKey = "original-key-12345"
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	dash := dashboard.New(eng, store, cfg.Dashboard.APIKey)
	defer dash.Close()
	mcpSSE := buildMCPSSEHandler(eng, cfg, store, nil, dash.CurrentAPIKey)
	mcpMux := http.NewServeMux()
	mcpSSE.RegisterRoutes(mcpMux)

	mcpRequest := func(key string) int {
		req := httptest.NewRequest(http.MethodPost, "/mcp/message", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
		req.Header.Set("X-API-Key", key)
		resp := httptest.NewRecorder()
		mcpMux.ServeHTTP(resp, req)
		return resp.Code
	}
	if got := mcpRequest("original-key-12345"); got != http.StatusAccepted {
		t.Fatalf("initial MCP key status = %d, want %d", got, http.StatusAccepted)
	}

	rotateBody := `{"current_key":"original-key-12345","new_key":"rotated-key-67890"}`
	rotateReq := httptest.NewRequest(http.MethodPost, "/api/v1/rotate-key", strings.NewReader(rotateBody))
	rotateReq.Header.Set("Content-Type", "application/json")
	rotateReq.Header.Set("X-API-Key", "original-key-12345")
	rotateResp := httptest.NewRecorder()
	dash.Handler().ServeHTTP(rotateResp, rotateReq)
	if rotateResp.Code != http.StatusOK {
		t.Fatalf("rotation status = %d, want %d: %s", rotateResp.Code, http.StatusOK, rotateResp.Body.String())
	}

	// The dashboard intentionally keeps a short grace window for ordinary API
	// requests, but MCP authentication must revoke the old key immediately.
	graceReq := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	graceReq.Header.Set("X-API-Key", "original-key-12345")
	graceResp := httptest.NewRecorder()
	dash.Handler().ServeHTTP(graceResp, graceReq)
	if graceResp.Code != http.StatusOK {
		t.Fatalf("dashboard grace key status = %d, want %d", graceResp.Code, http.StatusOK)
	}
	if got := mcpRequest("original-key-12345"); got != http.StatusUnauthorized {
		t.Fatalf("old MCP key status after rotation = %d, want %d", got, http.StatusUnauthorized)
	}
	if got := mcpRequest("rotated-key-67890"); got != http.StatusAccepted {
		t.Fatalf("new MCP key status after rotation = %d, want %d", got, http.StatusAccepted)
	}
}
