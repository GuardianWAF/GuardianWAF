package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/layers/clientside"
)

// Regression: GET /api/clientside/skimming-domains always reported
// {"domains":null,"count":0} — the production clientSideAdapter returned a
// hardcoded nil and clientside.Layer exposed no getter — while POST returned
// 200 "added" and Layer.AddSkimmingDomain genuinely recorded the domain for
// detection. An operator could not verify the blocklist: the list endpoint
// permanently denied what the write endpoint confirmed. The same gap hid
// config-loaded domains.

func TestClientSideSkimmingDomainReadback(t *testing.T) {
	cfg := clientside.DefaultConfig()
	// Exactly one config-loaded domain keeps the expected state deterministic.
	cfg.MagecartDetection.KnownSkimmingDomains = []string{"preload.example"}
	layer := clientside.NewLayer(cfg)
	d := &Dashboard{
		auditLog:        NewAuditLog(0),
		mux:             http.NewServeMux(),
		clientSideLayer: layer,
	}
	d.apiKey.Store(&apiKeyHolder{Current: "test-key"})
	NewClientSideHandler(d).RegisterRoutes(d.mux)

	doReq := func(method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/clientside/skimming-domains", bytes.NewReader([]byte(body)))
		req.Header.Set("X-API-Key", "test-key")
		rec := httptest.NewRecorder()
		d.mux.ServeHTTP(rec, req)
		return rec
	}

	// Control: POST is acknowledged by the write path.
	rec := doReq(http.MethodPost, `{"domain":"runtime-skimmer.example"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST: got %d with body %q, want 200", rec.Code, rec.Body.String())
	}

	// Defect path: GET must report the real blocklist — both the
	// config-loaded domain and the runtime-added one.
	rec = doReq(http.MethodGet, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: got %d with body %q, want 200", rec.Code, rec.Body.String())
	}
	var out struct {
		Domains []string `json:"domains"`
		Count   int      `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("GET body %q is not valid JSON: %v", rec.Body.String(), err)
	}
	if out.Count != 2 {
		t.Fatalf("FAIL: GET /api/clientside/skimming-domains reported count %d (domains %v), want 2 — the list endpoint hides domains the write endpoint confirmed", out.Count, out.Domains)
	}
	seen := map[string]bool{}
	for _, dom := range out.Domains {
		seen[dom] = true
	}
	if !seen["preload.example"] || !seen["runtime-skimmer.example"] {
		t.Fatalf("FAIL: GET reported domains %v, want both preload.example and runtime-skimmer.example", out.Domains)
	}
}
