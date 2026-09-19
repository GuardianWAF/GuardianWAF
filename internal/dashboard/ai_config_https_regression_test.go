package dashboard

// Regression (bug-hunt round 2026-09-18-r3): handleAISetConfig's front-door
// validator validateAIEndpointURL accepted the "http" scheme (its own error
// message advertised "URL scheme must be http or https") and even blessed an
// http:// URL with DNS + private-IP analysis — while the only write path
// (Analyzer.UpdateProvider → ai.NewClientValidated, which never sets
// AllowPrivateEndpoint for dashboard-driven config) rejects cleartext HTTP
// unconditionally: "AI endpoint must use HTTPS (the API key would be sent in
// cleartext)". An operator POSTing an http:// endpoint therefore passed
// validation and received a 500 blaming the scheme — a client error laundered
// into a server error, with the handler's validation asserting a contract the
// layer refuses.
//
// The layer's invariant is the authoritative one (client.go: the API key is
// sent as a Bearer token; refuse cleartext HTTP so the credential is never
// transmitted unencrypted). The fix mirrors it at the front door: reject
// non-HTTPS with a 400 carrying the rationale, before any write path runs.
//
// Public IP literals keep every case DNS-independent and deterministic.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/ai"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// recordingAIAnalyzer implements aiAnalyzerInterface, recording UpdateProvider
// calls so the test can assert the request never reached the write path.
type recordingAIAnalyzer struct {
	updateCalled bool
	updateCfg    ai.ProviderConfig
	updateErr    error
}

func (r *recordingAIAnalyzer) GetCatalog() ([]ai.ProviderSummary, error) { return nil, nil }
func (r *recordingAIAnalyzer) GetStore() *ai.Store                       { return nil }
func (r *recordingAIAnalyzer) UpdateProvider(cfg ai.ProviderConfig) error {
	r.updateCalled = true
	r.updateCfg = cfg
	return r.updateErr
}
func (r *recordingAIAnalyzer) TestConnection() error { return nil }
func (r *recordingAIAnalyzer) ManualAnalyze(evts []engine.Event) (*ai.AnalysisResult, error) {
	return nil, nil
}

// TestAISetConfig_CleartextHTTPRejectedAtFrontDoor is the defect case: an
// http:// public endpoint must be rejected with a 400 carrying the HTTPS
// rationale, and the AI layer must never see it.
func TestAISetConfig_CleartextHTTPRejectedAtFrontDoor(t *testing.T) {
	stub := &recordingAIAnalyzer{updateErr: fmt.Errorf("AI endpoint must use HTTPS (the API key would be sent in cleartext over %q); set allow_private_endpoint to override for local testing", "http://1.2.3.4/v1")}
	d := &Dashboard{}
	d.aiAnalyzer = stub

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/ai/config", strings.NewReader(`{"api_key":"key","base_url":"http://1.2.3.4/v1"}`))
	d.handleAISetConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("FAIL: a cleartext-http AI endpoint must be rejected at the front door with 400 (client error); got %d — the handler's own validator accepted the scheme and the AI layer refused it", rr.Code)
	}
	if stub.updateCalled {
		t.Fatalf("FAIL: handleAISetConfig forwarded a cleartext-http config to the AI layer; the scheme must be rejected before any write path runs")
	}
	if !strings.Contains(rr.Body.String(), "HTTPS") {
		t.Fatalf("FAIL: rejection message must carry the HTTPS rationale, got: %s", rr.Body.String())
	}
}

// Control: a valid https public endpoint still reaches the layer and returns
// 200 — proves the harness exercises the real path and the fix only narrows
// cleartext schemes.
func TestAISetConfig_ValidHTTPSReachesLayer(t *testing.T) {
	stub := &recordingAIAnalyzer{}
	d := &Dashboard{}
	d.aiAnalyzer = stub

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/ai/config", strings.NewReader(`{"api_key":"key","base_url":"https://1.1.1.1/v1"}`))
	d.handleAISetConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("FAIL: harness control — a valid https public endpoint must reach the AI layer and return 200; got %d: %s", rr.Code, rr.Body.String())
	}
	if !stub.updateCalled {
		t.Fatalf("FAIL: harness control — UpdateProvider must be invoked for a valid https config")
	}
	if stub.updateCfg.APIKey != "key" || stub.updateCfg.BaseURL != "https://1.1.1.1/v1" {
		t.Fatalf("FAIL: harness control — layer received %+v, want the request's provider config", stub.updateCfg)
	}
}

// TestValidateAIEndpointURL_RejectsCleartextHTTP pins the validator contract
// directly: http is not a valid AI endpoint scheme.
func TestValidateAIEndpointURL_RejectsCleartextHTTP(t *testing.T) {
	err := validateAIEndpointURL("http://1.2.3.4/v1")
	if err == nil {
		t.Fatalf("FAIL: validateAIEndpointURL accepted a cleartext-http endpoint — the AI layer refuses http unconditionally on the dashboard path (the API key travels as a Bearer token), so the front door must reject it too")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("FAIL: rejection must carry the HTTPS rationale, got: %v", err)
	}
}
