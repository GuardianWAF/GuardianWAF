package dashboard

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
)

// Regression: the DELETE kill-switch could not disable CUSTOM DLP patterns.
// dlpAdapter.DisablePattern resolved ids via registry.GetPattern(PatternType),
// which only searches the built-in patterns map — custom patterns (keyed by
// name in the registry's custom map, surfaced in LIST/GET since round 71)
// always 404'd. A noisy or over-matching custom pattern could not be turned
// off via the API while the list kept showing it enabled.
func TestDLPPatternDeleteDisablesCustomPattern(t *testing.T) {
	layer := dlp.NewLayer(nil)
	d := &Dashboard{
		auditLog: NewAuditLog(0),
		mux:      http.NewServeMux(),
		dlpLayer: layer,
	}
	d.apiKey.Store(&apiKeyHolder{Current: "test-key"})
	NewDLPHandler(d).RegisterRoutes(d.mux)

	// Add a custom pattern through the API adapter (the round-71 identity path).
	adapter := &dlpAdapter{layer: layer}
	re, err := regexp.Compile("noisy-[0-9]+")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := adapter.AddPattern(&DLPPatternInfo{
		ID:      "noisy-ptr",
		Name:    "noisy-ptr",
		Pattern: re.String(),
		Action:  "mask",
	}); err != nil {
		t.Fatalf("AddPattern: %v", err)
	}

	// The custom pattern is listed and enabled (round-71 identity: name = id).
	if p := adapter.GetPattern("noisy-ptr"); p == nil || !p.Enabled {
		t.Fatalf("custom pattern not listed enabled after add: %+v", p)
	}

	doDelete := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, "/api/dlp/patterns/"+id, nil)
		req.Header.Set("X-API-Key", "test-key")
		rec := httptest.NewRecorder()
		d.mux.ServeHTTP(rec, req)
		return rec
	}

	// Defect path: DELETE must honestly disable the CUSTOM pattern.
	rec := doDelete("noisy-ptr")
	if rec.Code != http.StatusOK {
		t.Fatalf("custom pattern DELETE: got %d with body %q, want 200 — the kill-switch "+
			"cannot disable custom patterns (they keep scanning/masking while the list "+
			"shows them enabled)", rec.Code, rec.Body.String())
	}
	if cp := layer.GetRegistry().GetCustomPattern("noisy-ptr"); cp == nil || cp.Enabled {
		t.Fatalf("custom pattern still enabled in the registry after DELETE: %+v", cp)
	}

	// Control: built-in disable keeps working.
	rec = doDelete("credit_card")
	if rec.Code != http.StatusOK {
		t.Fatalf("built-in pattern DELETE: got %d, want 200", rec.Code)
	}
	if layer.GetRegistry().GetPattern(dlp.PatternCreditCard).Enabled {
		t.Fatalf("built-in pattern still enabled after DELETE")
	}
}
