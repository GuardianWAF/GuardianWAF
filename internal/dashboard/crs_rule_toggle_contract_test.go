package dashboard

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Regression: the CRS rule-toggle PUT returned 200 {"enabled": <requested>}
// for ANY rule ID — crs.Layer.EnableRule/DisableRule are void and
// DisableRule silently records disabled-state for unknown IDs — so an
// operator's emergency enable/kill switch on a typo'd or stale rule ID faked
// success while nothing changed (the same silent-failure class the
// virtualpatch PUT contract fixed). The handler now mirrors the GET branch's
// GetRule existence check: unknown IDs return 404.
func TestCRSRuleToggleUnknownIDReturns404(t *testing.T) {
	mock := &mockCRSToggleLayer{
		rules: map[string]*CRSRuleInfo{
			"9.1": {ID: "9.1", Phase: 1, Severity: "critical", ParanoiaLevel: 1},
		},
		disabled: make(map[string]bool),
	}
	d := &Dashboard{
		auditLog:         NewAuditLog(0),
		mux:              http.NewServeMux(),
		crsLayerOverride: mock,
	}
	d.apiKey.Store(&apiKeyHolder{Current: "test-key"})
	NewCRSHandler(d).RegisterRoutes(d.mux)

	doPut := func(ruleID string, enabled bool) *httptest.ResponseRecorder {
		body := `{"enabled":true}`
		if !enabled {
			body = `{"enabled":false}`
		}
		req := httptest.NewRequest(http.MethodPut, "/api/crs/rules/"+ruleID, bytes.NewReader([]byte(body)))
		req.Header.Set("X-API-Key", "test-key")
		rec := httptest.NewRecorder()
		d.mux.ServeHTTP(rec, req)
		return rec
	}

	// Control: a known rule toggles with 200 and the layer records it.
	rec := doPut("9.1", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("known-rule toggle: got %d with body %q, want 200", rec.Code, rec.Body.String())
	}
	if !mock.disabled["9.1"] {
		t.Fatalf("known-rule disable did not reach the layer")
	}

	// Defect path: an unknown rule ID must 404, not fake success.
	rec = doPut("9.unknown", true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown-rule toggle: got %d with body %q, want 404 — fake success on a "+
			"nonexistent rule ID means the operator's emergency enable/kill switch "+
			"silently does nothing", rec.Code, rec.Body.String())
	}
}

// mockCRSToggleLayer implements CRSLayerInterface for the toggle contract test.
type mockCRSToggleLayer struct {
	rules         map[string]*CRSRuleInfo
	disabled      map[string]bool
	enabledCalls  []string
	disabledCalls []string
}

func (m *mockCRSToggleLayer) GetAllRules() []*CRSRuleInfo {
	out := make([]*CRSRuleInfo, 0, len(m.rules))
	for _, r := range m.rules {
		out = append(out, r)
	}
	return out
}

func (m *mockCRSToggleLayer) GetRule(id string) *CRSRuleInfo { return m.rules[id] }

func (m *mockCRSToggleLayer) EnableRule(id string) {
	m.enabledCalls = append(m.enabledCalls, id)
	delete(m.disabled, id)
}

func (m *mockCRSToggleLayer) DisableRule(id string) {
	m.disabledCalls = append(m.disabledCalls, id)
	m.disabled[id] = true
}

func (m *mockCRSToggleLayer) IsRuleEnabled(id string) bool {
	return m.rules[id] != nil && !m.disabled[id]
}

func (m *mockCRSToggleLayer) SetParanoiaLevel(level int) {}

func (m *mockCRSToggleLayer) Stats() map[string]int { return map[string]int{} }

func (m *mockCRSToggleLayer) Process(ctx *TestRequestContext) CRSResult {
	return CRSResult{Score: 0, Action: ActionType("pass")}
}
