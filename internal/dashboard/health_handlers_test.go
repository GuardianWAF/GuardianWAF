package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockIsolationChecker implements ClusterIsolationChecker for testing.
type mockIsolationChecker struct {
	isolated    bool
	memberCount int
}

func (m *mockIsolationChecker) IsIsolated() bool { return m.isolated }
func (m *mockIsolationChecker) MemberCount() int { return m.memberCount }

func TestHandleReady_NoChecker(t *testing.T) {
	d := newTestDashboard(t, "")
	// No isolation checker wired — should be ready.
	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()
	d.handleReady(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ready" {
		t.Errorf("status = %v, want ready", body["status"])
	}
	components, ok := body["components"].(map[string]any)
	if !ok {
		t.Fatal("missing components")
	}
	if _, hasCluster := components["cluster"]; hasCluster {
		t.Error("cluster component should be absent when no isolation checker")
	}
}

func TestHandleReady_ClusterReady(t *testing.T) {
	d := newTestDashboard(t, "")
	d.SetClusterIsolationChecker(&mockIsolationChecker{isolated: false, memberCount: 3})

	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()
	d.handleReady(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ready" {
		t.Errorf("status = %v, want ready", body["status"])
	}
	components := body["components"].(map[string]any)
	if components["cluster"] != "ready" {
		t.Errorf("cluster = %v, want ready", components["cluster"])
	}
	if components["cluster_members"] != "3" {
		t.Errorf("cluster_members = %v, want 3", components["cluster_members"])
	}
}

func TestHandleReady_ClusterIsolated(t *testing.T) {
	d := newTestDashboard(t, "")
	d.SetClusterIsolationChecker(&mockIsolationChecker{isolated: true, memberCount: 1})

	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()
	d.handleReady(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "not ready" {
		t.Errorf("status = %v, want 'not ready'", body["status"])
	}
	components := body["components"].(map[string]any)
	if components["cluster"] != "isolated" {
		t.Errorf("cluster = %v, want isolated", components["cluster"])
	}
}

func TestHandleReady_LivezUnaffected(t *testing.T) {
	d := newTestDashboard(t, "")
	d.SetClusterIsolationChecker(&mockIsolationChecker{isolated: true, memberCount: 1})

	// /livez should NOT be affected by isolation — only /readyz is.
	req := httptest.NewRequest("GET", "/livez", nil)
	w := httptest.NewRecorder()
	d.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("/livez should return 200 even when isolated, got %d", w.Code)
	}
}
