package dashboard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// fakeBanLayer is a minimal engine.Layer that also implements banLayer.
// It records ban/unban calls so tests can verify the local fallback path.
type fakeBanLayer struct {
	bans map[string]string // ip → reason
}

func (f *fakeBanLayer) Name() string { return "ipacl" }
func (f *fakeBanLayer) Order() int   { return 10 }
func (f *fakeBanLayer) Process(*engine.RequestContext) engine.LayerResult {
	return engine.LayerResult{Action: engine.ActionPass}
}
func (f *fakeBanLayer) AddAutoBan(ip string, reason string, ttl time.Duration) {
	f.bans[ip] = reason
}
func (f *fakeBanLayer) RemoveAutoBan(ip string) {
	delete(f.bans, ip)
}

// mockClusterProvider implements ClusterStatusProvider to record ProposeBan/
// ProposeUnban calls and optionally simulate "not leader" errors.
type mockClusterProvider struct {
	bans   map[string]time.Duration
	unbans map[string]bool
	err    error // error to return from ProposeBan/ProposeUnban
}

func (m *mockClusterProvider) Enabled() bool                 { return true }
func (m *mockClusterProvider) NodeID() string                { return "test-node" }
func (m *mockClusterProvider) Role() string                  { return "leader" }
func (m *mockClusterProvider) LeaderID() string              { return "test-node" }
func (m *mockClusterProvider) CurrentTerm() uint64           { return 1 }
func (m *mockClusterProvider) CommitIndex() uint64           { return 0 }
func (m *mockClusterProvider) LastApplied() uint64           { return 0 }
func (m *mockClusterProvider) LogLength() uint64             { return 0 }
func (m *mockClusterProvider) Peers() []ClusterPeerInfo      { return nil }
func (m *mockClusterProvider) StoreStats() ClusterStoreStats { return ClusterStoreStats{} }
func (m *mockClusterProvider) BannedIPs() []ClusterBanInfo   { return nil }
func (m *mockClusterProvider) ProposeBan(ip string, d time.Duration) error {
	if m.err != nil {
		return m.err
	}
	if m.bans == nil {
		m.bans = make(map[string]time.Duration)
	}
	m.bans[ip] = d
	return nil
}
func (m *mockClusterProvider) ProposeUnban(ip string) error {
	if m.err != nil {
		return m.err
	}
	if m.unbans == nil {
		m.unbans = make(map[string]bool)
	}
	m.unbans[ip] = true
	return nil
}

// TestClusterBanPropagation_ProposeBan verifies that POST /api/v1/bans calls
// ProposeBan on the cluster status provider AND applies the ban locally.
func TestClusterBanPropagation_ProposeBan(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	// Register a fake ban layer so the handler can apply the ban locally.
	bl := &fakeBanLayer{bans: make(map[string]string)}
	d.engine.AddLayer(engine.OrderedLayer{Layer: bl, Order: 10})

	// Wire the mock cluster provider.
	provider := &mockClusterProvider{}
	d.SetClusterStatusProvider(provider)

	body := `{"ip":"203.0.113.42","reason":"test ban","duration":"1h"}`
	req := httptest.NewRequest("POST", "/api/v1/bans", strings.NewReader(body))
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()
	d.handleAddBan(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify ProposeBan was called with the right IP and duration.
	if _, ok := provider.bans["203.0.113.42"]; !ok {
		t.Error("expected ProposeBan to be called with 203.0.113.42")
	}
	// Verify the ban was also applied locally.
	if _, ok := bl.bans["203.0.113.42"]; !ok {
		t.Error("expected local ban to be applied")
	}
}

// TestClusterBanPropagation_ProposeBanFollower verifies that when ProposeBan
// returns an error (e.g. "not leader"), the handler returns 503 instead of
// silently applying the ban locally.
func TestClusterBanPropagation_ProposeBanFollower(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	bl := &fakeBanLayer{bans: make(map[string]string)}
	d.engine.AddLayer(engine.OrderedLayer{Layer: bl, Order: 10})

	provider := &mockClusterProvider{err: errors.New("not raft leader")}
	d.SetClusterStatusProvider(provider)

	body := `{"ip":"203.0.113.99","reason":"ban from follower","duration":"1h"}`
	req := httptest.NewRequest("POST", "/api/v1/bans", strings.NewReader(body))
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()
	d.handleAddBan(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rr.Code, rr.Body.String())
	}
	// Verify the ban was NOT applied locally (proposal failed).
	if _, ok := bl.bans["203.0.113.99"]; ok {
		t.Error("ban should NOT be applied locally when cluster proposal fails")
	}
}

// TestClusterBanPropagation_ProposeUnban verifies that DELETE /api/v1/bans
// calls ProposeUnban on the cluster status provider AND removes the local ban.
func TestClusterBanPropagation_ProposeUnban(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	bl := &fakeBanLayer{bans: map[string]string{"203.0.113.42": "existing"}}
	d.engine.AddLayer(engine.OrderedLayer{Layer: bl, Order: 10})

	provider := &mockClusterProvider{}
	d.SetClusterStatusProvider(provider)

	body := `{"ip":"203.0.113.42"}`
	req := httptest.NewRequest("DELETE", "/api/v1/bans", strings.NewReader(body))
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()
	d.handleRemoveBan(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify ProposeUnban was called.
	if !provider.unbans["203.0.113.42"] {
		t.Error("expected ProposeUnban to be called with 203.0.113.42")
	}
	// Verify the local ban was removed.
	if _, ok := bl.bans["203.0.113.42"]; ok {
		t.Error("expected local ban to be removed")
	}
}

// TestClusterBanPropagation_NoCluster verifies that when no cluster provider is
// wired (single-node mode), bans are applied locally without calling ProposeBan.
func TestClusterBanPropagation_NoCluster(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	bl := &fakeBanLayer{bans: make(map[string]string)}
	d.engine.AddLayer(engine.OrderedLayer{Layer: bl, Order: 10})

	// No cluster provider wired — clusterStatus is nil.
	body := `{"ip":"198.51.100.1","reason":"single-node ban","duration":"30m"}`
	req := httptest.NewRequest("POST", "/api/v1/bans", strings.NewReader(body))
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()
	d.handleAddBan(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify the ban was applied locally.
	if _, ok := bl.bans["198.51.100.1"]; !ok {
		t.Error("expected local ban to be applied in single-node mode")
	}
}
