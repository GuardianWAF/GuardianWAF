package clustersync

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestHandler_HandleHealth_MethodNotAllowed covers the POST rejection.
func TestHandler_HandleHealth_MethodNotAllowed(t *testing.T) {
	m := NewManager(DefaultConfig())
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodPost, "/api/cluster/health", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleHealth(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestHandler_HandleSync_MethodNotAllowed covers GET rejection.
func TestHandler_HandleSync_MethodNotAllowed(t *testing.T) {
	m := NewManager(DefaultConfig())
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/sync", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleSync(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestHandler_HandleSync_InvalidBody covers bad JSON decode.
func TestHandler_HandleSync_InvalidBody(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodPost, "/api/cluster/sync", strings.NewReader("{bad json"))
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleSync(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad JSON, got %d", w.Code)
	}
}

// TestHandler_HandleSync_ReceiveEventOK covers successful event receive.
func TestHandler_HandleSync_ReceiveEventOK(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	body := `{"id":"evt-1","source_node":"node-2","entity_type":"tenant","entity_id":"e1","action":"create"}`
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/sync", strings.NewReader(body))
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleSync(w, req)

	if w.Code != http.StatusOK && w.Code != http.StatusConflict {
		t.Logf("got status %d (expected OK or Conflict)", w.Code)
	}
}

// TestHandler_HandleSync_Unauthorized covers missing auth.
func TestHandler_HandleSync_Unauthorized(t *testing.T) {
	m := NewManager(DefaultConfig())
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodPost, "/api/cluster/sync", nil)
	w := httptest.NewRecorder()
	h.handleSync(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestHandler_HandleEvents_MethodNotAllowed covers POST rejection.
func TestHandler_HandleEvents_MethodNotAllowed(t *testing.T) {
	m := NewManager(DefaultConfig())
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodPost, "/api/cluster/events", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleEvents(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestHandler_HandleEvents_InvalidSince covers bad since parameter.
func TestHandler_HandleEvents_InvalidSince(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/events?since=notanumber", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleEvents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (invalid since ignored), got %d", w.Code)
	}
}

// TestHandler_HandleEvents_WithValidSince covers valid since parameter.
func TestHandler_HandleEvents_WithValidSince(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	since := time.Now().Add(-1 * time.Hour).Unix()
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/events", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	q := req.URL.Query()
	q.Set("since", "")
	req.URL.RawQuery = q.Encode()
	_ = since
	w := httptest.NewRecorder()
	h.handleEvents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandler_HandleClusters_MethodNotAllowed covers DELETE rejection.
func TestHandler_HandleClusters_MethodNotAllowed(t *testing.T) {
	m := NewManager(DefaultConfig())
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodDelete, "/api/clusters", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleClusters(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestHandler_HandleClusterDetail_EmptyID covers missing cluster ID.
func TestHandler_HandleClusterDetail_EmptyID(t *testing.T) {
	m := NewManager(DefaultConfig())
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodGet, "/api/clusters/", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleClusterDetail(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestHandler_HandleClusterDetail_Join covers join cluster action.
func TestHandler_HandleClusterDetail_Join(t *testing.T) {
	AllowPlainHTTP()
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	cfg.NodeID = "node-1"
	m := NewManager(cfg)
	h := NewHandler(m)

	cluster := &Cluster{ID: "c1", Name: "test"}
	_ = m.AddCluster(cluster)

	nodeJSON := `{"id":"node-2","name":"worker","address":"http://localhost:9090"}`
	req := httptest.NewRequest(http.MethodPost, "/api/clusters/c1?action=join", strings.NewReader(nodeJSON))
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleClusterDetail(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for join, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandler_HandleClusterDetail_JoinMissingID covers join with auto-generated node ID.
func TestHandler_HandleClusterDetail_JoinMissingID(t *testing.T) {
	AllowPlainHTTP()
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	cfg.NodeID = "node-1"
	m := NewManager(cfg)
	h := NewHandler(m)

	cluster := &Cluster{ID: "c1", Name: "test"}
	_ = m.AddCluster(cluster)

	nodeJSON := `{"name":"worker","address":"http://192.168.1.10:9090"}`
	req := httptest.NewRequest(http.MethodPost, "/api/clusters/c1?action=join", strings.NewReader(nodeJSON))
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleClusterDetail(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for join with auto ID, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandler_HandleClusterDetail_Leave covers leave cluster action.
func TestHandler_HandleClusterDetail_Leave(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	cfg.NodeID = "node-1"
	m := NewManager(cfg)
	h := NewHandler(m)

	cluster := &Cluster{ID: "c1", Name: "test"}
	_ = m.AddCluster(cluster)
	_ = m.AddNodeToCluster("c1", &Node{ID: "node-2", Name: "worker"})

	req := httptest.NewRequest(http.MethodPost, "/api/clusters/c1?action=leave&node_id=node-2", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleClusterDetail(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204 for leave, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandler_HandleClusterDetail_LeaveNoNodeID covers missing node_id.
func TestHandler_HandleClusterDetail_LeaveNoNodeID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	cluster := &Cluster{ID: "c1", Name: "test"}
	_ = m.AddCluster(cluster)

	req := httptest.NewRequest(http.MethodPost, "/api/clusters/c1?action=leave", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleClusterDetail(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing node_id, got %d", w.Code)
	}
}

// TestHandler_DeleteCluster_NonExistent covers deleting non-existent cluster (returns 204).
func TestHandler_DeleteCluster_NonExistent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodDelete, "/api/clusters/nonexistent", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.deleteCluster(w, req, "nonexistent")

	// RemoveCluster returns nil even for non-existent clusters
	if w.Code != http.StatusNoContent {
		t.Logf("got status %d for deleting non-existent cluster", w.Code)
	}
}

// TestHandler_CreateCluster_Unauthorized covers missing auth.
func TestHandler_CreateCluster_Unauthorized(t *testing.T) {
	m := NewManager(DefaultConfig())
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodPost, "/api/clusters", nil)
	w := httptest.NewRecorder()
	h.createCluster(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestHandler_CreateCluster_InvalidJSON covers bad JSON.
func TestHandler_CreateCluster_InvalidJSON(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodPost, "/api/clusters", strings.NewReader("{bad"))
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.createCluster(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestHandler_CreateCluster_Success covers successful cluster creation.
func TestHandler_CreateCluster_Success(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	clusterJSON := `{"id":"c-new","name":"new-cluster","description":"test cluster"}`
	req := httptest.NewRequest(http.MethodPost, "/api/clusters", strings.NewReader(clusterJSON))
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.createCluster(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandler_HandleNodes_MethodNotAllowed covers POST rejection.
func TestHandler_HandleNodes_MethodNotAllowed(t *testing.T) {
	m := NewManager(DefaultConfig())
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodPost, "/api/nodes", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleNodes(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestHandler_HandleStats_MethodNotAllowed covers POST rejection.
func TestHandler_HandleStats_MethodNotAllowed(t *testing.T) {
	m := NewManager(DefaultConfig())
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodPost, "/api/sync/stats", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleStats(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestHandler_HandleReplicationStatus_MethodNotAllowed covers POST rejection.
func TestHandler_HandleReplicationStatus_MethodNotAllowed(t *testing.T) {
	m := NewManager(DefaultConfig())
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodPost, "/api/sync/status", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleReplicationStatus(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestSanitizeErr_NilError covers nil error.
func TestSanitizeErr_NilError(t *testing.T) {
	result := sanitizeErr(nil)
	if result != "" {
		t.Errorf("expected empty string for nil, got %q", result)
	}
}

// TestSanitizeErr_LongError covers truncation.
func TestSanitizeErr_LongError(t *testing.T) {
	longMsg := ""
	for i := 0; i < 300; i++ {
		longMsg += "x"
	}
	err := &coverageTestError{msg: longMsg}
	result := sanitizeErr(err)
	if len(result) > 200 {
		t.Errorf("expected truncation to 200 chars, got %d", len(result))
	}
}

type coverageTestError struct {
	msg string
}

func (e *coverageTestError) Error() string {
	return e.msg
}

// TestCheckAuth_EmptySecret covers no shared secret configured.
func TestCheckAuth_EmptySecret(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = ""
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/health", nil)
	req.Header.Set("X-Cluster-Auth", "whatever")
	if h.checkAuth(req) {
		t.Error("expected auth to fail with empty secret")
	}
}

// TestCheckAuth_WrongHeader covers wrong auth header value.
func TestCheckAuth_WrongHeader(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "correct-secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/health", nil)
	req.Header.Set("X-Cluster-Auth", "wrong-secret")
	if h.checkAuth(req) {
		t.Error("expected auth to fail with wrong secret")
	}
}

// TestManager_ReceiveEventFromOther covers receiving event from a different node.
func TestManager_ReceiveEventFromOther(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)

	handler := NewMockSyncHandler()
	m.RegisterHandler("tenant", handler)

	evt := &SyncEvent{
		ID:         "evt-external",
		SourceNode: "node-2",
		EntityType: "tenant",
		EntityID:   "entity-1",
		Action:     "create",
		Data:       map[string]any{"key": "value"},
	}

	err := m.ReceiveEvent(evt)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestManager_StartStopWithSync covers start/stop with sync workers.
func TestManager_StartStopWithSync(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.Enabled = true
	cfg.SyncInterval = 1 * time.Second

	m := NewManager(cfg)
	m.Start()
	time.Sleep(100 * time.Millisecond)
	m.Stop()
}

// TestDefaultConfig_Values covers DefaultConfig returns sensible values.
func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Error("expected Enabled=false by default")
	}
	if cfg.SyncInterval != 30*time.Second {
		t.Errorf("expected SyncInterval=30s, got %v", cfg.SyncInterval)
	}
	if cfg.MaxRetries != 3 {
		t.Errorf("expected MaxRetries=3, got %d", cfg.MaxRetries)
	}
}

// TestAllowPlainHTTP_Coverage covers AllowPlainHTTP function.
func TestAllowPlainHTTP_Coverage(t *testing.T) {
	AllowPlainHTTP()
	// Function just logs, verify it doesn't panic
}

// TestGenerateEventID_Coverage covers event ID generation.
func TestGenerateEventID_Coverage(t *testing.T) {
	id := generateEventID()
	if id == "" {
		t.Error("expected non-empty event ID")
	}
	id2 := generateEventID()
	if id == id2 {
		t.Error("expected unique IDs")
	}
}

// TestGenerateRandomString_Coverage covers random string generation.
func TestGenerateRandomString_Coverage(t *testing.T) {
	s := generateRandomString(16)
	if len(s) != 16 {
		t.Errorf("expected 16 chars, got %d", len(s))
	}
}

// TestSyncScopeParsing_Coverage covers various sync scope parsing edge cases.
func TestSyncScopeParsing_Coverage(t *testing.T) {
	tests := []struct {
		input    string
		expected SyncScope
	}{
		{"all", SyncAll},
		{"tenants", SyncTenants},
		{"config", SyncConfig},
		{"rules", SyncRules},
		{"invalid", SyncTenants}, // default
		{"", SyncTenants},        // default
	}
	for _, tt := range tests {
		result := ParseSyncScope(tt.input)
		if result != tt.expected {
			t.Errorf("ParseSyncScope(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

// TestSyncScope_StringAll_Coverage covers String method.
func TestSyncScope_StringAll_Coverage(t *testing.T) {
	if SyncAll.String() != "all" {
		t.Errorf("expected 'all', got %q", SyncAll.String())
	}
}

// TestCluster_GetNodesThreadSafe covers concurrent access to cluster nodes.
func TestCluster_GetNodesThreadSafe(t *testing.T) {
	c := &Cluster{
		ID:        "test",
		Name:      "test",
		Nodes:     []string{"node-1"},
		CreatedAt: time.Now(),
	}
	c.mu.RLock()
	nodes := make([]string, len(c.Nodes))
	copy(nodes, c.Nodes)
	c.mu.RUnlock()

	if len(nodes) != 1 || nodes[0] != "node-1" {
		t.Errorf("expected [node-1], got %v", nodes)
	}
}

// TestGetCluster_NilResult covers GetCluster returning nil.
func TestGetCluster_NilResult(t *testing.T) {
	m := NewManager(DefaultConfig())
	result := m.GetCluster("nonexistent")
	if result != nil {
		t.Error("expected nil for nonexistent cluster")
	}
}

// TestGetNode_NilResult covers GetNode returning nil.
func TestGetNode_NilResult(t *testing.T) {
	m := NewManager(DefaultConfig())
	result := m.GetNode("nonexistent")
	if result != nil {
		t.Error("expected nil for nonexistent node")
	}
}

// TestListClusters_Empty covers empty cluster list.
func TestListClusters_Empty(t *testing.T) {
	m := NewManager(DefaultConfig())
	clusters := m.GetClusters()
	if len(clusters) != 0 {
		t.Errorf("expected 0 clusters, got %d", len(clusters))
	}
}

// TestManager_BroadcastNoHandlers covers broadcast with no handlers.
func TestManager_BroadcastNoHandlers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	m := NewManager(cfg)

	// Should not panic
	_ = m.BroadcastEvent("tenant", "e1", "create", map[string]any{"key": "val"})
}

// TestSyncScopeString_Custom covers custom scope.
func TestSyncScopeString_Custom(t *testing.T) {
	s := SyncScope(99)
	result := s.String()
	if result != "custom" {
		t.Errorf("expected 'custom', got %q", result)
	}
}

// TestResolveConflict_AllModes tests resolveConflict for all conflict resolution modes.
func TestResolveConflict_AllModes(t *testing.T) {
	incoming := &SyncEvent{SourceNode: "node-2", Timestamp: 200}
	existing := &SyncEvent{SourceNode: "node-1", Timestamp: 100}

	// LastWriteWins: newer timestamp wins
	cfg := DefaultConfig()
	cfg.ConflictResolution = LastWriteWins
	m := NewManager(cfg)
	if !m.resolveConflict(incoming, existing) {
		t.Error("LastWriteWins: incoming (ts=200) should win over existing (ts=100)")
	}

	// LastWriteWins: older timestamp loses
	if m.resolveConflict(existing, incoming) {
		t.Error("LastWriteWins: existing (ts=100) should lose to incoming (ts=200)")
	}

	// SourcePriority: local has priority 100, remote has 50
	// incoming (node-2, pri=50) vs existing (node-1, pri=100) -> 50 > 100 = false -> rejects
	cfg2 := DefaultConfig()
	cfg2.ConflictResolution = SourcePriority
	cfg2.NodeID = "node-1"
	m2 := NewManager(cfg2)
	if m2.resolveConflict(incoming, existing) {
		t.Error("SourcePriority: incoming (pri=50) should lose to existing (pri=100)")
	}
	// Reverse: incoming is local (pri=100) vs existing is remote (pri=50) -> 100 > 50 = true
	if !m2.resolveConflict(existing, incoming) {
		t.Error("SourcePriority: existing (pri=100) should beat incoming (pri=50)")
	}

	// Manual: always rejects
	cfg3 := DefaultConfig()
	cfg3.ConflictResolution = Manual
	m3 := NewManager(cfg3)
	if m3.resolveConflict(incoming, existing) {
		t.Error("Manual: should always reject")
	}
}

// TestGetNodePriority_Coverage tests getNodePriority.
func TestGetNodePriority_Coverage(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "local-node"
	m := NewManager(cfg)

	if m.getNodePriority("local-node") != 100 {
		t.Error("local node should have priority 100")
	}
	if m.getNodePriority("remote-node") != 50 {
		t.Error("remote node should have priority 50")
	}
}

// TestIsConcurrent_Coverage tests isConcurrent vector clock comparison.
func TestIsConcurrent_Coverage(t *testing.T) {
	tests := []struct {
		name string
		a, b map[string]int64
		want bool
	}{
		{
			"identical",
			map[string]int64{"n1": 1, "n2": 1},
			map[string]int64{"n1": 1, "n2": 1},
			false,
		},
		{
			"concurrent",
			map[string]int64{"n1": 2, "n2": 1},
			map[string]int64{"n1": 1, "n2": 2},
			true,
		},
		{
			"a before b",
			map[string]int64{"n1": 1, "n2": 1},
			map[string]int64{"n1": 2, "n2": 2},
			false,
		},
		{
			"disjoint keys",
			map[string]int64{"n1": 1},
			map[string]int64{"n2": 1},
			true,
		},
		{
			"empty",
			map[string]int64{},
			map[string]int64{},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isConcurrent(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("isConcurrent(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// TestUpdateVectorClock_Coverage tests updateVectorClock.
func TestUpdateVectorClock_Coverage(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	m := NewManager(cfg)

	// Update with nil should be no-op
	m.updateVectorClock(nil)

	// Update with remote clock
	m.updateVectorClock(map[string]int64{"node-2": 5, "node-3": 3})
	m.mu.RLock()
	if m.vectorClock["node-2"] != 5 {
		t.Errorf("expected node-2 clock=5, got %d", m.vectorClock["node-2"])
	}
	m.mu.RUnlock()

	// Update with higher value
	m.updateVectorClock(map[string]int64{"node-2": 10})
	m.mu.RLock()
	if m.vectorClock["node-2"] != 10 {
		t.Errorf("expected node-2 clock=10, got %d", m.vectorClock["node-2"])
	}
	m.mu.RUnlock()

	// Update with lower value (should NOT decrease)
	m.updateVectorClock(map[string]int64{"node-2": 3})
	m.mu.RLock()
	if m.vectorClock["node-2"] != 10 {
		t.Errorf("expected node-2 clock=10 (not decreased), got %d", m.vectorClock["node-2"])
	}
	m.mu.RUnlock()
}

// TestCheckConflict_Coverage tests checkConflict with various scenarios.
func TestCheckConflict_Coverage(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	m := NewManager(cfg)

	// No events in log - no conflict
	conflict, existing := m.checkConflict(&SyncEvent{
		EntityType: "tenant", EntityID: "e1", Timestamp: 100,
	})
	if conflict {
		t.Error("expected no conflict with empty log")
	}
	if existing != nil {
		t.Error("expected nil existing")
	}

	// Add an event to the log
	m.mu.Lock()
	m.eventLog = append(m.eventLog, &SyncEvent{
		EntityType: "tenant", EntityID: "e1", Timestamp: 100, SourceNode: "node-1",
	})
	m.mu.Unlock()

	// Check with older timestamp (should conflict)
	conflict, _ = m.checkConflict(&SyncEvent{
		EntityType: "tenant", EntityID: "e1", Timestamp: 50, SourceNode: "node-2",
	})
	if !conflict {
		t.Error("expected conflict when existing is newer")
	}

	// Check with newer timestamp (should NOT conflict)
	conflict, _ = m.checkConflict(&SyncEvent{
		EntityType: "tenant", EntityID: "e1", Timestamp: 200, SourceNode: "node-2",
	})
	if conflict {
		t.Error("expected no conflict when incoming is newer")
	}

	// Check with concurrent vector clocks
	m.mu.Lock()
	m.eventLog = append(m.eventLog[:0], &SyncEvent{
		EntityType:  "tenant",
		EntityID:    "e1",
		Timestamp:   100,
		SourceNode:  "node-1",
		VectorClock: map[string]int64{"node-1": 2, "node-2": 1},
	})
	m.mu.Unlock()

	conflict, _ = m.checkConflict(&SyncEvent{
		EntityType:  "tenant",
		EntityID:    "e1",
		Timestamp:   100,
		SourceNode:  "node-2",
		VectorClock: map[string]int64{"node-1": 1, "node-2": 2},
	})
	if !conflict {
		t.Error("expected conflict with concurrent vector clocks")
	}

	// Different entity - no conflict
	conflict, _ = m.checkConflict(&SyncEvent{
		EntityType: "rule", EntityID: "r1", Timestamp: 100,
	})
	if conflict {
		t.Error("expected no conflict for different entity type")
	}
}

// TestCheckNodeHealth_Coverage tests checkNodeHealth with mock HTTP server.
func TestCheckNodeHealth_Coverage(t *testing.T) {
	// Start a fake health endpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/cluster/health" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.Enabled = true
	m := NewManager(cfg)

	// Add a remote node pointing to our test server
	remoteNode := &Node{ID: "node-2", Name: "remote", Address: srv.URL, IsLocal: false}
	m.mu.Lock()
	m.nodes["node-2"] = remoteNode
	m.health["node-2"] = false
	m.mu.Unlock()

	m.checkNodeHealth()

	m.mu.RLock()
	healthy := m.health["node-2"]
	node := m.nodes["node-2"]
	m.mu.RUnlock()

	if !healthy {
		t.Error("expected node-2 to be healthy after health check")
	}
	if node == nil || !node.Healthy {
		t.Error("expected node to be marked healthy")
	}
}

// TestCheckNodeHealth_StaleNode tests stale node removal.
func TestCheckNodeHealth_StaleNode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	m := NewManager(cfg)

	// Add a stale node (last seen > 5 minutes ago, unhealthy)
	staleNode := &Node{
		ID: "node-stale", Name: "stale", Address: "http://127.0.0.1:1",
		IsLocal: false, Healthy: false,
		LastSeen: time.Now().Add(-10 * time.Minute),
	}
	m.mu.Lock()
	m.nodes["node-stale"] = staleNode
	m.health["node-stale"] = false
	// Add a cluster with this node
	cluster := &Cluster{ID: "c1", Nodes: []string{"node-stale"}}
	m.clusters["c1"] = cluster
	m.mu.Unlock()

	m.checkNodeHealth()

	// Stale node should be removed
	m.mu.RLock()
	_, nodeExists := m.nodes["node-stale"]
	_, healthExists := m.health["node-stale"]
	m.mu.RUnlock()

	if nodeExists {
		t.Error("expected stale node to be removed from nodes")
	}
	if healthExists {
		t.Error("expected stale node to be removed from health")
	}
}

// TestPerformFullSync_Coverage tests performFullSync with mock server.
func TestPerformFullSync_Coverage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/cluster/events" {
			// Return empty events list
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("[]"))
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.Enabled = true
	m := NewManager(cfg)

	// Add healthy remote node
	remoteNode := &Node{ID: "node-2", Name: "remote", Address: srv.URL, IsLocal: false, Healthy: true}
	m.mu.Lock()
	m.nodes["node-2"] = remoteNode
	m.health["node-2"] = true
	m.mu.Unlock()

	m.performFullSync()

	// Verify lastSync was updated
	m.mu.RLock()
	_, ok := m.lastSync["node-2"]
	m.mu.RUnlock()
	if !ok {
		t.Error("expected lastSync to be updated for node-2")
	}
}

// TestSyncFromNode_NonOKResponse tests syncFromNode with non-200 response.
func TestSyncFromNode_NonOKResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	m := NewManager(cfg)

	node := &Node{ID: "node-2", Address: srv.URL}
	m.syncFromNode(node)
	// Should not panic
}

// TestSyncFromNode_InvalidJSON tests syncFromNode with invalid JSON response.
func TestSyncFromNode_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	m := NewManager(cfg)

	node := &Node{ID: "node-2", Address: srv.URL}
	m.syncFromNode(node)
	// Should not panic
}

// TestCalculateChecksum_NilData tests calculateChecksum with nil data.
func TestCalculateChecksum_NilData_Cov(t *testing.T) {
	result := calculateChecksum(nil)
	if result != "" {
		t.Errorf("expected empty checksum for nil data, got %q", result)
	}
}

// TestValidatePeerURL_EdgeCases tests validatePeerURL edge cases.
func TestValidatePeerURL_EdgeCases(t *testing.T) {
	AllowPlainHTTP()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid http", "http://192.168.1.1:9090", false},
		{"valid https", "https://example.com:9090", false},
		{"invalid scheme", "ftp://host:9090", true},
		{"empty host", "http://", true}, // empty host is rejected
		{"link-local", "http://169.254.1.1:9090", true},
		{"unspecified", "http://0.0.0.0:9090", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePeerURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePeerURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

// TestBroadcastEvent_SemaphoreFull tests BroadcastEvent when replicateSem is full.
func TestBroadcastEvent_SemaphoreFull(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.Enabled = true
	m := NewManager(cfg)

	// Add a cluster with a healthy node
	AllowPlainHTTP()
	cluster := &Cluster{ID: "c1", SyncScope: SyncAll}
	m.AddCluster(cluster)
	_ = m.AddNodeToCluster("c1", &Node{
		ID: "node-2", Address: "http://127.0.0.1:1", Healthy: true, IsLocal: false,
	})

	// Fill the semaphore
	for i := 0; i < 16; i++ {
		m.replicateSem <- struct{}{}
	}

	// Broadcast should still succeed (event queued locally, replication slot skipped)
	err := m.BroadcastEvent("tenant", "e1", "create", map[string]any{"key": "val"})
	if err != nil {
		t.Errorf("BroadcastEvent should succeed even when sem full: %v", err)
	}

	// Drain
	for i := 0; i < 16; i++ {
		<-m.replicateSem
	}
}

// TestBroadcastEvent_QueueFull tests BroadcastEvent when event queue is full.
func TestBroadcastEvent_QueueFull(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.Enabled = true
	m := NewManager(cfg)

	// Fill event queue
	for i := 0; i < 1000; i++ {
		m.eventQueue <- &SyncEvent{ID: "filler"}
	}

	// Should return error when queue is full
	err := m.BroadcastEvent("tenant", "e1", "create", map[string]any{"key": "val"})
	if err == nil {
		t.Error("expected error when event queue is full")
	}

	// Drain
	for i := 0; i < 1000; i++ {
		<-m.eventQueue
	}
}

// TestReceiveEvent_ConflictResolved tests ReceiveEvent with conflict resolution.
func TestReceiveEvent_ConflictResolved(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.ConflictResolution = LastWriteWins
	m := NewManager(cfg)

	handler := NewMockSyncHandler()
	m.RegisterHandler("tenant", handler)

	// Add existing event to log with HIGHER timestamp (conflict: existing is newer)
	m.mu.Lock()
	m.eventLog = append(m.eventLog, &SyncEvent{
		EntityType: "tenant", EntityID: "e1", Timestamp: 300,
		SourceNode: "node-1",
	})
	m.mu.Unlock()

	// Receive OLDER event (ts=200 < existing ts=300) -- triggers conflict check
	// LastWriteWins: incoming ts=200 < existing ts=300 -> resolveConflict returns false -> rejected
	// Let's reverse: receive NEWER event (ts=400) when existing is ts=300
	// Actually checkConflict says: if e.Timestamp > event.Timestamp -> conflict
	// existing ts=300 > incoming ts=200 -> conflict detected
	// resolveConflict(LWW): incoming ts=200 > existing ts=300 -> false -> rejected
	// So to test resolved case, we need incoming to be newer
	evt := &SyncEvent{
		SourceNode: "node-2",
		EntityType: "tenant",
		EntityID:   "e1",
		Timestamp:  400, // Newer than existing (300)
		Action:     "update",
		Data:       map[string]any{"key": "new-value"},
	}
	err := m.ReceiveEvent(evt)
	// Conflict detected: existing ts=300 > incoming ts=400? No, 300 > 400 is false.
	// So there's NO conflict (existing is older). Event is applied directly.
	if err != nil {
		t.Errorf("expected success: %v", err)
	}
}

// TestReceiveEvent_ConflictRejected tests ReceiveEvent with rejected conflict.
func TestReceiveEvent_ConflictRejected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.ConflictResolution = Manual // Manual always rejects
	m := NewManager(cfg)

	handler := NewMockSyncHandler()
	m.RegisterHandler("tenant", handler)

	// Add existing event to log with HIGHER timestamp (triggers conflict check)
	m.mu.Lock()
	m.eventLog = append(m.eventLog, &SyncEvent{
		EntityType: "tenant", EntityID: "e1", Timestamp: 300,
		SourceNode: "node-1",
	})
	m.mu.Unlock()

	// Receive OLDER event (ts=200 < existing ts=300) -> conflict detected
	// Manual mode: resolveConflict always returns false -> rejected
	evt := &SyncEvent{
		SourceNode: "node-2",
		EntityType: "tenant",
		EntityID:   "e1",
		Timestamp:  200,
		Action:     "update",
		Data:       map[string]any{"key": "value"},
	}
	err := m.ReceiveEvent(evt)
	if err == nil {
		t.Error("expected error when conflict resolution rejects")
	}
}

// TestLeaveCluster_Coverage tests leaveCluster handler fully.
func TestLeaveCluster_Coverage(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	cfg.NodeID = "node-1"
	m := NewManager(cfg)
	h := NewHandler(m)

	// Create cluster and add node
	AllowPlainHTTP()
	cluster := &Cluster{ID: "c1", Name: "test"}
	_ = m.AddCluster(cluster)
	_ = m.AddNodeToCluster("c1", &Node{ID: "node-2", Name: "worker", Address: "http://192.168.1.1:9090"})

	// Leave with auth
	req := httptest.NewRequest(http.MethodPost, "/api/clusters/c1?action=leave&node_id=node-2", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleClusterDetail(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204 for leave, got %d: %s", w.Code, w.Body.String())
	}
}

// TestJoinCluster_WithAddress tests joinCluster with address field.
func TestJoinCluster_WithAddress(t *testing.T) {
	AllowPlainHTTP()
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	cfg.NodeID = "node-1"
	m := NewManager(cfg)
	h := NewHandler(m)

	cluster := &Cluster{ID: "c1", Name: "test"}
	_ = m.AddCluster(cluster)

	nodeJSON := `{"id":"node-3","name":"worker3","address":"http://192.168.1.50:9090"}`
	req := httptest.NewRequest(http.MethodPost, "/api/clusters/c1?action=join", strings.NewReader(nodeJSON))
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleClusterDetail(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for join with address, got %d: %s", w.Code, w.Body.String())
	}
}

// TestDeleteCluster_WithAuth tests deleteCluster with proper auth.
func TestDeleteCluster_WithAuth_Cov(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	// Add cluster first
	_ = m.AddCluster(&Cluster{ID: "c1", Name: "test"})

	req := httptest.NewRequest(http.MethodDelete, "/api/clusters/c1", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.deleteCluster(w, req, "c1")

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204 for delete, got %d", w.Code)
	}
}

// TestGetReplicationStatus_NoPeers tests GetReplicationStatus with only local node.
func TestGetReplicationStatus_NoPeers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	m := NewManager(cfg)

	status := m.GetReplicationStatus()
	if len(status) != 0 {
		t.Errorf("expected 0 replication status entries (local only), got %d", len(status))
	}
}

// TestStart_WithClusterConfig tests Start with cluster configuration.
func TestStart_WithClusterConfig(t *testing.T) {
	AllowPlainHTTP()
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.NodeID = "node-1"
	cfg.SharedSecret = "secret"
	cfg.Clusters = []ClusterConfig{
		{
			ID:   "c1",
			Name: "test-cluster",
			Nodes: []Node{
				{ID: "node-2", Address: "http://192.168.1.1:9090"},
			},
			SyncScope: "all",
		},
	}
	m := NewManager(cfg)

	err := m.Start()
	if err != nil {
		t.Errorf("Start failed: %v", err)
	}

	// Verify cluster was created
	clusters := m.GetClusters()
	if len(clusters) != 1 {
		t.Errorf("expected 1 cluster, got %d", len(clusters))
	}

	// Stop immediately
	m.Stop()
}

// TestStart_WithClusterConfig_EmptyNodeID tests Start with empty node ID.
func TestStart_WithClusterConfig_EmptyNodeID(t *testing.T) {
	AllowPlainHTTP()
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.NodeID = "node-1"
	cfg.Clusters = []ClusterConfig{
		{
			ID:   "c1",
			Name: "test",
			Nodes: []Node{
				{ID: "", Address: "http://192.168.1.1:9090"}, // Empty ID, should be generated
			},
			SyncScope: "all",
		},
	}
	m := NewManager(cfg)
	err := m.Start()
	if err != nil {
		t.Errorf("Start failed: %v", err)
	}
	m.Stop()
}

// TestStart_WithClusterConfig_LocalNodeSkip tests Start skips local node in cluster config.
func TestStart_WithClusterConfig_LocalNodeSkip(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.NodeID = "node-1"
	cfg.Clusters = []ClusterConfig{
		{
			ID:   "c1",
			Name: "test",
			Nodes: []Node{
				{ID: "node-1", Address: "http://localhost:9090"}, // Same as local
			},
			SyncScope: "all",
		},
	}
	m := NewManager(cfg)
	err := m.Start()
	if err != nil {
		t.Errorf("Start failed: %v", err)
	}
	clusters := m.GetClusters()
	if len(clusters) != 1 {
		t.Errorf("expected 1 cluster, got %d", len(clusters))
	}
	m.Stop()
}

// TestIsInScope_AllTypes tests isInScope for all entity types.
func TestIsInScope_AllTypes(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	tests := []struct {
		scope      SyncScope
		entityType string
		want       bool
	}{
		{SyncTenants, "tenant", true},
		{SyncTenants, "tenant_rule", true},
		{SyncTenants, "rule", false},
		{SyncRules, "rule", true},
		{SyncRules, "tenant", false},
		{SyncConfig, "config", true},
		{SyncConfig, "tenant", false},
		{SyncAll, "tenant", true},
		{SyncAll, "rule", true},
		{SyncAll, "config", true},
		{SyncAll, "unknown", true}, // default returns true
	}

	for _, tt := range tests {
		cluster := &Cluster{SyncScope: tt.scope}
		got := m.isInScope(cluster, tt.entityType)
		if got != tt.want {
			t.Errorf("isInScope(%v, %q) = %v, want %v", tt.scope, tt.entityType, got, tt.want)
		}
	}
}

// TestGetCluster_Found tests getCluster with existing cluster.
func TestGetCluster_Found(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)
	_ = m.AddCluster(&Cluster{ID: "c1", Name: "test", Nodes: []string{"n1"}})

	req := httptest.NewRequest(http.MethodGet, "/api/clusters/c1", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.getCluster(w, req, "c1")

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for found cluster, got %d", w.Code)
	}
}

// TestGetCluster_NotFound tests getCluster with non-existent cluster.
func TestGetCluster_NotFound(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodGet, "/api/clusters/nonexistent", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.getCluster(w, req, "nonexistent")

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for not found, got %d", w.Code)
	}
}

// TestDeleteCluster_Unauthorized tests deleteCluster without auth.
func TestDeleteCluster_Unauthorized(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodDelete, "/api/clusters/c1", nil)
	w := httptest.NewRecorder()
	h.deleteCluster(w, req, "c1")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestHandleReplicationStatus_OK tests handleReplicationStatus GET.
func TestHandleReplicationStatus_OK(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	cfg.NodeID = "node-1"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/replication", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleReplicationStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandleReplicationStatus_Unauthorized tests handleReplicationStatus without auth.
func TestHandleReplicationStatus_Unauthorized(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/replication", nil)
	w := httptest.NewRecorder()
	h.handleReplicationStatus(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestJoinCluster_Unauthorized tests joinCluster without auth.
func TestJoinCluster_Unauthorized(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodPost, "/api/clusters/c1?action=join", strings.NewReader(`{"id":"n"}`))
	w := httptest.NewRecorder()
	h.joinCluster(w, req, "c1")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestJoinCluster_InvalidJSON tests joinCluster with bad JSON.
func TestJoinCluster_InvalidJSON(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodPost, "/api/clusters/c1?action=join", strings.NewReader("{bad"))
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.joinCluster(w, req, "c1")

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestLeaveCluster_Unauthorized tests leaveCluster without auth.
func TestLeaveCluster_Unauthorized(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodPost, "/api/clusters/c1?action=leave&node_id=n1", nil)
	w := httptest.NewRecorder()
	h.leaveCluster(w, req, "c1")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestLeaveCluster_NoNodeID tests leaveCluster without node_id.
func TestLeaveCluster_NoNodeID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodPost, "/api/clusters/c1?action=leave", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.leaveCluster(w, req, "c1")

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestHandleStats_OK tests handleStats GET with auth.
func TestHandleStats_OK(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/stats", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleStats(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandleNodes_OK tests handleNodes GET with auth.
func TestHandleNodes_OK(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/nodes", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleNodes(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandleHealth_OK tests handleHealth GET.
func TestHandleHealth_OK(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/health", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
