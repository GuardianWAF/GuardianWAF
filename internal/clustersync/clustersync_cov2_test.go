package clustersync

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Handler coverage tests ---

// TestHandleEvents_WithListHandler covers handleEvents when a handler
// implements the List interface and returns events.
func TestHandleEvents_WithListHandler(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	// Register a mock handler that returns events from List
	mock := &listReturningHandler{
		events: []*SyncEvent{
			{ID: "evt-1", EntityType: "tenant", EntityID: "e1", Action: "create"},
			{ID: "evt-2", EntityType: "tenant", EntityID: "e2", Action: "update"},
		},
	}
	m.RegisterHandler("tenant", mock)

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/events?since=1000000", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleEvents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var events []*SyncEvent
	if err := json.NewDecoder(w.Body).Decode(&events); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}
}

// TestHandleEvents_ListError covers handleEvents when handler's List returns error.
func TestHandleEvents_ListError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	mock := &listReturningHandler{err: fmt.Errorf("db error")}
	m.RegisterHandler("tenant", mock)

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/events", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleEvents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (errors are skipped), got %d", w.Code)
	}

	// Should return empty list since List errored
	var events []*SyncEvent
	if err := json.NewDecoder(w.Body).Decode(&events); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events when List errors, got %d", len(events))
	}
}

// TestHandleEvents_NoAuth covers handleEvents without auth.
func TestHandleEvents_NoAuth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/events", nil)
	w := httptest.NewRecorder()
	h.handleEvents(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestCreateCluster_AutoID covers createCluster with empty ID (auto-generated).
func TestCreateCluster_AutoID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	clusterJSON := `{"name":"auto-id-cluster","description":"ID should be auto-generated"}`
	req := httptest.NewRequest(http.MethodPost, "/api/clusters", strings.NewReader(clusterJSON))
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.createCluster(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	id, _ := result["id"].(string)
	if id == "" {
		t.Error("expected auto-generated cluster ID")
	}
	if !strings.HasPrefix(id, "cluster-") {
		t.Errorf("expected ID to start with 'cluster-', got %q", id)
	}
}

// TestCreateCluster_WithNodes covers createCluster with nodes in the payload.
func TestCreateCluster_WithNodes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	clusterJSON := `{"id":"c-with-nodes","name":"cluster-with-nodes","nodes":["n1","n2"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/clusters", strings.NewReader(clusterJSON))
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.createCluster(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if result["id"] != "c-with-nodes" {
		t.Errorf("expected id 'c-with-nodes', got %v", result["id"])
	}
}

// TestGetCluster_SuccessWithNodes covers getCluster with cluster that has nodes.
func TestGetCluster_SuccessWithNodes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	_ = m.AddCluster(&Cluster{
		ID:        "c-detail",
		Name:      "Detail Cluster",
		Nodes:     []string{"n1", "n2"},
		SyncScope: SyncAll,
		CreatedAt: time.Now(),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/clusters/c-detail", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.getCluster(w, req, "c-detail")

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	nodes, ok := result["nodes"].([]any)
	if !ok || len(nodes) != 2 {
		t.Errorf("expected 2 nodes, got %v", result["nodes"])
	}
}

// TestGetCluster_NoAuth covers getCluster without auth.
func TestGetCluster_NoAuth_Cov2(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodGet, "/api/clusters/c1", nil)
	w := httptest.NewRecorder()
	h.getCluster(w, req, "c1")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestDeleteCluster_NoAuth_Cov2 covers deleteCluster without auth.
func TestDeleteCluster_NoAuth_Cov2(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodDelete, "/api/clusters/c1", nil)
	w := httptest.NewRecorder()
	h.deleteCluster(w, req, "c1")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestDeleteCluster_Success covers deleteCluster of an existing cluster.
func TestDeleteCluster_Success(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	_ = m.AddCluster(&Cluster{ID: "c-del", Name: "to-delete"})

	req := httptest.NewRequest(http.MethodDelete, "/api/clusters/c-del", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.deleteCluster(w, req, "c-del")

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}

	// Verify cluster was actually removed
	if m.GetCluster("c-del") != nil {
		t.Error("expected cluster to be deleted")
	}
}

// TestHandleClusterDetail_MethodNotAllowed covers unsupported methods on cluster detail.
func TestHandleClusterDetail_MethodNotAllowed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodPut, "/api/clusters/c1", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleClusterDetail(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// --- Manager coverage tests ---

// TestReplicationWorker_ZeroInterval covers replicationWorker with zero sync interval.
func TestReplicationWorker_ZeroInterval(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.NodeID = "node-1"
	cfg.SyncInterval = 0 // Zero interval, should default to 30s

	m := NewManager(cfg)

	// Start and immediately stop - exercises the zero-interval path
	m.Start()
	time.Sleep(50 * time.Millisecond)
	m.Stop()
}

// TestReplicationWorker_NegativeInterval covers replicationWorker with negative sync interval.
func TestReplicationWorker_NegativeInterval(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.NodeID = "node-1"
	cfg.SyncInterval = -1 * time.Second // Negative interval

	m := NewManager(cfg)
	m.Start()
	time.Sleep(50 * time.Millisecond)
	m.Stop()
}

// TestSendEventToNode_NonOKResponse covers sendEventToNode when the target returns non-200.
func TestSendEventToNode_NonOKResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)

	node := &Node{ID: "node-2", Address: srv.URL}
	event := &SyncEvent{
		ID: "evt-1", SourceNode: "node-1",
		EntityType: "tenant", EntityID: "e1", Action: "create",
	}

	err := m.sendEventToNode(node, event)
	if err == nil {
		t.Error("expected error for non-200 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected error to mention status 500, got %v", err)
	}
}

// TestSendEventToNode_ConflictResponse covers sendEventToNode when the target returns 409.
func TestSendEventToNode_ConflictResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)

	node := &Node{ID: "node-2", Address: srv.URL}
	event := &SyncEvent{
		ID: "evt-1", SourceNode: "node-1",
		EntityType: "tenant", EntityID: "e1", Action: "create",
	}

	err := m.sendEventToNode(node, event)
	if err == nil {
		t.Error("expected error for 409 response")
	}
}

// TestSendEventToNode_Success verifies lastSync is updated on success.
func TestSendEventToNode_Success_LastSync(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers
		if r.Header.Get("X-Cluster-Auth") != "secret" {
			t.Errorf("expected X-Cluster-Auth header")
		}
		if r.Header.Get("X-Source-Node") != "node-1" {
			t.Errorf("expected X-Source-Node header")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type header")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)

	node := &Node{ID: "node-2", Address: srv.URL}
	event := &SyncEvent{
		ID: "evt-1", SourceNode: "node-1",
		EntityType: "tenant", EntityID: "e1", Action: "create",
	}

	err := m.sendEventToNode(node, event)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify lastSync was updated
	m.mu.RLock()
	_, ok := m.lastSync["node-2"]
	m.mu.RUnlock()
	if !ok {
		t.Error("expected lastSync to be updated for node-2")
	}
}

// TestSendEventToNode_InvalidURL covers sendEventToNode with invalid URL.
func TestSendEventToNode_InvalidURL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)

	node := &Node{ID: "node-bad", Address: "http://[::1]:namedport"} // invalid URL
	event := &SyncEvent{
		ID: "evt-1", SourceNode: "node-1",
		EntityType: "tenant", EntityID: "e1", Action: "create",
	}

	// Should not panic; returns error
	err := m.sendEventToNode(node, event)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

// TestReplicateEvent_ScopedCluster covers replicateEvent skipping out-of-scope entity types.
func TestReplicateEvent_ScopedCluster(t *testing.T) {
	AllowPlainHTTP()

	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)

	// Create cluster scoped to SyncRules only
	cluster := &Cluster{ID: "c1", SyncScope: SyncRules}
	_ = m.AddCluster(cluster)
	_ = m.AddNodeToCluster("c1", &Node{
		ID: "node-2", Address: "http://192.168.1.1:9090", Healthy: true, IsLocal: false,
	})

	event := &SyncEvent{
		ID: "evt-1", SourceNode: "node-1",
		EntityType: "tenant", // Not in SyncRules scope
		EntityID:   "e1", Action: "create",
	}

	// Should skip replication because entity type not in scope
	m.replicateEvent(event)
	// No panic = success
}

// TestReplicateEvent_InScopeWithCluster covers replicateEvent with in-scope entity.
func TestReplicateEvent_InScopeWithCluster(t *testing.T) {
	AllowPlainHTTP()

	// Create a server that accepts sync events
	received := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)

	cluster := &Cluster{ID: "c1", SyncScope: SyncAll}
	_ = m.AddCluster(cluster)
	_ = m.AddNodeToCluster("c1", &Node{
		ID: "node-2", Address: srv.URL, Healthy: true, IsLocal: false,
	})

	event := &SyncEvent{
		ID: "evt-1", SourceNode: "node-1",
		EntityType: "tenant", EntityID: "e1", Action: "create",
	}

	m.replicateEvent(event)

	// Wait for the async call or timeout
	select {
	case <-received:
		// Success - event was replicated
	case <-time.After(2 * time.Second):
		t.Error("expected event to be replicated to node-2")
	}
}

// TestResolveConflict_DefaultCase covers the default case in resolveConflict.
func TestResolveConflict_DefaultCase(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ConflictResolution = ConflictResolution(99) // Unknown value
	m := NewManager(cfg)

	incoming := &SyncEvent{SourceNode: "node-2", Timestamp: 200}
	existing := &SyncEvent{SourceNode: "node-1", Timestamp: 100}

	// Default falls through to timestamp comparison
	if !m.resolveConflict(incoming, existing) {
		t.Error("default: incoming (ts=200) should beat existing (ts=100)")
	}

	// Reverse
	if m.resolveConflict(existing, incoming) {
		t.Error("default: existing (ts=100) should lose to incoming (ts=200)")
	}
}

// TestResolveConflict_SourcePriority_EqualPriority covers SourcePriority with equal priorities.
func TestResolveConflict_SourcePriority_EqualPriority(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.ConflictResolution = SourcePriority
	m := NewManager(cfg)

	incoming := &SyncEvent{SourceNode: "node-2", Timestamp: 200}
	existing := &SyncEvent{SourceNode: "node-3", Timestamp: 100}

	// Both are remote nodes, both have priority 50. 50 > 50 = false
	if m.resolveConflict(incoming, existing) {
		t.Error("equal priorities: incoming should not win")
	}
}

// TestReceiveEvent_NoHandler covers ReceiveEvent with unregistered entity type.
func TestReceiveEvent_NoHandler(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	m := NewManager(cfg)

	evt := &SyncEvent{
		ID: "evt-1", SourceNode: "node-2",
		EntityType: "unknown_type", EntityID: "e1", Action: "create",
	}

	err := m.ReceiveEvent(evt)
	if err == nil {
		t.Error("expected error for unknown entity type")
	}
	if !strings.Contains(err.Error(), "no handler") {
		t.Errorf("expected 'no handler' error, got %v", err)
	}
}

// TestReceiveEvent_ApplyError covers ReceiveEvent when handler.Apply fails.
func TestReceiveEvent_ApplyError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	m := NewManager(cfg)

	m.RegisterHandler("tenant", &errorApplyHandler{})

	evt := &SyncEvent{
		ID: "evt-1", SourceNode: "node-2",
		EntityType: "tenant", EntityID: "e1", Action: "create",
		Data: map[string]any{"key": "value"},
	}

	err := m.ReceiveEvent(evt)
	if err == nil {
		t.Error("expected error when Apply fails")
	}
	if !strings.Contains(err.Error(), "applying event") {
		t.Errorf("expected 'applying event' in error, got %v", err)
	}
}

// TestSyncFromNode_ValidEvents covers syncFromNode receiving valid events from a remote node.
func TestSyncFromNode_ValidEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		events := []*SyncEvent{
			{ID: "evt-1", SourceNode: "node-2", EntityType: "tenant", EntityID: "e1", Action: "create", Timestamp: time.Now().UnixNano()},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	m := NewManager(cfg)

	// Register a handler so ReceiveEvent succeeds
	m.RegisterHandler("tenant", NewMockSyncHandler())

	node := &Node{ID: "node-2", Address: srv.URL}
	m.syncFromNode(node)

	// Verify lastSync was updated
	m.mu.RLock()
	_, ok := m.lastSync["node-2"]
	m.mu.RUnlock()
	if !ok {
		t.Error("expected lastSync to be updated after syncFromNode")
	}
}

// TestSyncFromNode_ReceiveError covers syncFromNode when ReceiveEvent fails for some events.
func TestSyncFromNode_ReceiveError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		events := []*SyncEvent{
			{ID: "evt-1", SourceNode: "node-2", EntityType: "unknown_type", EntityID: "e1", Action: "create"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	m := NewManager(cfg)

	// No handler registered for "unknown_type" so ReceiveEvent will error
	node := &Node{ID: "node-2", Address: srv.URL}
	m.syncFromNode(node)

	// syncFromNode should not panic; it just logs and continues
}

// TestPingNode_Error covers pingNode with unreachable node.
func TestPingNode_Error(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)

	node := &Node{ID: "node-bad", Address: "http://127.0.0.1:1"} // Port 1 will fail
	healthy := m.pingNode(node)
	if healthy {
		t.Error("expected unhealthy for unreachable node")
	}
}

// TestPingNode_InvalidURL covers pingNode with malformed URL.
func TestPingNode_InvalidURL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)

	node := &Node{ID: "node-bad", Address: "http://[::1]:namedport"}
	healthy := m.pingNode(node)
	if healthy {
		t.Error("expected unhealthy for invalid URL")
	}
}

// TestRemoveNodeFromCluster_NonExistentCluster covers RemoveNodeFromCluster with bad cluster.
func TestRemoveNodeFromCluster_NonExistentCluster(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	err := m.RemoveNodeFromCluster("nonexistent", "node-1")
	if err == nil {
		t.Error("expected error for non-existent cluster")
	}
}

// TestAddNodeToCluster_Duplicate covers AddNodeToCluster with an already-added node.
func TestAddNodeToCluster_Duplicate(t *testing.T) {
	AllowPlainHTTP()
	cfg := DefaultConfig()
	m := NewManager(cfg)

	_ = m.AddCluster(&Cluster{ID: "c1", Name: "test"})
	_ = m.AddNodeToCluster("c1", &Node{ID: "n1", Address: "http://192.168.1.1:9090"})
	err := m.AddNodeToCluster("c1", &Node{ID: "n1", Address: "http://192.168.1.1:9090"})
	if err != nil {
		t.Errorf("expected nil for duplicate add (idempotent), got %v", err)
	}
}

// TestLeaveCluster_NonExistentCluster covers leaveCluster with non-existent cluster.
func TestLeaveCluster_NonExistentCluster(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	req := httptest.NewRequest(http.MethodPost, "/api/clusters/nonexistent?action=leave&node_id=n1", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.leaveCluster(w, req, "nonexistent")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for non-existent cluster, got %d", w.Code)
	}
}

// TestLeaveCluster_Success covers leaveCluster removing a node from a cluster.
func TestLeaveCluster_Success(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	cfg.NodeID = "node-1"
	m := NewManager(cfg)
	h := NewHandler(m)

	_ = m.AddCluster(&Cluster{ID: "c1", Name: "test"})
	_ = m.AddNodeToCluster("c1", &Node{ID: "node-2", Address: "http://192.168.1.1:9090"})

	req := httptest.NewRequest(http.MethodPost, "/api/clusters/c1?action=leave&node_id=node-2", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.leaveCluster(w, req, "c1")

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
}

// TestJoinCluster_NonExistentCluster covers joinCluster with non-existent cluster.
func TestJoinCluster_NonExistentCluster(t *testing.T) {
	AllowPlainHTTP()
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	nodeJSON := `{"id":"node-2","name":"worker","address":"http://192.168.1.1:9090"}`
	req := httptest.NewRequest(http.MethodPost, "/api/clusters/nonexistent?action=join", strings.NewReader(nodeJSON))
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.joinCluster(w, req, "nonexistent")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for non-existent cluster, got %d: %s", w.Code, w.Body.String())
	}
}

// TestJoinCluster_Success covers joinCluster with valid node data.
func TestJoinCluster_Success(t *testing.T) {
	AllowPlainHTTP()
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	cfg.NodeID = "node-1"
	m := NewManager(cfg)
	h := NewHandler(m)

	_ = m.AddCluster(&Cluster{ID: "c1", Name: "test"})

	nodeJSON := `{"id":"node-2","name":"worker","address":"http://192.168.1.1:9090"}`
	req := httptest.NewRequest(http.MethodPost, "/api/clusters/c1?action=join", strings.NewReader(nodeJSON))
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.joinCluster(w, req, "c1")

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if result["id"] != "node-2" {
		t.Errorf("expected id 'node-2', got %v", result["id"])
	}
}

// TestHandleClusterDetail_GetWithAuth covers GET on handleClusterDetail with auth.
func TestHandleClusterDetail_GetWithAuth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	_ = m.AddCluster(&Cluster{
		ID:        "c1",
		Name:      "test",
		Nodes:     []string{},
		SyncScope: SyncTenants,
		CreatedAt: time.Now(),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/clusters/c1", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleClusterDetail(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleClusterDetail_DeleteWithAuth covers DELETE on handleClusterDetail with auth.
func TestHandleClusterDetail_DeleteWithAuth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SharedSecret = "secret"
	m := NewManager(cfg)
	h := NewHandler(m)

	_ = m.AddCluster(&Cluster{ID: "c1", Name: "test"})

	req := httptest.NewRequest(http.MethodDelete, "/api/clusters/c1", nil)
	req.Header.Set("X-Cluster-Auth", "secret")
	w := httptest.NewRecorder()
	h.handleClusterDetail(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

// --- Helper types for testing ---

// listReturningHandler implements SyncHandler and returns configurable results from List.
type listReturningHandler struct {
	mu     sync.RWMutex
	events []*SyncEvent
	err    error
}

func (h *listReturningHandler) Apply(event *SyncEvent) error {
	return nil
}

func (h *listReturningHandler) Get(entityID string) (map[string]any, error) {
	return nil, nil
}

func (h *listReturningHandler) List(since time.Time) ([]*SyncEvent, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.err != nil {
		return nil, h.err
	}
	return h.events, nil
}

// errorApplyHandler implements SyncHandler and always returns error from Apply.
type errorApplyHandler struct{}

func (h *errorApplyHandler) Apply(event *SyncEvent) error {
	return errors.New("apply failed")
}

func (h *errorApplyHandler) Get(entityID string) (map[string]any, error) {
	return nil, nil
}

func (h *errorApplyHandler) List(since time.Time) ([]*SyncEvent, error) {
	return nil, nil
}
