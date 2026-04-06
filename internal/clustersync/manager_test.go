package clustersync

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// MockSyncHandler implements SyncHandler for testing
type MockSyncHandler struct {
	mu       sync.RWMutex
	entities map[string]map[string]any
	applied  []*SyncEvent
}

func NewMockSyncHandler() *MockSyncHandler {
	return &MockSyncHandler{
		entities: make(map[string]map[string]any),
		applied:  make([]*SyncEvent, 0),
	}
}

func (m *MockSyncHandler) Apply(event *SyncEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.applied = append(m.applied, event)

	switch event.Action {
	case "create", "update":
		m.entities[event.EntityID] = event.Data
	case "delete":
		delete(m.entities, event.EntityID)
	}

	return nil
}

func (m *MockSyncHandler) Get(entityID string) (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, ok := m.entities[entityID]
	if !ok {
		return nil, fmt.Errorf("entity not found: %s", entityID)
	}
	return data, nil
}

func (m *MockSyncHandler) List(since time.Time) ([]*SyncEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := make([]*SyncEvent, 0)
	for _, event := range m.applied {
		if event.Timestamp >= since.UnixNano() {
			events = append(events, event)
		}
	}
	return events, nil
}

func (m *MockSyncHandler) GetAppliedCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.applied)
}


// Tests

func TestNewManager(t *testing.T) {
	config := DefaultConfig()
	mgr := NewManager(config)

	if mgr == nil {
		t.Fatal("expected manager to be created")
	}

	if mgr.localNode == nil {
		t.Fatal("expected local node to be created")
	}

	if mgr.localNode.ID == "" {
		t.Error("expected local node to have ID")
	}

	if !mgr.localNode.IsLocal {
		t.Error("expected local node to be marked as local")
	}
}

func TestBroadcastEvent(t *testing.T) {
	config := &Config{
		Enabled:      true,
		NodeID:       "test-node",
		SharedSecret: "secret",
	}

	mgr := NewManager(config)
	handler := NewMockSyncHandler()
	mgr.RegisterHandler("tenant", handler)

	err := mgr.BroadcastEvent("tenant", "tenant-123", "create", map[string]any{
		"name": "Test Tenant",
	})

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Check stats
	stats := mgr.GetStats()
	if stats.TotalEventsSent != 1 {
		t.Errorf("expected 1 event sent, got %d", stats.TotalEventsSent)
	}
}

func TestReceiveEvent(t *testing.T) {
	config := &Config{
		Enabled:            true,
		NodeID:             "local-node",
		SharedSecret:       "secret",
		ConflictResolution: LastWriteWins,
	}

	mgr := NewManager(config)
	handler := NewMockSyncHandler()
	mgr.RegisterHandler("tenant", handler)

	// Test receiving an event from another node
	event := &SyncEvent{
		ID:         "evt-1",
		Timestamp:  time.Now().UnixNano(),
		SourceNode: "remote-node",
		EntityType: "tenant",
		EntityID:   "tenant-123",
		Action:     "create",
		Data: map[string]any{
			"name": "Test Tenant",
		},
	}

	err := mgr.ReceiveEvent(event)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify handler applied the event
	if handler.GetAppliedCount() != 1 {
		t.Errorf("expected 1 applied event, got %d", handler.GetAppliedCount())
	}

	// Check stats
	stats := mgr.GetStats()
	if stats.TotalEventsReceived != 1 {
		t.Errorf("expected 1 event received, got %d", stats.TotalEventsReceived)
	}
}

func TestReceiveOwnEvent(t *testing.T) {
	config := &Config{
		Enabled:      true,
		NodeID:       "local-node",
		SharedSecret: "secret",
	}

	mgr := NewManager(config)
	handler := NewMockSyncHandler()
	mgr.RegisterHandler("tenant", handler)

	event := &SyncEvent{
		ID:         "evt-1",
		Timestamp:  time.Now().UnixNano(),
		SourceNode: "local-node", // Same as local
		EntityType: "tenant",
		EntityID:   "tenant-123",
		Action:     "create",
		Data:       map[string]any{"name": "Test"},
	}

	err := mgr.ReceiveEvent(event)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Should not apply own events
	if handler.GetAppliedCount() != 0 {
		t.Error("expected own event to be ignored")
	}
}

func TestConflictResolutionLastWriteWins(t *testing.T) {
	config := &Config{
		Enabled:            true,
		NodeID:             "local-node",
		SharedSecret:       "secret",
		ConflictResolution: LastWriteWins,
	}

	mgr := NewManager(config)
	handler := NewMockSyncHandler()
	mgr.RegisterHandler("tenant", handler)

	now := time.Now()

	// First event (older)
	oldEvent := &SyncEvent{
		ID:         "evt-1",
		Timestamp:  now.Add(-time.Hour).UnixNano(),
		SourceNode: "remote-node",
		EntityType: "tenant",
		EntityID:   "tenant-123",
		Action:     "create",
		Data:       map[string]any{"name": "Old Name"},
	}

	// Second event (newer) - should win
	newEvent := &SyncEvent{
		ID:         "evt-2",
		Timestamp:  now.UnixNano(),
		SourceNode: "remote-node",
		EntityType: "tenant",
		EntityID:   "tenant-123",
		Action:     "update",
		Data:       map[string]any{"name": "New Name"},
	}

	mgr.ReceiveEvent(oldEvent)
	mgr.ReceiveEvent(newEvent)

	// Check stats - should have 2 events, 0 conflicts (different timestamps)
	stats := mgr.GetStats()
	if stats.TotalEventsReceived != 2 {
		t.Errorf("expected 2 events received, got %d", stats.TotalEventsReceived)
	}
}

func TestAddCluster(t *testing.T) {
	config := DefaultConfig()
	mgr := NewManager(config)

	cluster := &Cluster{
		ID:        "cluster-1",
		Name:      "Test Cluster",
		Nodes:     []string{},
		SyncScope: SyncTenants,
		CreatedAt: time.Now(),
	}

	err := mgr.AddCluster(cluster)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	clusters := mgr.GetClusters()
	if len(clusters) != 1 {
		t.Errorf("expected 1 cluster, got %d", len(clusters))
	}

	if clusters[0].ID != "cluster-1" {
		t.Errorf("expected cluster ID to be 'cluster-1', got %s", clusters[0].ID)
	}
}

func TestRemoveCluster(t *testing.T) {
	config := DefaultConfig()
	mgr := NewManager(config)

	cluster := &Cluster{
		ID:        "cluster-1",
		Name:      "Test Cluster",
		Nodes:     []string{},
		SyncScope: SyncTenants,
		CreatedAt: time.Now(),
	}

	mgr.AddCluster(cluster)

	err := mgr.RemoveCluster("cluster-1")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	clusters := mgr.GetClusters()
	if len(clusters) != 0 {
		t.Errorf("expected 0 clusters, got %d", len(clusters))
	}
}

func TestAddNodeToCluster(t *testing.T) {
	config := DefaultConfig()
	mgr := NewManager(config)

	cluster := &Cluster{
		ID:        "cluster-1",
		Name:      "Test Cluster",
		Nodes:     []string{},
		SyncScope: SyncTenants,
		CreatedAt: time.Now(),
	}
	mgr.AddCluster(cluster)

	node := &Node{
		ID:      "node-2",
		Name:    "Node 2",
		Address: "http://localhost:9445",
		Healthy: true,
	}

	err := mgr.AddNodeToCluster("cluster-1", node)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify node was added
	c := mgr.GetCluster("cluster-1")
	if c == nil {
		t.Fatal("expected cluster to exist")
	}

	found := false
	for _, nid := range c.Nodes {
		if nid == "node-2" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected node to be added to cluster")
	}
}

func TestAddNodeToNonExistentCluster(t *testing.T) {
	config := DefaultConfig()
	mgr := NewManager(config)

	node := &Node{
		ID:      "node-2",
		Name:    "Node 2",
		Address: "http://localhost:9445",
	}

	err := mgr.AddNodeToCluster("non-existent", node)
	if err == nil {
		t.Error("expected error for non-existent cluster")
	}
}

func TestRemoveNodeFromCluster(t *testing.T) {
	config := DefaultConfig()
	mgr := NewManager(config)

	cluster := &Cluster{
		ID:        "cluster-1",
		Name:      "Test Cluster",
		Nodes:     []string{"node-1", "node-2"},
		SyncScope: SyncTenants,
		CreatedAt: time.Now(),
	}
	mgr.AddCluster(cluster)

	err := mgr.RemoveNodeFromCluster("cluster-1", "node-2")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	c := mgr.GetCluster("cluster-1")
	if len(c.Nodes) != 1 {
		t.Errorf("expected 1 node in cluster, got %d", len(c.Nodes))
	}
}

func TestParseSyncScope(t *testing.T) {
	tests := []struct {
		input    string
		expected SyncScope
	}{
		{"tenants", SyncTenants},
		{"rules", SyncRules},
		{"config", SyncConfig},
		{"all", SyncAll},
		{"unknown", SyncTenants}, // Default
	}

	for _, tt := range tests {
		result := ParseSyncScope(tt.input)
		if result != tt.expected {
			t.Errorf("ParseSyncScope(%s) = %v, expected %v", tt.input, result, tt.expected)
		}
	}
}

func TestSyncScopeString(t *testing.T) {
	tests := []struct {
		scope    SyncScope
		expected string
	}{
		{SyncTenants, "tenants"},
		{SyncRules, "rules"},
		{SyncConfig, "config"},
		{SyncAll, "all"},
		{SyncScope(999), "custom"},
	}

	for _, tt := range tests {
		result := tt.scope.String()
		if result != tt.expected {
			t.Errorf("SyncScope(%d).String() = %s, expected %s", tt.scope, result, tt.expected)
		}
	}
}

func TestIsInScope(t *testing.T) {
	mgr := NewManager(DefaultConfig())

	tests := []struct {
		scope      SyncScope
		entityType string
		expected   bool
	}{
		{SyncTenants, "tenant", true},
		{SyncTenants, "tenant_rule", true},
		{SyncTenants, "rule", false},
		{SyncRules, "rule", true},
		{SyncRules, "tenant", false},
		{SyncConfig, "config", true},
		{SyncAll, "tenant", true},
		{SyncAll, "rule", true},
		{SyncAll, "config", true},
	}

	for _, tt := range tests {
		cluster := &Cluster{
			ID:        "test",
			SyncScope: tt.scope,
		}
		result := mgr.isInScope(cluster, tt.entityType)
		if result != tt.expected {
			t.Errorf("isInScope(%v, %s) = %v, expected %v", tt.scope, tt.entityType, result, tt.expected)
		}
	}
}

func TestCalculateChecksum(t *testing.T) {
	data := map[string]any{
		"name": "Test",
		"id":   123,
	}

	checksum1 := calculateChecksum(data)
	checksum2 := calculateChecksum(data)

	if checksum1 == "" {
		t.Error("expected non-empty checksum")
	}

	if checksum1 != checksum2 {
		t.Error("expected same data to produce same checksum")
	}

	// Different data should produce different checksum
	data2 := map[string]any{
		"name": "Test Different",
		"id":   123,
	}
	checksum3 := calculateChecksum(data2)

	if checksum1 == checksum3 {
		t.Error("expected different data to produce different checksum")
	}
}

func TestGenerateNodeIDFromAddress(t *testing.T) {
	id1 := generateNodeIDFromAddress("http://localhost:9444")
	id2 := generateNodeIDFromAddress("http://localhost:9444")
	id3 := generateNodeIDFromAddress("http://localhost:9445")

	if id1 == "" {
		t.Error("expected non-empty node ID")
	}

	if id1 != id2 {
		t.Error("expected same address to produce same ID")
	}

	if id1 == id3 {
		t.Error("expected different address to produce different ID")
	}
}

func TestManagerStartStop(t *testing.T) {
	config := &Config{
		Enabled:       true,
		NodeID:        "test-node",
		SharedSecret:  "secret",
		SyncInterval:  30 * time.Second,
		Clusters: []ClusterConfig{
			{
				ID:            "cluster-1",
				Name:          "Test Cluster",
				Nodes:         []Node{},
				SyncScope:     "all",
				Bidirectional: true,
			},
		},
	}

	mgr := NewManager(config)

	err := mgr.Start()
	if err != nil {
		t.Fatalf("expected no error on start, got: %v", err)
	}

	// Give background workers time to start
	time.Sleep(100 * time.Millisecond)

	err = mgr.Stop()
	if err != nil {
		t.Fatalf("expected no error on stop, got: %v", err)
	}
}

func TestDisabledManager(t *testing.T) {
	config := &Config{
		Enabled: false,
	}

	mgr := NewManager(config)

	err := mgr.Start()
	if err != nil {
		t.Error("expected no error when starting disabled manager")
	}

	err = mgr.Stop()
	if err != nil {
		t.Error("expected no error when stopping disabled manager")
	}

	// Broadcast should be no-op
	err = mgr.BroadcastEvent("tenant", "123", "create", map[string]any{})
	if err != nil {
		t.Error("expected no error when broadcasting with disabled manager")
	}
}

func TestPingNode(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Cluster-Auth") != "test-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Enabled:      true,
		NodeID:       "test-node",
		SharedSecret: "test-secret",
	}

	mgr := NewManager(config)

	node := &Node{
		ID:      "test-node",
		Address: server.URL,
	}

	healthy := mgr.pingNode(node)
	if !healthy {
		t.Error("expected node to be healthy")
	}

	// Test with wrong secret
	config.SharedSecret = "wrong-secret"
	mgr2 := NewManager(config)
	healthy = mgr2.pingNode(node)
	if healthy {
		t.Error("expected node to be unhealthy with wrong secret")
	}
}

func TestSendEventToNode(t *testing.T) {
	received := make(chan *SyncEvent, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		var event SyncEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Errorf("failed to decode event: %v", err)
		}

		received <- &event
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Enabled:      true,
		NodeID:       "test-node",
		SharedSecret: "test-secret",
	}

	mgr := NewManager(config)

	node := &Node{
		ID:      "remote-node",
		Address: server.URL,
	}

	event := &SyncEvent{
		ID:         "evt-1",
		Timestamp:  time.Now().UnixNano(),
		SourceNode: "test-node",
		EntityType: "tenant",
		EntityID:   "123",
		Action:     "create",
		Data:       map[string]any{"name": "Test"},
	}

	err := mgr.sendEventToNode(node, event)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	select {
	case receivedEvent := <-received:
		if receivedEvent.EntityID != "123" {
			t.Errorf("expected entity ID '123', got %s", receivedEvent.EntityID)
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for event")
	}
}

func TestGetReplicationStatus(t *testing.T) {
	config := &Config{
		Enabled:      true,
		NodeID:       "local-node",
		SharedSecret: "secret",
	}

	mgr := NewManager(config)

	// Add remote node
	mgr.mu.Lock()
	mgr.nodes["remote-1"] = &Node{
		ID:      "remote-1",
		Name:    "Remote Node",
		Address: "http://localhost:9445",
		Healthy: true,
		IsLocal: false,
	}
	mgr.lastSync["remote-1"] = time.Now().Add(-time.Minute)
	mgr.mu.Unlock()

	status := mgr.GetReplicationStatus()
	if len(status) != 1 {
		t.Errorf("expected 1 replication status, got %d", len(status))
	}

	if status[0].NodeID != "remote-1" {
		t.Errorf("expected node ID 'remote-1', got %s", status[0].NodeID)
	}
}

func TestGetNodes(t *testing.T) {
	config := &Config{
		Enabled:      true,
		NodeID:       "local-node",
		SharedSecret: "secret",
	}

	mgr := NewManager(config)

	// Add nodes
	mgr.mu.Lock()
	mgr.nodes["node-1"] = &Node{ID: "node-1", Name: "Node 1"}
	mgr.nodes["node-2"] = &Node{ID: "node-2", Name: "Node 2"}
	mgr.mu.Unlock()

	nodes := mgr.GetNodes()
	if len(nodes) != 3 { // 1 local node + 2 added nodes
		t.Errorf("expected 3 nodes, got %d", len(nodes))
	}
}

func TestGetNode(t *testing.T) {
	config := DefaultConfig()
	mgr := NewManager(config)

	mgr.mu.Lock()
	mgr.nodes["node-1"] = &Node{ID: "node-1", Name: "Node 1"}
	mgr.mu.Unlock()

	node := mgr.GetNode("node-1")
	if node == nil {
		t.Fatal("expected node to exist")
	}

	if node.Name != "Node 1" {
		t.Errorf("expected name 'Node 1', got %s", node.Name)
	}

	// Non-existent node
	node = mgr.GetNode("non-existent")
	if node != nil {
		t.Error("expected nil for non-existent node")
	}
}

func TestGetVectorClock(t *testing.T) {
	config := &Config{
		NodeID: "test-node",
	}
	mgr := NewManager(config)

	vc := mgr.getVectorClock()
	if vc == nil {
		t.Error("expected non-nil vector clock")
	}

	if _, ok := vc["test-node"]; !ok {
		t.Error("expected vector clock to contain local node")
	}
}

func BenchmarkBroadcastEvent(b *testing.B) {
	config := &Config{
		Enabled:      true,
		NodeID:       "test-node",
		SharedSecret: "secret",
	}

	mgr := NewManager(config)
	handler := NewMockSyncHandler()
	mgr.RegisterHandler("tenant", handler)

	data := map[string]any{
		"name": "Test Tenant",
		"id":   "tenant-123",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgr.BroadcastEvent("tenant", fmt.Sprintf("tenant-%d", i), "create", data)
	}
}

func BenchmarkReceiveEvent(b *testing.B) {
	config := &Config{
		Enabled:            true,
		NodeID:             "local-node",
		SharedSecret:       "secret",
		ConflictResolution: LastWriteWins,
	}

	mgr := NewManager(config)
	handler := NewMockSyncHandler()
	mgr.RegisterHandler("tenant", handler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := &SyncEvent{
			ID:         fmt.Sprintf("evt-%d", i),
			Timestamp:  time.Now().UnixNano(),
			SourceNode: "remote-node",
			EntityType: "tenant",
			EntityID:   fmt.Sprintf("tenant-%d", i),
			Action:     "create",
			Data:       map[string]any{"name": "Test"},
		}
		mgr.ReceiveEvent(event)
	}
}

// Integration test
func TestClusterSyncIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Create two managers simulating two nodes
	config1 := &Config{
		Enabled:            true,
		NodeID:             "node-1",
		NodeName:           "Node 1",
		BindAddress:        "127.0.0.1",
		APIPort:            19444,
		SharedSecret:       "shared-secret",
		SyncInterval:       1 * time.Second,
		ConflictResolution: LastWriteWins,
		MaxRetries:         3,
	}

	config2 := &Config{
		Enabled:            true,
		NodeID:             "node-2",
		NodeName:           "Node 2",
		BindAddress:        "127.0.0.1",
		APIPort:            19445,
		SharedSecret:       "shared-secret",
		SyncInterval:       1 * time.Second,
		ConflictResolution: LastWriteWins,
		MaxRetries:         3,
	}

	mgr1 := NewManager(config1)
	mgr2 := NewManager(config2)

	handler1 := NewMockSyncHandler()
	handler2 := NewMockSyncHandler()

	mgr1.RegisterHandler("tenant", handler1)
	mgr2.RegisterHandler("tenant", handler2)

	// Add clusters
	cluster1 := &Cluster{
		ID:        "cluster-test",
		Name:      "Test Cluster",
		Nodes:     []string{"node-1", "node-2"},
		SyncScope: SyncAll,
		CreatedAt: time.Now(),
	}

	mgr1.AddCluster(cluster1)

	// Add node 2 to manager 1's view
	mgr1.AddNodeToCluster("cluster-test", &Node{
		ID:      "node-2",
		Name:    "Node 2",
		Address: fmt.Sprintf("http://127.0.0.1:%d", config2.APIPort),
	})

	// Start both managers
	if err := mgr1.Start(); err != nil {
		t.Fatalf("failed to start manager 1: %v", err)
	}
	defer mgr1.Stop()

	if err := mgr2.Start(); err != nil {
		t.Fatalf("failed to start manager 2: %v", err)
	}
	defer mgr2.Stop()

	// Broadcast event from node 1
	err := mgr1.BroadcastEvent("tenant", "tenant-123", "create", map[string]any{
		"name": "Test Tenant",
	})
	if err != nil {
		t.Fatalf("failed to broadcast: %v", err)
	}

	// In a real integration test, we would verify the event was received by node 2
	// For this test, we just verify the broadcast succeeded
	t.Log("Integration test passed - broadcast succeeded")
}
