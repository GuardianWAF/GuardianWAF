package cluster

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("expected cluster to be disabled by default")
	}

	if cfg.BindAddr != "0.0.0.0" {
		t.Errorf("bind_addr = %s, want 0.0.0.0", cfg.BindAddr)
	}

	if cfg.BindPort != 7946 {
		t.Errorf("bind_port = %d, want 7946", cfg.BindPort)
	}

	if cfg.HeartbeatInterval != 5*time.Second {
		t.Errorf("heartbeat_interval = %v, want 5s", cfg.HeartbeatInterval)
	}

	if cfg.HeartbeatTimeout != 15*time.Second {
		t.Errorf("heartbeat_timeout = %v, want 15s", cfg.HeartbeatTimeout)
	}
}

func TestNewCluster(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if cluster == nil {
		t.Fatal("expected cluster, got nil")
	}

	if cluster.localNode == nil {
		t.Error("expected localNode to be set")
	}

	if cluster.config != cfg {
		t.Error("config mismatch")
	}

	if cluster.state != StateJoining {
		t.Errorf("state = %s, want joining", cluster.state)
	}
}

func TestCluster_StartStop_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Should not fail when disabled
	if err := cluster.Start(); err != nil {
		t.Errorf("Start failed: %v", err)
	}

	if err := cluster.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}

func TestCluster_NodeIDGeneration(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.NodeID = "" // Empty to trigger generation

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if cluster.localNode.ID == "" {
		t.Error("expected node ID to be generated")
	}

	if len(cluster.localNode.ID) != 16 { // 8 bytes hex encoded
		t.Errorf("node ID length = %d, want 16", len(cluster.localNode.ID))
	}
}

func TestCluster_AdvertiseAddrFallback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BindAddr = "192.168.1.100"
	cfg.AdvertiseAddr = "" // Empty to trigger fallback

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if cluster.localNode.Address != "192.168.1.100" {
		t.Errorf("advertise_addr = %s, want 192.168.1.100", cluster.localNode.Address)
	}
}

func TestCluster_IPBan(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Initially not banned
	if cluster.IsIPBanned("1.2.3.4") {
		t.Error("IP should not be banned initially")
	}

	// Ban the IP
	cluster.BanIP("1.2.3.4", time.Hour)

	// Should be banned
	if !cluster.IsIPBanned("1.2.3.4") {
		t.Error("IP should be banned")
	}

	// Different IP should not be banned
	if cluster.IsIPBanned("5.6.7.8") {
		t.Error("different IP should not be banned")
	}
}

func TestCluster_IPBanExpiry(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Ban with very short TTL
	cluster.BanIP("1.2.3.4", 1*time.Millisecond)

	// Should be banned immediately
	if !cluster.IsIPBanned("1.2.3.4") {
		t.Error("IP should be banned")
	}

	// Wait for expiry
	time.Sleep(10 * time.Millisecond)

	// Should no longer be banned
	if cluster.IsIPBanned("1.2.3.4") {
		t.Error("IP ban should have expired")
	}
}

func TestCluster_UnbanIP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Ban the IP
	cluster.BanIP("1.2.3.4", time.Hour)
	if !cluster.IsIPBanned("1.2.3.4") {
		t.Fatal("IP should be banned")
	}

	// Unban the IP
	cluster.UnbanIP("1.2.3.4")

	// Should not be banned anymore
	if cluster.IsIPBanned("1.2.3.4") {
		t.Error("IP should not be banned after unban")
	}
}

func TestCluster_LeaderElection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.NodeID = "node-a"

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Initially not leader
	if cluster.IsLeader() {
		t.Error("should not be leader initially")
	}

	// Simulate becoming leader manually
	cluster.nodes["node-a"] = cluster.localNode
	cluster.nodes["node-b"] = &Node{ID: "node-b", State: StateActive}
	cluster.startLeaderElection()

	// Lower ID should be leader
	if !cluster.IsLeader() {
		t.Error("node-a should be leader (lower ID)")
	}

	// Test with higher ID node
	cfg2 := DefaultConfig()
	cfg2.Enabled = true
	cfg2.NodeID = "node-z"

	cluster2, err := New(cfg2)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	cluster2.nodes["node-a"] = &Node{ID: "node-a", State: StateActive}
	cluster2.nodes["node-z"] = cluster2.localNode
	cluster2.startLeaderElection()

	if cluster2.IsLeader() {
		t.Error("node-z should not be leader (higher ID)")
	}
}

func TestCluster_GetNodes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Add some nodes
	cluster.nodes["node-1"] = &Node{ID: "node-1", State: StateActive}
	cluster.nodes["node-2"] = &Node{ID: "node-2", State: StateActive}
	cluster.nodes["node-3"] = &Node{ID: "node-3", State: StateFailed}

	nodes := cluster.GetNodes()
	if len(nodes) != 3 {
		t.Errorf("nodes count = %d, want 3", len(nodes))
	}

	activeNodes := cluster.GetActiveNodes()
	if len(activeNodes) != 2 {
		t.Errorf("active nodes count = %d, want 2", len(activeNodes))
	}
}

func TestCluster_GetLeader(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// No leader initially
	if leader := cluster.GetLeader(); leader != nil {
		t.Error("expected no leader initially")
	}

	// Add a leader node
	cluster.nodes["leader-node"] = &Node{ID: "leader-node", State: StateActive, IsLeader: true}

	leader := cluster.GetLeader()
	if leader == nil {
		t.Fatal("expected leader")
	}

	if leader.ID != "leader-node" {
		t.Errorf("leader ID = %s, want leader-node", leader.ID)
	}
}

func TestCluster_handleJoin(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	newNode := &Node{ID: "new-node", Address: "10.0.0.1", Port: 7946}
	cluster.handleJoin(newNode)

	if _, exists := cluster.nodes["new-node"]; !exists {
		t.Error("new node should be added")
	}

	if cluster.nodes["new-node"].State != StateActive {
		t.Error("new node should be active")
	}
}

func TestCluster_handleLeave(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Add a node
	cluster.nodes["leaving-node"] = &Node{ID: "leaving-node", State: StateActive}

	// Leave
	cluster.handleLeave("leaving-node")

	if _, exists := cluster.nodes["leaving-node"]; exists {
		t.Error("left node should be removed")
	}
}

func TestCluster_checkFailedNodes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.HeartbeatTimeout = 100 * time.Millisecond

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Add an old node with stale heartbeat
	oldTime := time.Now().Add(-time.Hour)
	cluster.nodes["old-node"] = &Node{
		ID:            "old-node",
		State:         StateActive,
		LastHeartbeat: oldTime,
	}

	cluster.checkFailedNodes()

	if cluster.nodes["old-node"].State != StateFailed {
		t.Errorf("old node state = %s, want failed", cluster.nodes["old-node"].State)
	}
}

func TestHTTP_handleJoinHTTP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	node := &Node{ID: "http-node", Address: "10.0.0.1", Port: 7946}
	body, _ := json.Marshal(node)

	req := httptest.NewRequest(http.MethodPost, "/cluster/join", bytes.NewReader(body))
	w := httptest.NewRecorder()

	cluster.handleJoinHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	if _, exists := cluster.nodes["http-node"]; !exists {
		t.Error("node should be added via HTTP")
	}
}

func TestHTTP_handleJoinHTTP_InvalidMethod(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/cluster/join", nil)
	w := httptest.NewRecorder()

	cluster.handleJoinHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHTTP_handleJoinHTTP_InvalidBody(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/cluster/join", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()

	cluster.handleJoinHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHTTP_handleMessageHTTP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Add sender node
	cluster.nodes["sender-node"] = &Node{ID: "sender-node", State: StateActive}

	msg := &Message{
		Type:      MsgHeartbeat,
		From:      "sender-node",
		Timestamp: time.Now(),
	}
	body, _ := json.Marshal(msg)

	req := httptest.NewRequest(http.MethodPost, "/cluster/message", bytes.NewReader(body))
	w := httptest.NewRecorder()

	cluster.handleMessageHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	// Verify heartbeat was updated
	if cluster.nodes["sender-node"].LastHeartbeat.IsZero() {
		t.Error("sender heartbeat should be updated")
	}
}

func TestHTTP_handleNodesHTTP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	cluster.nodes["node-1"] = &Node{ID: "node-1", State: StateActive}
	cluster.nodes["node-2"] = &Node{ID: "node-2", State: StateActive}

	req := httptest.NewRequest(http.MethodGet, "/cluster/nodes", nil)
	w := httptest.NewRecorder()

	cluster.handleNodesHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var nodes []*Node
	if err := json.Unmarshal(w.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(nodes) != 2 {
		t.Errorf("nodes count = %d, want 2", len(nodes))
	}
}

func TestHTTP_handleHealthHTTP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.NodeID = "test-node"

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	cluster.state = StateActive
	cluster.localNode.State = StateActive

	req := httptest.NewRequest(http.MethodGet, "/cluster/health", nil)
	w := httptest.NewRecorder()

	cluster.handleHealthHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var health map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &health); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if health["node_id"] != "test-node" {
		t.Errorf("node_id = %v, want test-node", health["node_id"])
	}
}

func TestLayer_NewLayer_Disabled(t *testing.T) {
	cfg := &LayerConfig{Enabled: false}

	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	if layer.cluster != nil {
		t.Error("cluster should be nil when disabled")
	}

	if layer.Name() != "cluster" {
		t.Errorf("name = %s, want cluster", layer.Name())
	}
}

func TestLayer_Process_NotEnabled(t *testing.T) {
	cfg := &LayerConfig{Enabled: false}

	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("1.2.3.4"),
	}
	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Error("should allow when disabled")
	}
}

func TestLayer_Process_IPBanned(t *testing.T) {
	clusterCfg := DefaultConfig()
	clusterCfg.Enabled = true

	cluster, err := New(clusterCfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	cluster.BanIP("1.2.3.4", time.Hour)

	layer := &Layer{
		cluster: cluster,
		config:  &LayerConfig{Enabled: true},
	}

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("1.2.3.4"),
	}
	result := layer.Process(ctx)

	if result.Action != engine.ActionBlock {
		t.Errorf("action = %v, want block", result.Action)
	}

	if result.Score != 100 {
		t.Errorf("score = %d, want 100", result.Score)
	}
}

func TestLayer_Process_IPAllowed(t *testing.T) {
	clusterCfg := DefaultConfig()
	clusterCfg.Enabled = true

	cluster, err := New(clusterCfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	layer := &Layer{
		cluster: cluster,
		config:  &LayerConfig{Enabled: true},
	}

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("1.2.3.4"),
	}
	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("action = %v, want pass", result.Action)
	}
}

func TestLayer_IsLeader(t *testing.T) {
	clusterCfg := DefaultConfig()
	clusterCfg.Enabled = true

	cluster, err := New(clusterCfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	layer := &Layer{
		cluster: cluster,
		config:  &LayerConfig{Enabled: true},
	}

	if layer.IsLeader() {
		t.Error("should not be leader initially")
	}

	// Test disabled layer
	disabledLayer := &Layer{
		cluster: nil,
		config:  &LayerConfig{Enabled: false},
	}

	if disabledLayer.IsLeader() {
		t.Error("disabled layer should not be leader")
	}
}

func TestLayer_GetNodeCount(t *testing.T) {
	clusterCfg := DefaultConfig()
	clusterCfg.Enabled = true

	cluster, err := New(clusterCfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	cluster.nodes["node-1"] = &Node{ID: "node-1", State: StateActive}
	cluster.nodes["node-2"] = &Node{ID: "node-2", State: StateActive}

	layer := &Layer{
		cluster: cluster,
		config:  &LayerConfig{Enabled: true},
	}

	if count := layer.GetNodeCount(); count != 2 {
		t.Errorf("node count = %d, want 2", count)
	}

	// Test disabled layer
	disabledLayer := &Layer{
		cluster: nil,
		config:  &LayerConfig{Enabled: false},
	}

	if count := disabledLayer.GetNodeCount(); count != 1 {
		t.Errorf("disabled layer node count = %d, want 1", count)
	}
}

func TestMessageHandlers_IPBan(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Get the IP ban handler
	handler, exists := cluster.handlers[MsgIPBan]
	if !exists {
		t.Fatal("IP ban handler should exist")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"ip":  "5.6.7.8",
		"ttl": 3600.0,
	})

	msg := &Message{
		Type:    MsgIPBan,
		From:    "other-node",
		Payload: payload,
	}

	if err := handler(msg); err != nil {
		t.Errorf("handler failed: %v", err)
	}

	if !cluster.IsIPBanned("5.6.7.8") {
		t.Error("IP should be banned via message handler")
	}
}

func TestMessageHandlers_IPUnban(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Ban first
	cluster.BanIP("9.10.11.12", time.Hour)
	if !cluster.IsIPBanned("9.10.11.12") {
		t.Fatal("IP should be banned")
	}

	// Get the IP unban handler
	handler, exists := cluster.handlers[MsgIPUnban]
	if !exists {
		t.Fatal("IP unban handler should exist")
	}

	payload, _ := json.Marshal(map[string]string{
		"ip": "9.10.11.12",
	})

	msg := &Message{
		Type:    MsgIPUnban,
		From:    "other-node",
		Payload: payload,
	}

	if err := handler(msg); err != nil {
		t.Errorf("handler failed: %v", err)
	}

	if cluster.IsIPBanned("9.10.11.12") {
		t.Error("IP should be unbanned via message handler")
	}
}

func TestMessageHandlers_LeaderElection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.NodeID = "node-b"

	cluster, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Add nodes
	cluster.nodes["node-a"] = &Node{ID: "node-a", State: StateActive}
	cluster.nodes["node-b"] = cluster.localNode

	// Get the leader election handler
	handler, exists := cluster.handlers[MsgLeaderElection]
	if !exists {
		t.Fatal("leader election handler should exist")
	}

	// Other node becomes leader
	msg := &Message{
		Type: MsgLeaderElection,
		From: "node-a",
	}

	if err := handler(msg); err != nil {
		t.Errorf("handler failed: %v", err)
	}

	if cluster.IsLeader() {
		t.Error("should not be leader (other node is)")
	}

	if cluster.nodes["node-a"].IsLeader != true {
		t.Error("node-a should be marked as leader")
	}

	// This node becomes leader
	msg.From = "node-b"
	if err := handler(msg); err != nil {
		t.Errorf("handler failed: %v", err)
	}

	if !cluster.IsLeader() {
		t.Error("should be leader now")
	}
}

func TestStateSync_Snapshot(t *testing.T) {
	sync := &StateSync{
		IPBans:     make(map[string]time.Time),
		RateLimits: make(map[string]int64),
	}

	sync.IPBans["1.2.3.4"] = time.Now().Add(time.Hour)
	sync.RateLimits["key1"] = 100

	sync.mu.Lock()
	state := *sync
	sync.mu.Unlock()

	if len(state.IPBans) != 1 {
		t.Errorf("IP bans count = %d, want 1", len(state.IPBans))
	}

	if len(state.RateLimits) != 1 {
		t.Errorf("rate limits count = %d, want 1", len(state.RateLimits))
	}
}

func TestGenerateNodeID(t *testing.T) {
	id1 := generateNodeID()
	id2 := generateNodeID()

	if len(id1) != 16 {
		t.Errorf("ID length = %d, want 16", len(id1))
	}

	if id1 == id2 {
		t.Error("IDs should be unique")
	}
}
