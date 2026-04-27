package cluster

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- Layer coverage tests ---

func TestLayer_NewLayer_NilConfig(t *testing.T) {
	layer, err := NewLayer(nil)
	if err != nil {
		t.Fatalf("NewLayer(nil) failed: %v", err)
	}
	if layer == nil {
		t.Fatal("expected layer, got nil")
	}
	if layer.cluster != nil {
		t.Error("cluster should be nil with nil config")
	}
}

func TestLayer_NewLayer_Enabled(t *testing.T) {
	cfg := &LayerConfig{
		Enabled: true,
		Config:  DefaultConfig(),
	}
	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer(enabled) failed: %v", err)
	}
	if layer.cluster == nil {
		t.Error("cluster should not be nil when enabled")
	}
}

func TestLayer_Order(t *testing.T) {
	layer := &Layer{}
	if layer.Order() != 75 {
		t.Errorf("Order() = %d, want 75", layer.Order())
	}
}

func TestLayer_StartStop_NilCluster(t *testing.T) {
	layer := &Layer{cluster: nil, config: &LayerConfig{Enabled: false}}
	if err := layer.Start(); err != nil {
		t.Errorf("Start with nil cluster: %v", err)
	}
	if err := layer.Stop(); err != nil {
		t.Errorf("Stop with nil cluster: %v", err)
	}
}

func TestLayer_StartStop_DisabledCluster(t *testing.T) {
	clusterCfg := DefaultConfig()
	clusterCfg.Enabled = false
	cluster, _ := New(clusterCfg)
	layer := &Layer{cluster: cluster, config: &LayerConfig{Enabled: false}}

	if err := layer.Start(); err != nil {
		t.Errorf("Start failed: %v", err)
	}
	if err := layer.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}

func TestLayer_GetCluster(t *testing.T) {
	clusterCfg := DefaultConfig()
	clusterCfg.Enabled = true
	c, _ := New(clusterCfg)
	layer := &Layer{cluster: c}

	if layer.GetCluster() != c {
		t.Error("GetCluster should return the underlying cluster")
	}

	nilLayer := &Layer{cluster: nil}
	if nilLayer.GetCluster() != nil {
		t.Error("GetCluster should return nil when cluster is nil")
	}
}

func TestLayer_BanIP(t *testing.T) {
	clusterCfg := DefaultConfig()
	clusterCfg.Enabled = true
	c, _ := New(clusterCfg)
	layer := &Layer{cluster: c, config: &LayerConfig{Enabled: true}}

	layer.BanIP(net.ParseIP("10.0.0.1"), time.Hour)
	if !c.IsIPBanned("10.0.0.1") {
		t.Error("IP should be banned via layer")
	}

	// Nil cluster should not panic
	nilLayer := &Layer{cluster: nil}
	nilLayer.BanIP(net.ParseIP("10.0.0.1"), time.Hour)
}

// --- Cluster Start/Stop disabled ---

func TestCoverage_StartStop_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	c, _ := New(cfg)

	if err := c.Start(); err != nil {
		t.Fatalf("Start disabled: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop disabled: %v", err)
	}
}

func TestCoverage_Stop_DoubleStop_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	c, _ := New(cfg)

	c.Start()
	// Double stop on disabled cluster should be fine
	c.Stop()
	c.Stop()
}

func TestCluster_Events(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	c, _ := New(cfg)

	ch := c.Events()
	if ch == nil {
		t.Error("Events() should return a non-nil channel")
	}
}

// --- handleJoin edge cases ---

func TestCluster_handleJoin_MaxNodesReached(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MaxNodes = 1
	c, _ := New(cfg)

	// Add the local node first
	c.nodes[c.localNode.ID] = c.localNode

	// Try to add another node - should fail
	newNode := &Node{ID: "extra-node", Address: "10.0.0.1", Port: 7946}
	result := c.handleJoin(newNode)
	if result {
		t.Error("handleJoin should return false when cluster is full")
	}
}

func TestCluster_handleJoin_ExistingNode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	c, _ := New(cfg)

	node := &Node{ID: "existing-node", Address: "10.0.0.1", Port: 7946}
	c.handleJoin(node)

	// Join again (rejoin) - should update, not duplicate
	node2 := &Node{ID: "existing-node", Address: "10.0.0.2", Port: 7947}
	c.handleJoin(node2)

	if len(c.nodes) != 1 {
		t.Errorf("expected 1 node after rejoin, got %d", len(c.nodes))
	}
}

func TestCluster_handleJoin_TriggersLeaderElection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.NodeID = "node-a"
	c, _ := New(cfg)

	// Add local node first so it's part of the member list for election
	c.localNode.State = StateActive
	c.nodes["node-a"] = c.localNode

	// handleJoin when no leader exists should trigger election
	newNode := &Node{ID: "node-b", Address: "10.0.0.1", Port: 7946}
	c.handleJoin(newNode)

	// node-a should become leader (lower ID)
	if !c.IsLeader() {
		t.Error("node-a should become leader when first node joins")
	}
}

// --- handleLeave edge cases ---

func TestCluster_handleLeave_LeaderNode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.NodeID = "node-b"
	c, _ := New(cfg)

	// Setup: node-a is leader, node-b is us
	c.nodes["node-a"] = &Node{ID: "node-a", State: StateActive, IsLeader: true}
	c.nodes["node-b"] = c.localNode
	c.localNode.State = StateActive

	// Leader leaves
	c.handleLeave("node-a")

	if _, exists := c.nodes["node-a"]; exists {
		t.Error("node-a should be removed")
	}

	// node-b should become leader
	if !c.IsLeader() {
		t.Error("node-b should become leader after node-a leaves")
	}
}

func TestCluster_handleLeave_NonExistentNode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	c, _ := New(cfg)

	// Should not panic
	c.handleLeave("non-existent")
}

// --- HTTP handler coverage ---

func TestHTTP_handleJoinHTTP_ClusterFull(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "test-secret"
	cfg.MaxNodes = 1
	c, _ := New(cfg)
	c.nodes[c.localNode.ID] = c.localNode

	node := &Node{ID: "extra-node", Address: "10.0.0.1", Port: 7946}
	body, _ := json.Marshal(node)

	req := httptest.NewRequest(http.MethodPost, "/cluster/join", bytes.NewReader(body))
	req.Header.Set("X-Cluster-Auth", "test-secret")
	w := httptest.NewRecorder()

	c.handleJoinHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (cluster full)", w.Code)
	}
}

func TestHTTP_handleJoinHTTP_Unauthorized(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "test-secret"
	c, _ := New(cfg)

	req := httptest.NewRequest(http.MethodPost, "/cluster/join", nil)
	req.Header.Set("X-Cluster-Auth", "wrong-secret")
	w := httptest.NewRecorder()

	c.handleJoinHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestHTTP_handleJoinHTTP_NoAuthConfigured(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = ""
	c, _ := New(cfg)

	req := httptest.NewRequest(http.MethodPost, "/cluster/join", nil)
	w := httptest.NewRecorder()

	c.handleJoinHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when no auth configured", w.Code)
	}
}

func TestHTTP_handleMessageHTTP_InvalidMethod(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "test-secret"
	c, _ := New(cfg)

	req := httptest.NewRequest(http.MethodGet, "/cluster/message", nil)
	req.Header.Set("X-Cluster-Auth", "test-secret")
	w := httptest.NewRecorder()

	c.handleMessageHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHTTP_handleMessageHTTP_Unauthorized(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "test-secret"
	c, _ := New(cfg)

	req := httptest.NewRequest(http.MethodPost, "/cluster/message", nil)
	req.Header.Set("X-Cluster-Auth", "bad")
	w := httptest.NewRecorder()

	c.handleMessageHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestHTTP_handleMessageHTTP_InvalidBody(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "test-secret"
	c, _ := New(cfg)

	req := httptest.NewRequest(http.MethodPost, "/cluster/message", bytes.NewReader([]byte("bad")))
	req.Header.Set("X-Cluster-Auth", "test-secret")
	w := httptest.NewRecorder()

	c.handleMessageHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHTTP_handleMessageHTTP_UnknownSender(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "test-secret"
	c, _ := New(cfg)

	msg := &Message{
		Type:      MsgHeartbeat,
		From:      "unknown-node",
		Timestamp: time.Now(),
	}
	body, _ := json.Marshal(msg)

	req := httptest.NewRequest(http.MethodPost, "/cluster/message", bytes.NewReader(body))
	req.Header.Set("X-Cluster-Auth", "test-secret")
	w := httptest.NewRecorder()

	c.handleMessageHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHTTP_handleMessageHTTP_HandlerError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "test-secret"
	c, _ := New(cfg)
	c.nodes["sender"] = &Node{ID: "sender", State: StateActive}

	// Register a handler that returns an error
	c.handlers[MsgIPBan] = func(msg *Message) error {
		return fmt.Errorf("internal handler error")
	}

	payload, _ := json.Marshal(map[string]any{
		"ip": "1.2.3.4",
	})
	msg := &Message{
		Type:    MsgIPBan,
		From:    "sender",
		Payload: payload,
	}
	body, _ := json.Marshal(msg)

	req := httptest.NewRequest(http.MethodPost, "/cluster/message", bytes.NewReader(body))
	req.Header.Set("X-Cluster-Auth", "test-secret")
	w := httptest.NewRecorder()

	c.handleMessageHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHTTP_handleNodesHTTP_InvalidMethod(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "test-secret"
	c, _ := New(cfg)

	req := httptest.NewRequest(http.MethodPost, "/cluster/nodes", nil)
	req.Header.Set("X-Cluster-Auth", "test-secret")
	w := httptest.NewRecorder()

	c.handleNodesHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHTTP_handleNodesHTTP_Unauthorized(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "test-secret"
	c, _ := New(cfg)

	req := httptest.NewRequest(http.MethodGet, "/cluster/nodes", nil)
	req.Header.Set("X-Cluster-Auth", "wrong")
	w := httptest.NewRecorder()

	c.handleNodesHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestHTTP_handleHealthHTTP_Unauthorized(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "test-secret"
	c, _ := New(cfg)

	req := httptest.NewRequest(http.MethodGet, "/cluster/health", nil)
	req.Header.Set("X-Cluster-Auth", "wrong")
	w := httptest.NewRecorder()

	c.handleHealthHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// --- RegisterHandler ---

func TestCluster_RegisterHandler(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	c, _ := New(cfg)

	called := false
	c.RegisterHandler("custom_type", func(msg *Message) error {
		called = true
		return nil
	})

	if _, exists := c.handlers["custom_type"]; !exists {
		t.Error("custom handler should be registered")
	}

	// Call the handler to verify
	c.handlers["custom_type"](&Message{})
	if !called {
		t.Error("handler should have been called")
	}
}

// --- BanIP/UnbanIP disabled ---

func TestCluster_BanIP_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	c, _ := New(cfg)

	c.BanIP("1.2.3.4", time.Hour)
	if c.IsIPBanned("1.2.3.4") {
		t.Error("should not be banned when disabled")
	}
}

func TestCluster_UnbanIP_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	c, _ := New(cfg)

	c.UnbanIP("1.2.3.4") // should not panic
}

// --- StateSync handler coverage ---

func TestMessageHandlers_StateSync(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	c, _ := New(cfg)

	handler, exists := c.handlers[MsgStateSync]
	if !exists {
		t.Fatal("state sync handler should exist")
	}

	stateData := StateSyncData{
		IPBans:     map[string]time.Time{"1.2.3.4": time.Now().Add(time.Hour)},
		RateLimits: map[string]int64{"key1": 100},
	}
	payload, _ := json.Marshal(stateData)

	msg := &Message{
		Type:    MsgStateSync,
		From:    "other-node",
		Payload: payload,
	}

	// Leader should ignore state sync
	c.isLeader.Store(true)
	if err := handler(msg); err != nil {
		t.Errorf("handler failed: %v", err)
	}

	// Non-leader should accept state sync
	c.isLeader.Store(false)
	if err := handler(msg); err != nil {
		t.Errorf("handler failed for non-leader: %v", err)
	}

	if !c.IsIPBanned("1.2.3.4") {
		t.Error("IP should be banned after state sync")
	}
}

func TestMessageHandlers_StateSync_InvalidPayload(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	c, _ := New(cfg)
	c.isLeader.Store(false)

	handler := c.handlers[MsgStateSync]
	msg := &Message{
		Type:    MsgStateSync,
		From:    "other-node",
		Payload: json.RawMessage(`invalid json`),
	}

	if err := handler(msg); err == nil {
		t.Error("expected error for invalid JSON payload")
	}
}

func TestMessageHandlers_IPBan_InvalidPayload(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	c, _ := New(cfg)

	handler := c.handlers[MsgIPBan]
	msg := &Message{
		Type:    MsgIPBan,
		From:    "other-node",
		Payload: json.RawMessage(`not valid json`),
	}

	if err := handler(msg); err == nil {
		t.Error("expected error for invalid JSON payload")
	}
}

func TestMessageHandlers_IPUnban_InvalidPayload(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	c, _ := New(cfg)

	handler := c.handlers[MsgIPUnban]
	msg := &Message{
		Type:    MsgIPUnban,
		From:    "other-node",
		Payload: json.RawMessage(`not valid json`),
	}

	if err := handler(msg); err == nil {
		t.Error("expected error for invalid JSON payload")
	}
}

// --- authenticateCluster coverage ---

func TestCluster_authenticateCluster_NoAuthConfigured(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = ""
	c, _ := New(cfg)

	req := httptest.NewRequest(http.MethodPost, "/cluster/join", nil)
	if c.authenticateCluster(req) {
		t.Error("should reject when no auth secret is configured")
	}
}

func TestCluster_authenticateCluster_ValidSecret(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "my-secret"
	c, _ := New(cfg)

	req := httptest.NewRequest(http.MethodPost, "/cluster/join", nil)
	req.Header.Set("X-Cluster-Auth", "my-secret")
	if !c.authenticateCluster(req) {
		t.Error("should accept valid auth secret")
	}
}

func TestCluster_authenticateCluster_InvalidSecret(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "my-secret"
	c, _ := New(cfg)

	req := httptest.NewRequest(http.MethodPost, "/cluster/join", nil)
	req.Header.Set("X-Cluster-Auth", "wrong-secret")
	if c.authenticateCluster(req) {
		t.Error("should reject invalid auth secret")
	}
}

// --- clusterSanitizeErr ---

func TestClusterSanitizeErr(t *testing.T) {
	// Test nil
	if result := clusterSanitizeErr(nil); result != "" {
		t.Errorf("nil: got %q, want empty", result)
	}

	// Test simple error (no path)
	if result := clusterSanitizeErr(fmt.Errorf("simple error")); result == "internal error" {
		t.Error("simple error should not be sanitized to 'internal error'")
	}

	// Test error with forward slash (path)
	if result := clusterSanitizeErr(fmt.Errorf("failed at /some/path")); result != "internal error" {
		t.Errorf("path error: got %q, want internal error", result)
	}

	// Test error with goroutine
	if result := clusterSanitizeErr(fmt.Errorf("goroutine panic")); result != "internal error" {
		t.Errorf("goroutine error: got %q, want internal error", result)
	}

	// Test error with runtime/
	if result := clusterSanitizeErr(fmt.Errorf("runtime/ error")); result != "internal error" {
		t.Errorf("runtime error: got %q, want internal error", result)
	}

	// Test long error message
	if result := clusterSanitizeErr(fmt.Errorf("%s", strings.Repeat("x", 300))); len(result) > 200 {
		t.Errorf("long error should be truncated, got %d chars", len(result))
	}

	// Test error with backslash
	if result := clusterSanitizeErr(fmt.Errorf("failed at \\some\\path")); result != "internal error" {
		t.Errorf("backslash error: got %q, want internal error", result)
	}
}

// --- joinCluster / joinViaSeed ---

func TestCluster_joinCluster_AllSeedsFail(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.SeedNodes = []string{"127.0.0.1:19999", "127.0.0.1:19998"}
	c, _ := New(cfg)

	err := c.joinCluster()
	if err == nil {
		t.Error("expected error when all seeds fail")
	}
}

func TestCluster_joinCluster_NoSeeds(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.SeedNodes = nil
	c, _ := New(cfg)

	// No seeds means the loop doesn't execute, returns error
	err := c.joinCluster()
	if err == nil {
		t.Error("expected error when no seeds configured")
	}
}

func TestCluster_joinViaSeed_Success(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "test-secret"
	c, _ := New(cfg)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cluster/join" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	err := c.joinViaSeed(server.URL)
	if err != nil {
		t.Errorf("joinViaSeed failed: %v", err)
	}
}

func TestCluster_joinViaSeed_NonResponsive(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	c, _ := New(cfg)

	err := c.joinViaSeed("http://127.0.0.1:19999")
	if err == nil {
		t.Error("expected error for non-responsive seed")
	}
}

func TestCluster_joinViaSeed_ServerError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	c, _ := New(cfg)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	err := c.joinViaSeed(server.URL)
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

// --- sendMessage ---

func TestCluster_sendMessage_HTTPS(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.TLSCertFile = "cert.pem"
	cfg.TLSKeyFile = "key.pem"
	c, _ := New(cfg)

	// Should attempt HTTPS connection and fail
	node := &Node{ID: "test", Address: "127.0.0.1", Port: 19999}
	msg := &Message{Type: MsgHeartbeat, From: c.localNode.ID, Timestamp: time.Now()}

	err := c.sendMessage(t.Context(), node, msg)
	if err == nil {
		t.Error("expected error for unreachable HTTPS node")
	}
}

// --- broadcast coverage ---

func TestCluster_broadcast_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	c, _ := New(cfg)

	c.broadcast(&Message{Type: MsgHeartbeat, From: "test", Timestamp: time.Now()})
}

func TestCluster_broadcast_WithNodes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	c, _ := New(cfg)

	c.nodes["node-1"] = &Node{ID: "node-1", Address: "127.0.0.1", Port: 19999, State: StateActive, LastHeartbeat: time.Now()}
	c.nodes["node-2"] = &Node{ID: "node-2", Address: "127.0.0.1", Port: 19998, State: StateActive, LastHeartbeat: time.Now()}

	c.broadcast(&Message{Type: MsgHeartbeat, From: c.localNode.ID, Timestamp: time.Now()})
	// Give goroutines time to attempt (and fail) sends
	time.Sleep(200 * time.Millisecond)
}

// --- StateSync Clone and data coverage ---

func TestStateSync_Clone_Empty(t *testing.T) {
	sync := &StateSync{
		IPBans:     make(map[string]time.Time),
		RateLimits: make(map[string]int64),
	}

	data := sync.Clone()
	if len(data.IPBans) != 0 {
		t.Error("expected empty IP bans")
	}
	if len(data.RateLimits) != 0 {
		t.Error("expected empty rate limits")
	}
}

func TestStateSync_Clone_WithData(t *testing.T) {
	now := time.Now()
	sync := &StateSync{
		IPBans:     map[string]time.Time{"1.2.3.4": now.Add(time.Hour), "5.6.7.8": now.Add(2 * time.Hour)},
		RateLimits: map[string]int64{"key1": 100, "key2": 200},
		ConfigHash: "abc123",
	}

	data := sync.Clone()
	if len(data.IPBans) != 2 {
		t.Errorf("IP bans = %d, want 2", len(data.IPBans))
	}
	if len(data.RateLimits) != 2 {
		t.Errorf("rate limits = %d, want 2", len(data.RateLimits))
	}
	if data.ConfigHash != "abc123" {
		t.Errorf("config hash = %s, want abc123", data.ConfigHash)
	}

	// Verify it's a copy
	data.IPBans["9.9.9.9"] = now
	if _, exists := sync.IPBans["9.9.9.9"]; exists {
		t.Error("Clone should return a copy, not shared reference")
	}
}

// --- getLeaderUnlocked ---

func TestCluster_getLeaderUnlocked_MultipleNodes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	c, _ := New(cfg)

	c.nodes["node-1"] = &Node{ID: "node-1", State: StateActive, IsLeader: false}
	c.nodes["node-2"] = &Node{ID: "node-2", State: StateActive, IsLeader: true}
	c.nodes["node-3"] = &Node{ID: "node-3", State: StateActive, IsLeader: false}

	leader := c.getLeaderUnlocked()
	if leader == nil || leader.ID != "node-2" {
		t.Error("should return node-2 as leader")
	}
}

// --- checkFailedNodes with leader failure ---

func TestCluster_checkFailedNodes_LeaderFailure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.HeartbeatTimeout = 100 * time.Millisecond
	cfg.NodeID = "node-b"
	c, _ := New(cfg)

	c.localNode.State = StateActive

	// Setup: node-a is leader and stale
	c.nodes["node-a"] = &Node{
		ID: "node-a", State: StateActive, IsLeader: true,
		LastHeartbeat: time.Now().Add(-time.Hour),
	}
	c.nodes["node-b"] = c.localNode

	c.checkFailedNodes()

	// node-a should be failed
	if c.nodes["node-a"].State != StateFailed {
		t.Error("node-a should be marked as failed")
	}

	// node-b should become leader
	if !c.IsLeader() {
		t.Error("node-b should become leader after node-a fails")
	}
}

// --- Concurrent access tests ---

func TestCluster_ConcurrentAccess(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	c, _ := New(cfg)

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
			c.BanIP(ip, time.Hour)
			c.IsIPBanned(ip)
			c.GetNodes()
			c.GetActiveNodes()
			c.GetNodeCount()
			c.GetLeader()
		}(i)
	}
	wg.Wait()
}

// --- New with nil config ---

func TestCluster_New_NilConfig(t *testing.T) {
	c, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil) failed: %v", err)
	}
	if c == nil {
		t.Fatal("expected cluster, got nil")
	}
}

// --- Layer Process with nil config ---

func TestLayer_Process_NilConfig(t *testing.T) {
	// config.Enabled=false with nil cluster should pass
	layer := &Layer{
		cluster: nil,
		config:  &LayerConfig{Enabled: false},
	}

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("1.2.3.4"),
	}
	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Error("should pass with disabled config")
	}
}

// --- Event channel test ---

func TestCluster_Events_Drain(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	c, _ := New(cfg)

	// Fill the events channel
	for i := range 100 {
		select {
		case c.events <- Event{Type: EventNodeJoin, Node: &Node{ID: fmt.Sprintf("node-%d", i)}, Timestamp: time.Now()}:
		default:
		}
	}

	// Events() should still return the channel
	ch := c.Events()
	if ch == nil {
		t.Error("Events should return non-nil channel")
	}
}

// --- Start with seed nodes using test server (tests joinCluster path) ---

func TestCluster_joinViaSeed_SchemeHandling(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "test-secret"
	c, _ := New(cfg)

	// Test with scheme already in URL
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// The URL already contains "http://"
	err := c.joinViaSeed(server.URL)
	if err != nil {
		t.Errorf("joinViaSeed with existing scheme failed: %v", err)
	}

	// Test without scheme (should default to https://)
	err = c.joinViaSeed("127.0.0.1:19999")
	if err == nil {
		t.Error("expected error for unreachable https seed")
	}
}

// --- sendMessage successful path via test server ---

func TestCluster_sendMessage_Success(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "test-secret"
	c, _ := New(cfg)

	// Create a test server that handles cluster messages
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Cluster-Auth") != "test-secret" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Parse host:port from test server URL
	addr := server.URL[len("http://"):]
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	node := &Node{ID: "test-node", Address: host, Port: port}
	msg := &Message{Type: MsgHeartbeat, From: c.localNode.ID, Timestamp: time.Now()}

	err := c.sendMessage(t.Context(), node, msg)
	if err != nil {
		t.Errorf("sendMessage to test server failed: %v", err)
	}
}

// --- sendMessage with non-200 response ---

func TestCluster_sendMessage_Non200Response(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "test-secret"
	c, _ := New(cfg)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer server.Close()

	addr := server.URL[len("http://"):]
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	node := &Node{ID: "test-node", Address: host, Port: port}
	msg := &Message{Type: MsgHeartbeat, From: c.localNode.ID, Timestamp: time.Now()}

	err := c.sendMessage(t.Context(), node, msg)
	if err == nil {
		t.Error("expected error for non-200 response")
	}
}

// --- sendMessage without auth secret ---

func TestCluster_sendMessage_NoAuth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = ""
	c, _ := New(cfg)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	addr := server.URL[len("http://"):]
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	node := &Node{ID: "test-node", Address: host, Port: port}
	msg := &Message{Type: MsgHeartbeat, From: c.localNode.ID, Timestamp: time.Now()}

	err := c.sendMessage(t.Context(), node, msg)
	if err != nil {
		t.Errorf("sendMessage without auth should work: %v", err)
	}
}

// --- syncState unit test ---

func TestCluster_syncState_Unit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	c, _ := New(cfg)

	// Add some state
	c.stateSync.mu.Lock()
	c.stateSync.IPBans["1.2.3.4"] = time.Now().Add(time.Hour)
	c.stateSync.RateLimits["key1"] = 100
	c.stateSync.mu.Unlock()

	// Call syncState directly (normally called by stateSyncLoop)
	c.syncState()
	// syncState calls broadcast which will try to send to active nodes
	// With no nodes it should just return
}

// --- handleNodesHTTP with nodes ---

func TestHTTP_handleNodesHTTP_WithNodes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuthSecret = "test-secret"
	c, _ := New(cfg)

	c.nodes["node-1"] = &Node{ID: "node-1", State: StateActive}
	c.nodes["node-2"] = &Node{ID: "node-2", State: StateActive}

	req := httptest.NewRequest(http.MethodGet, "/cluster/nodes", nil)
	req.Header.Set("X-Cluster-Auth", "test-secret")
	w := httptest.NewRecorder()

	c.handleNodesHTTP(w, req)

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

// --- MaxNodes = 0 (unlimited) ---

func TestCluster_handleJoin_UnlimitedNodes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MaxNodes = 0 // unlimited
	c, _ := New(cfg)

	for i := range 20 {
		node := &Node{ID: fmt.Sprintf("node-%d", i), Address: "10.0.0.1", Port: 7946}
		if !c.handleJoin(node) {
			t.Errorf("handleJoin should succeed with unlimited nodes (iteration %d)", i)
		}
	}
}
