// Package cluster provides distributed coordination for GuardianWAF nodes.
package cluster

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// NodeState represents the state of a cluster node.
type NodeState string

const (
	StateJoining   NodeState = "joining"
	StateActive    NodeState = "active"
	StateLeaving   NodeState = "leaving"
	StateFailed    NodeState = "failed"
	StateLeader    NodeState = "leader"
)

// MessageType represents the type of cluster message.
type MessageType string

const (
	MsgHeartbeat     MessageType = "heartbeat"
	MsgStateSync     MessageType = "state_sync"
	MsgIPBan         MessageType = "ip_ban"
	MsgIPUnban       MessageType = "ip_unban"
	MsgRateLimit     MessageType = "rate_limit"
	MsgConfigUpdate  MessageType = "config_update"
	MsgLeaderElection MessageType = "leader_election"
)

// Config for cluster coordination.
type Config struct {
	Enabled        bool          `yaml:"enabled"`
	NodeID         string        `yaml:"node_id"`
	BindAddr       string        `yaml:"bind_addr"`
	BindPort       int           `yaml:"bind_port"`
	AdvertiseAddr  string        `yaml:"advertise_addr"`
	SeedNodes      []string      `yaml:"seed_nodes"`
	SyncInterval   time.Duration `yaml:"sync_interval"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	HeartbeatTimeout  time.Duration `yaml:"heartbeat_timeout"`
	LeaderElectionTimeout time.Duration `yaml:"leader_election_timeout"`
	MaxNodes       int           `yaml:"max_nodes"`
	AuthSecret     string        `yaml:"auth_secret"` // shared secret for cluster API authentication
}

// DefaultConfig returns default cluster config.
func DefaultConfig() *Config {
	return &Config{
		Enabled:               false,
		BindAddr:              "0.0.0.0",
		BindPort:              7946,
		SyncInterval:          30 * time.Second,
		HeartbeatInterval:     5 * time.Second,
		HeartbeatTimeout:      15 * time.Second,
		LeaderElectionTimeout: 30 * time.Second,
		MaxNodes:              10,
	}
}

// Node represents a cluster member.
type Node struct {
	ID            string    `json:"id"`
	Address       string    `json:"address"`
	Port          int       `json:"port"`
	State         NodeState `json:"state"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	Metadata      map[string]string `json:"metadata"`
	IsLeader      bool      `json:"is_leader"`
	JoinedAt      time.Time `json:"joined_at"`
}

// Cluster manages the distributed cluster.
type Cluster struct {
	config    *Config
	localNode *Node
	nodes     map[string]*Node
	mu        sync.RWMutex
	state     atomic.Value // stores NodeState
	isLeader  atomic.Bool

	// Channels
	events    chan Event
	stopCh    chan struct{}

	// State sync
	stateSync *StateSync

	// Handlers
	handlers map[MessageType]MessageHandler
	handlerMu sync.RWMutex

	// HTTP client
	httpClient *http.Client

	// HTTP server for cluster API
	httpServer *http.Server
}

// Event represents a cluster event.
type Event struct {
	Type      EventType
	Node      *Node
	Timestamp time.Time
}

// EventType represents the type of cluster event.
type EventType string

const (
	EventNodeJoin  EventType = "node_join"
	EventNodeLeave EventType = "node_leave"
	EventNodeFail  EventType = "node_fail"
	EventLeaderChange EventType = "leader_change"
)

// Message represents a cluster message.
type Message struct {
	Type      MessageType       `json:"type"`
	From      string            `json:"from"`
	Timestamp time.Time         `json:"timestamp"`
	Payload   json.RawMessage   `json:"payload"`
}

// MessageHandler handles cluster messages.
type MessageHandler func(msg *Message) error

// StateSync manages distributed state synchronization.
type StateSync struct {
	IPBans     map[string]time.Time `json:"ip_bans"`
	RateLimits map[string]int64     `json:"rate_limits"`
	ConfigHash string               `json:"config_hash"`
	mu         sync.RWMutex
}

// StateSyncData holds the data from StateSync without the mutex.
// Used for safe copying and JSON serialization.
type StateSyncData struct {
	IPBans     map[string]time.Time `json:"ip_bans"`
	RateLimits map[string]int64     `json:"rate_limits"`
	ConfigHash string               `json:"config_hash"`
}

// Clone returns a copy of the state data safely (without copying the mutex).
func (s *StateSync) Clone() StateSyncData {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Deep copy the maps
	ipBansCopy := make(map[string]time.Time, len(s.IPBans))
	for k, v := range s.IPBans {
		ipBansCopy[k] = v
	}

	rateLimitsCopy := make(map[string]int64, len(s.RateLimits))
	for k, v := range s.RateLimits {
		rateLimitsCopy[k] = v
	}

	return StateSyncData{
		IPBans:     ipBansCopy,
		RateLimits: rateLimitsCopy,
		ConfigHash: s.ConfigHash,
	}
}

// New creates a new cluster.
func New(cfg *Config) (*Cluster, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Generate node ID if not provided
	if cfg.NodeID == "" {
		cfg.NodeID = generateNodeID()
	}

	if cfg.AdvertiseAddr == "" {
		cfg.AdvertiseAddr = cfg.BindAddr
	}

	c := &Cluster{
		config: cfg,
		localNode: &Node{
			ID:       cfg.NodeID,
			Address:  cfg.AdvertiseAddr,
			Port:     cfg.BindPort,
			State:    StateJoining,
			Metadata: make(map[string]string),
			JoinedAt: time.Now(),
		},
		nodes:    make(map[string]*Node),
		events:   make(chan Event, 100),
		stopCh:   make(chan struct{}),
		handlers: make(map[MessageType]MessageHandler),
		stateSync: &StateSync{
			IPBans:     make(map[string]time.Time),
			RateLimits: make(map[string]int64),
		},
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}

	// Register default handlers
	c.registerDefaultHandlers()

	c.state.Store(StateJoining)
	return c, nil
}

// Start starts the cluster.
func (c *Cluster) Start() error {
	if !c.config.Enabled {
		return nil
	}

	// Start HTTP server for cluster communication
	go c.startHTTPServer()

	// Join seed nodes
	if len(c.config.SeedNodes) > 0 {
		if err := c.joinCluster(); err != nil {
			return fmt.Errorf("failed to join cluster: %w", err)
		}
	}

	// Start background tasks
	go c.heartbeatLoop()
	// Initialize state
	c.state.Store(StateJoining)

	go c.failureDetector()
	go c.stateSyncLoop()

	// Mark as active
	c.state.Store(StateActive)
	c.localNode.State = StateActive
	c.nodes[c.localNode.ID] = c.localNode

	return nil
}

// Stop stops the cluster.
func (c *Cluster) Stop() error {
	if !c.config.Enabled {
		return nil
	}

	close(c.stopCh)

	// Notify other nodes we're leaving
	c.broadcast(&Message{
		Type:      MsgHeartbeat,
		From:      c.localNode.ID,
		Timestamp: time.Now(),
	})

	// Shutdown HTTP server gracefully
	if c.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.httpServer.Shutdown(ctx)
	}

	return nil
}

// IsLeader returns if this node is the leader.
func (c *Cluster) IsLeader() bool {
	return c.isLeader.Load()
}

// getLeaderUnlocked returns the leader node without acquiring lock.
// Caller must hold c.mu lock.
func (c *Cluster) getLeaderUnlocked() *Node {
	for _, node := range c.nodes {
		if node.IsLeader {
			return node
		}
	}
	return nil
}

// GetLeader returns the current leader node.
func (c *Cluster) GetLeader() *Node {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, node := range c.nodes {
		if node.IsLeader {
			return node
		}
	}
	return nil
}

// GetNodes returns all cluster nodes.
func (c *Cluster) GetNodes() []*Node {
	c.mu.RLock()
	defer c.mu.RUnlock()

	nodes := make([]*Node, 0, len(c.nodes))
	for _, node := range c.nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// GetActiveNodes returns active nodes.
func (c *Cluster) GetActiveNodes() []*Node {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var nodes []*Node
	for _, node := range c.nodes {
		if node.State == StateActive {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// GetNodeCount returns the number of nodes in the cluster.
func (c *Cluster) GetNodeCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.nodes)
}

// BanIP adds an IP to the cluster-wide ban list.
func (c *Cluster) BanIP(ip string, ttl time.Duration) {
	if !c.config.Enabled {
		return
	}

	c.stateSync.mu.Lock()
	c.stateSync.IPBans[ip] = time.Now().Add(ttl)
	c.stateSync.mu.Unlock()

	// Broadcast to other nodes
	payload, _ := json.Marshal(map[string]any{
		"ip":  ip,
		"ttl": ttl.Seconds(),
	})

	c.broadcast(&Message{
		Type:      MsgIPBan,
		From:      c.localNode.ID,
		Timestamp: time.Now(),
		Payload:   payload,
	})
}

// UnbanIP removes an IP from the cluster-wide ban list.
func (c *Cluster) UnbanIP(ip string) {
	if !c.config.Enabled {
		return
	}

	c.stateSync.mu.Lock()
	delete(c.stateSync.IPBans, ip)
	c.stateSync.mu.Unlock()

	// Broadcast to other nodes
	payload, _ := json.Marshal(map[string]string{"ip": ip})

	c.broadcast(&Message{
		Type:      MsgIPUnban,
		From:      c.localNode.ID,
		Timestamp: time.Now(),
		Payload:   payload,
	})
}

// IsIPBanned checks if an IP is banned cluster-wide.
func (c *Cluster) IsIPBanned(ip string) bool {
	if !c.config.Enabled {
		return false
	}

	c.stateSync.mu.RLock()
	expiry, exists := c.stateSync.IPBans[ip]
	c.stateSync.mu.RUnlock()

	if !exists {
		return false
	}

	if time.Now().After(expiry) {
		// Expired, remove it
		c.UnbanIP(ip)
		return false
	}

	return true
}

// RegisterHandler registers a message handler.
func (c *Cluster) RegisterHandler(msgType MessageType, handler MessageHandler) {
	c.handlerMu.Lock()
	c.handlers[msgType] = handler
	c.handlerMu.Unlock()
}

// broadcast sends a message to all nodes.
func (c *Cluster) broadcast(msg *Message) {
	if !c.config.Enabled {
		return
	}

	nodes := c.GetActiveNodes()
	for _, node := range nodes {
		if node.ID == c.localNode.ID {
			continue
		}
		go func(n *Node) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := c.sendMessage(ctx, n, msg); err != nil {
				log.Printf("[cluster] warning: failed to send message to node %s: %v", n.ID, err)
			}
		}(node)
	}
}

// sendMessage sends a message to a specific node.
func (c *Cluster) sendMessage(ctx context.Context, node *Node, msg *Message) error {
	url := fmt.Sprintf("http://%s:%d/cluster/message", node.Address, node.Port)

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.config.AuthSecret != "" {
		req.Header.Set("X-Cluster-Auth", c.config.AuthSecret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("node returned status %d", resp.StatusCode)
	}

	return nil
}

// joinCluster joins the cluster via seed nodes.
func (c *Cluster) joinCluster() error {
	for _, seed := range c.config.SeedNodes {
		if err := c.joinViaSeed(seed); err == nil {
			return nil
		}
	}
	return fmt.Errorf("could not join via any seed node")
}

// joinViaSeed attempts to join via a specific seed node.
func (c *Cluster) joinViaSeed(seed string) error {
	url := fmt.Sprintf("http://%s/cluster/join", seed)

	data, _ := json.Marshal(c.localNode)

	req, reqErr := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if reqErr != nil {
		return reqErr
	}
	req.Header.Set("Content-Type", "application/json")
	if c.config.AuthSecret != "" {
		req.Header.Set("X-Cluster-Auth", c.config.AuthSecret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("seed returned status %d", resp.StatusCode)
	}

	return nil
}

// handleJoin handles a node join request.
func (c *Cluster) handleJoin(node *Node) {
	c.mu.Lock()
	existing, exists := c.nodes[node.ID]
	if exists {
		existing.State = StateActive
		existing.LastHeartbeat = time.Now()
	} else {
		node.State = StateActive
		node.LastHeartbeat = time.Now()
		c.nodes[node.ID] = node

	}

	// If no leader exists, start election
	var msg *Message
	if c.getLeaderUnlocked() == nil {
		msg = c.startLeaderElection()
	}

	joinEvent := Event{
		Type:      EventNodeJoin,
		Node:      node,
		Timestamp: time.Now(),
	}
	c.mu.Unlock()

	select {
	case c.events <- joinEvent:
	default:
	}

	if msg != nil {
		c.broadcast(msg)
	}
}

// handleLeave handles a node leave.
func (c *Cluster) handleLeave(nodeID string) {
	c.mu.Lock()
	node, exists := c.nodes[nodeID]
	if !exists {
		c.mu.Unlock()
		return
	}

	node.State = StateLeaving
	leaveEvent := Event{
		Type:      EventNodeLeave,
		Node:      node,
		Timestamp: time.Now(),
	}
	delete(c.nodes, nodeID)
	c.mu.Unlock()

	select {
	case c.events <- leaveEvent:
	default:
	}
	// If leader left, start election
	if node.IsLeader {
		c.mu.Lock()
		msg := c.startLeaderElection()
		c.mu.Unlock()
		if msg != nil {
			c.broadcast(msg)
		}
	}
}

// startLeaderElection performs leader election state mutation.
// Caller must hold c.mu lock. Returns a message to broadcast if this node
// became leader, or nil. The caller should broadcast OUTSIDE the lock.
func (c *Cluster) startLeaderElection() *Message {
	// Simple leader election: lowest node ID wins
	var leader *Node
	for _, node := range c.nodes {
		if node.State == StateActive {
			if leader == nil || node.ID < leader.ID {
				leader = node
			}
		}
	}

	if leader == nil || leader.ID != c.localNode.ID {
		return nil
	}

	c.isLeader.Store(true)
	c.localNode.IsLeader = true
	c.state.Store(StateLeader)

	return &Message{
		Type:      MsgLeaderElection,
		From:      c.localNode.ID,
		Timestamp: time.Now(),
	}
}

// heartbeatLoop sends periodic heartbeats.
func (c *Cluster) heartbeatLoop() {
	ticker := time.NewTicker(c.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.broadcast(&Message{
				Type:      MsgHeartbeat,
				From:      c.localNode.ID,
				Timestamp: time.Now(),
			})
		case <-c.stopCh:
			return
		}
	}
}

// failureDetector detects failed nodes.
func (c *Cluster) failureDetector() {
	ticker := time.NewTicker(c.config.HeartbeatTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.checkFailedNodes()
		case <-c.stopCh:
			return
		}
	}
}

// checkFailedNodes checks for and marks failed nodes.
func (c *Cluster) checkFailedNodes() {
	c.mu.Lock()
	var msg *Message
	var failEvents []Event
	for _, node := range c.nodes {
		if node.ID == c.localNode.ID {
			continue
		}

		if node.State == StateActive &&
			time.Since(node.LastHeartbeat) > c.config.HeartbeatTimeout {
			node.State = StateFailed
			failEvents = append(failEvents, Event{
				Type:      EventNodeFail,
				Node:      node,
				Timestamp: time.Now(),
			})

			// If leader failed, start election
			if node.IsLeader {
				msg = c.startLeaderElection()
			}
		}
	}
	c.mu.Unlock()

	for _, evt := range failEvents {
		select {
		case c.events <- evt:
		default:
		}
	}

	if msg != nil {
		c.broadcast(msg)
	}
}

// stateSyncLoop periodically syncs state.
func (c *Cluster) stateSyncLoop() {
	if !c.IsLeader() {
		return
	}

	ticker := time.NewTicker(c.config.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.syncState()
		case <-c.stopCh:
			return
		}
	}
}

// syncState broadcasts current state to all nodes.
func (c *Cluster) syncState() {
	state := c.stateSync.Clone()

	payload, _ := json.Marshal(state)

	c.broadcast(&Message{
		Type:      MsgStateSync,
		From:      c.localNode.ID,
		Timestamp: time.Now(),
		Payload:   payload,
	})
}

// startHTTPServer starts the HTTP server for cluster communication.
func (c *Cluster) startHTTPServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/cluster/join", c.handleJoinHTTP)
	mux.HandleFunc("/cluster/message", c.handleMessageHTTP)
	mux.HandleFunc("/cluster/nodes", c.handleNodesHTTP)
	mux.HandleFunc("/cluster/health", c.handleHealthHTTP)

	addr := fmt.Sprintf("%s:%d", c.config.BindAddr, c.config.BindPort)
	c.httpServer = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		if err := c.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[cluster] warning: HTTP server failed: %v", err)
		}
	}()
}

// authenticateCluster validates the X-Cluster-Auth header using constant-time comparison.
func (c *Cluster) authenticateCluster(r *http.Request) bool {
	if c.config.AuthSecret == "" {
		return true // no secret configured, allow (backward-compatible)
	}
	auth := r.Header.Get("X-Cluster-Auth")
	return subtle.ConstantTimeCompare([]byte(auth), []byte(c.config.AuthSecret)) == 1
}

// HTTP handlers
func (c *Cluster) handleJoinHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !c.authenticateCluster(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB max
	var node Node
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Enforce max nodes
	if c.config.MaxNodes > 0 {
		c.mu.RLock()
		nodeCount := len(c.nodes)
		c.mu.RUnlock()
		if nodeCount >= c.config.MaxNodes {
			http.Error(w, "cluster full", http.StatusServiceUnavailable)
			return
		}
	}

	c.handleJoin(&node)
	w.WriteHeader(http.StatusOK)
}

func (c *Cluster) handleMessageHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !c.authenticateCluster(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB max
	var msg Message
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Update sender's heartbeat
	c.mu.Lock()
	if node, exists := c.nodes[msg.From]; exists {
		node.LastHeartbeat = time.Now()
	}
	c.mu.Unlock()

	// Handle message
	c.handlerMu.RLock()
	handler, exists := c.handlers[msg.Type]
	c.handlerMu.RUnlock()
	if exists {
		if err := handler(&msg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (c *Cluster) handleNodesHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !c.authenticateCluster(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	nodes := c.GetNodes()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(nodes); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

func (c *Cluster) handleHealthHTTP(w http.ResponseWriter, r *http.Request) {
	if !c.authenticateCluster(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"status":    c.state.Load().(NodeState),
		"node_id":   c.localNode.ID,
		"is_leader": c.IsLeader(),
		"nodes":     c.GetNodeCount(),
	}); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

// registerDefaultHandlers registers default message handlers.
func (c *Cluster) registerDefaultHandlers() {
	c.handlers[MsgHeartbeat] = func(msg *Message) error {
		// Heartbeat updates are handled in handleMessageHTTP
		return nil
	}

	c.handlers[MsgIPBan] = func(msg *Message) error {
		var payload struct {
			IP  string  `json:"ip"`
			TTL float64 `json:"ttl"`
		}
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			return err
		}
		c.stateSync.mu.Lock()
		c.stateSync.IPBans[payload.IP] = time.Now().Add(time.Duration(payload.TTL) * time.Second)
		c.stateSync.mu.Unlock()
		return nil
	}

	c.handlers[MsgIPUnban] = func(msg *Message) error {
		var payload struct {
			IP string `json:"ip"`
		}
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			return err
		}
		c.stateSync.mu.Lock()
		delete(c.stateSync.IPBans, payload.IP)
		c.stateSync.mu.Unlock()
		return nil
	}

	c.handlers[MsgStateSync] = func(msg *Message) error {
		if c.IsLeader() {
			return nil // Leaders don't accept state sync
		}
		var state StateSync
		if err := json.Unmarshal(msg.Payload, &state); err != nil {
			return err
		}
		// Copy fields into existing object rather than replacing pointer,
		// to avoid unlocking a mutex that was never locked.
		c.stateSync.mu.Lock()
		c.stateSync.IPBans = state.IPBans
		c.stateSync.RateLimits = state.RateLimits
		c.stateSync.ConfigHash = state.ConfigHash
		c.stateSync.mu.Unlock()
		return nil
	}

	c.handlers[MsgLeaderElection] = func(msg *Message) error {
		c.mu.Lock()
		defer c.mu.Unlock()

		// Update leader status
		for _, node := range c.nodes {
			node.IsLeader = (node.ID == msg.From)
		}

		if msg.From == c.localNode.ID {
			c.isLeader.Store(true)
			c.state.Store(StateLeader)
		} else {
			c.isLeader.Store(false)
			c.state.Store(StateActive)
		}

		return nil
	}
}

// generateNodeID generates a random node ID.
func generateNodeID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to time-based ID if CSPRNG fails
		return fmt.Sprintf("node-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
