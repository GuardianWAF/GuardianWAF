// Package clustersync provides active-active replication between GuardianWAF nodes.
package clustersync

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Manager handles cluster synchronization.
//
// Lock ordering: Manager.mu must be acquired before Cluster.mu.
// Never hold Cluster.mu while acquiring Manager.mu, or deadlock may occur.
type Manager struct {
	config *Config

	mu        sync.RWMutex
	nodes     map[string]*Node       // All known nodes
	clusters  map[string]*Cluster    // All clusters
	health    map[string]bool        // Node health status
	localNode *Node

	// Event handling
	eventQueue chan *SyncEvent
	eventLog   []*SyncEvent           // Recent events for replay

	// Sync tracking
	lastSync map[string]time.Time     // nodeID -> last successful sync

	// Handlers for different entity types
	handlers map[string]SyncHandler

	// Shared HTTP client for node communication
	httpClient *http.Client

	// Background tasks
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Vector clock for conflict detection
	vectorClock map[string]int64

	// Stats
	stats SyncStats
	statsMu sync.RWMutex
}

// SyncHandler processes incoming sync events.
type SyncHandler interface {
	Apply(event *SyncEvent) error
	Get(entityID string) (map[string]any, error)
	List(since time.Time) ([]*SyncEvent, error)
}

// NewManager creates a new cluster sync manager.
func NewManager(config *Config) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		config:      config,
		nodes:       make(map[string]*Node),
		clusters:    make(map[string]*Cluster),
		health:      make(map[string]bool),
		eventQueue:  make(chan *SyncEvent, 1000),
		eventLog:    make([]*SyncEvent, 0, 1000),
		lastSync:    make(map[string]time.Time),
		handlers:    make(map[string]SyncHandler),
		vectorClock: make(map[string]int64),
		ctx:         ctx,
		cancel:      cancel,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}

	// Create local node
	m.localNode = &Node{
		ID:       config.NodeID,
		Name:     config.NodeName,
		Address:  fmt.Sprintf("http://%s:%d", config.BindAddress, config.APIPort),
		APIKey:   config.SharedSecret,
		Healthy:  true,
		IsLocal:  true,
		LastSeen: time.Now(),
	}
	m.nodes[config.NodeID] = m.localNode

	return m
}

// Start initializes the manager and starts background tasks.
func (m *Manager) Start() error {
	if !m.config.Enabled {
		return nil
	}

	// Initialize clusters from config
	for _, cc := range m.config.Clusters {
		cluster := &Cluster{
			ID:          cc.ID,
			Name:        cc.Name,
			Description: "",
			Nodes:       make([]string, 0),
			SyncScope:   ParseSyncScope(cc.SyncScope),
			CreatedAt:   time.Now(),
		}

		for _, node := range cc.Nodes {
			if node.ID == "" {
				node.ID = generateNodeIDFromAddress(node.Address)
			}
			if node.ID == m.config.NodeID {
				continue // Skip local node
			}
			// Validate peer URL for SSRF protection
			if err := validatePeerURL(node.Address); err != nil {
				log.Printf("[clustersync] WARNING: peer node address rejected: %s: %v", node.Address, err)
				continue
			}
			m.mu.Lock()
			m.nodes[node.ID] = &node
			m.health[node.ID] = false
			cluster.Nodes = append(cluster.Nodes, node.ID)
			m.mu.Unlock()
		}

		m.mu.Lock()
		m.clusters[cc.ID] = cluster
		m.mu.Unlock()
	}

	// Start background workers
	m.wg.Add(3)
	go m.eventProcessor()
	go m.healthChecker()
	go m.replicationWorker()

	return nil
}

// Stop shuts down the manager.
func (m *Manager) Stop() error {
	if !m.config.Enabled {
		return nil
	}

	m.cancel()
	m.wg.Wait()
	return nil
}

// RegisterHandler registers a handler for an entity type.
func (m *Manager) RegisterHandler(entityType string, handler SyncHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[entityType] = handler
}

// BroadcastEvent sends an event to all cluster members.
func (m *Manager) BroadcastEvent(entityType, entityID, action string, data map[string]any) error {
	if !m.config.Enabled {
		return nil
	}

	event := &SyncEvent{
		ID:          generateEventID(),
		Timestamp:   time.Now().UnixNano(),
		SourceNode:  m.config.NodeID,
		EntityType:  entityType,
		EntityID:    entityID,
		Action:      action,
		Data:        data,
		Checksum:    calculateChecksum(data),
		VectorClock: m.getVectorClock(),
	}

	// Add to local queue
	select {
	case m.eventQueue <- event:
	default:
		return fmt.Errorf("event queue full")
	}

	// Also replicate to peers immediately
	go m.replicateEvent(event)

	m.statsMu.Lock()
	m.stats.TotalEventsSent++
	m.statsMu.Unlock()

	return nil
}

// ReceiveEvent processes an incoming sync event.
func (m *Manager) ReceiveEvent(event *SyncEvent) error {
	if event.SourceNode == m.config.NodeID {
		return nil // Ignore own events
	}

	// Check for conflicts
	conflict, existing := m.checkConflict(event)
	if conflict {
		m.statsMu.Lock()
		m.stats.TotalConflicts++
		m.stats.LastConflictAt = time.Now()
		m.statsMu.Unlock()

		// Resolve conflict
		if !m.resolveConflict(event, existing) {
			return fmt.Errorf("conflict resolution rejected update")
		}
		m.statsMu.Lock()
		m.stats.TotalResolved++
		m.statsMu.Unlock()
	}

	// Apply the event
	handler, ok := m.handlers[event.EntityType]
	if !ok {
		return fmt.Errorf("no handler for entity type: %s", event.EntityType)
	}

	if err := handler.Apply(event); err != nil {
		return fmt.Errorf("applying event: %w", err)
	}

	// Update vector clock
	m.updateVectorClock(event.VectorClock)

	m.statsMu.Lock()
	m.stats.TotalEventsReceived++
	m.statsMu.Unlock()

	return nil
}

// AddCluster adds a new cluster.
func (m *Manager) AddCluster(cluster *Cluster) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.clusters[cluster.ID] = cluster
	return nil
}

// RemoveCluster removes a cluster.
func (m *Manager) RemoveCluster(clusterID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.clusters, clusterID)
	return nil
}

// AddNodeToCluster adds a node to a cluster.
func (m *Manager) AddNodeToCluster(clusterID string, node *Node) error {
	// Validate peer URL for SSRF protection
	if err := validatePeerURL(node.Address); err != nil {
		return fmt.Errorf("peer address rejected: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	cluster, ok := m.clusters[clusterID]
	if !ok {
		return fmt.Errorf("cluster not found: %s", clusterID)
	}

	cluster.mu.Lock()
	defer cluster.mu.Unlock()

	// Check if node already exists
	if slices.Contains(cluster.Nodes, node.ID) {
		return nil // Already in cluster
	}

	cluster.Nodes = append(cluster.Nodes, node.ID)
	m.nodes[node.ID] = node
	m.health[node.ID] = false

	return nil
}

// RemoveNodeFromCluster removes a node from a cluster.
func (m *Manager) RemoveNodeFromCluster(clusterID, nodeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cluster, ok := m.clusters[clusterID]
	if !ok {
		return fmt.Errorf("cluster not found: %s", clusterID)
	}

	cluster.mu.Lock()
	defer cluster.mu.Unlock()

	// Remove from cluster nodes
	newNodes := make([]string, 0, len(cluster.Nodes))
	for _, id := range cluster.Nodes {
		if id != nodeID {
			newNodes = append(newNodes, id)
		}
	}
	cluster.Nodes = newNodes

	return nil
}

// GetClusters returns all clusters.
func (m *Manager) GetClusters() []*Cluster {
	m.mu.RLock()
	defer m.mu.RUnlock()

	clusters := make([]*Cluster, 0, len(m.clusters))
	for _, c := range m.clusters {
		clusters = append(clusters, c)
	}
	return clusters
}

// GetCluster returns a specific cluster.
func (m *Manager) GetCluster(clusterID string) *Cluster {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.clusters[clusterID]
}

// GetNodes returns all nodes.
func (m *Manager) GetNodes() []*Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	nodes := make([]*Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		nodes = append(nodes, n)
	}
	return nodes
}

// GetNode returns a specific node.
func (m *Manager) GetNode(nodeID string) *Node {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.nodes[nodeID]
}

// GetStats returns sync statistics.
func (m *Manager) GetStats() SyncStats {
	m.statsMu.RLock()
	defer m.statsMu.RUnlock()
	return m.stats
}

// GetReplicationStatus returns replication status for all nodes.
func (m *Manager) GetReplicationStatus() []*ReplicationStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := make([]*ReplicationStatus, 0)
	for id, node := range m.nodes {
		if node.IsLocal {
			continue
		}

		lastSync := m.lastSync[id]
		lag := time.Since(lastSync).Milliseconds()

		status = append(status, &ReplicationStatus{
			NodeID:          id,
			LastReplication: lastSync,
			LagMilliseconds: lag,
		})
	}

	return status
}

// Background workers

func (m *Manager) eventProcessor() {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		case event := <-m.eventQueue:
			// Log event for replay (protected by mu to prevent data race with checkConflict)
			m.mu.Lock()
			m.eventLog = append(m.eventLog, event)
			if len(m.eventLog) > 1000 {
				m.eventLog = m.eventLog[len(m.eventLog)-1000:]
			}
			m.mu.Unlock()
		}
	}
}

func (m *Manager) healthChecker() {
	defer m.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkNodeHealth()
		}
	}
}

func (m *Manager) replicationWorker() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.performFullSync()
		}
	}
}

// Helper methods

func (m *Manager) checkNodeHealth() {
	m.mu.RLock()
	nodes := make([]*Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		if !n.IsLocal {
			nodes = append(nodes, n)
		}
	}
	m.mu.RUnlock()

	staleTimeout := 5 * time.Minute // Remove nodes unseen for 5 minutes

	for _, node := range nodes {
		healthy := m.pingNode(node)
		m.mu.Lock()
		m.health[node.ID] = healthy
		if n, ok := m.nodes[node.ID]; ok {
			if healthy {
				n.Healthy = true
				n.LastSeen = time.Now()
			} else {
				n.Healthy = false
				// Remove stale nodes from all clusters
				if !n.LastSeen.IsZero() && time.Since(n.LastSeen) > staleTimeout {
					for _, cluster := range m.clusters {
						cluster.mu.Lock()
						cluster.Nodes = slices.DeleteFunc(cluster.Nodes, func(id string) bool {
							return id == node.ID
						})
						cluster.mu.Unlock()
					}
					delete(m.nodes, node.ID)
					delete(m.health, node.ID)
					m.mu.Unlock()
					continue
				}
			}
		}
		m.mu.Unlock()
	}
}

func (m *Manager) pingNode(node *Node) bool {
	client := m.httpClient
	req, err := http.NewRequest("GET", node.Address+"/api/cluster/health", nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-Cluster-Auth", m.config.SharedSecret)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode == http.StatusOK
}

func (m *Manager) replicateEvent(event *SyncEvent) {
	m.mu.RLock()
	clusters := make([]*Cluster, 0, len(m.clusters))
	for _, c := range m.clusters {
		clusters = append(clusters, c)
	}
	m.mu.RUnlock()

	for _, cluster := range clusters {
		// Check if entity type is in cluster scope
		if !m.isInScope(cluster, event.EntityType) {
			continue
		}

		cluster.mu.RLock()
		nodeIDs := make([]string, len(cluster.Nodes))
		copy(nodeIDs, cluster.Nodes)
		cluster.mu.RUnlock()

		for _, nodeID := range nodeIDs {
			if nodeID == m.config.NodeID {
				continue
			}

			m.mu.RLock()
			node, ok := m.nodes[nodeID]
			m.mu.RUnlock()
			if !ok || !node.Healthy {
				continue
			}

			if err := m.sendEventToNode(node, event); err != nil {
				log.Printf("[clustersync] warning: failed to send event to node %s: %v", nodeID, err)
			}
		}
	}
}

func (m *Manager) sendEventToNode(node *Node, event *SyncEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", node.Address+"/api/cluster/sync", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cluster-Auth", m.config.SharedSecret)
	req.Header.Set("X-Source-Node", m.config.NodeID)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
		return fmt.Errorf("sync failed: %d", resp.StatusCode)
	}

	m.mu.Lock()
	m.lastSync[node.ID] = time.Now()
	m.mu.Unlock()

	return nil
}

func (m *Manager) performFullSync() {
	m.mu.RLock()
	nodes := make([]*Node, 0)
	for _, n := range m.nodes {
		if !n.IsLocal && n.Healthy {
			nodes = append(nodes, n)
		}
	}
	m.mu.RUnlock()

	for _, node := range nodes {
		m.syncFromNode(node)
	}
}

func (m *Manager) syncFromNode(node *Node) {
	// Request all changes since last sync
	m.mu.RLock()
	lastSync := m.lastSync[node.ID]
	m.mu.RUnlock()

	url := fmt.Sprintf("%s/api/cluster/events?since=%d", node.Address, lastSync.Unix())

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Cluster-Auth", m.config.SharedSecret)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
		return
	}

	var events []*SyncEvent
	if err := json.NewDecoder(io.LimitReader(resp.Body, 10<<20)).Decode(&events); err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)

	for _, event := range events {
		if err := m.ReceiveEvent(event); err != nil {
			// Log but continue
			continue
		}
	}

	m.mu.Lock()
	m.lastSync[node.ID] = time.Now()
	m.mu.Unlock()
}

func (m *Manager) checkConflict(event *SyncEvent) (bool, *SyncEvent) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Check if we have a newer version of this entity
	for _, e := range m.eventLog {
		if e.EntityType == event.EntityType && e.EntityID == event.EntityID {
			if e.VectorClock != nil && event.VectorClock != nil {
				if isConcurrent(e.VectorClock, event.VectorClock) {
					return true, e
				}
				continue
			}
			if e.Timestamp > event.Timestamp {
				return true, e
			}
		}
	}
	return false, nil
}

func (m *Manager) resolveConflict(incoming, existing *SyncEvent) bool {
	switch m.config.ConflictResolution {
	case LastWriteWins:
		// Timestamp-based: newer wins
		return incoming.Timestamp > existing.Timestamp
	case SourcePriority:
		// Configurable priority
		return m.getNodePriority(incoming.SourceNode) > m.getNodePriority(existing.SourceNode)
	case Manual:
		// Always reject, manual intervention needed
		return false
	default:
		return incoming.Timestamp > existing.Timestamp
	}
}

func (m *Manager) getNodePriority(nodeID string) int {
	// Simple priority based on node ID ordering
	// Can be extended to configurable priorities
	if nodeID == m.config.NodeID {
		return 100 // Local has priority
	}
	return 50
}

func (m *Manager) getVectorClock() map[string]int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vectorClock[m.config.NodeID]++
	cp := make(map[string]int64, len(m.vectorClock))
	for k, v := range m.vectorClock {
		cp[k] = v
	}
	return cp
}

func (m *Manager) updateVectorClock(remote map[string]int64) {
	if remote == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range remote {
		if cur, ok := m.vectorClock[k]; !ok || v > cur {
			m.vectorClock[k] = v
		}
	}
}

// isConcurrent returns true if two vector clocks represent concurrent writes
// (neither happened-before the other).
func isConcurrent(a, b map[string]int64) bool {
	aLessB, bLessA := false, false
	for k, va := range a {
		if vb, ok := b[k]; ok {
			if va < vb {
				aLessB = true
			} else if va > vb {
				bLessA = true
			}
		} else {
			bLessA = true
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			aLessB = true
		}
	}
	return aLessB && bLessA
}

func (m *Manager) isInScope(cluster *Cluster, entityType string) bool {
	scope := cluster.SyncScope
	switch entityType {
	case "tenant", "tenant_rule":
		return scope&SyncTenants != 0
	case "rule":
		return scope&SyncRules != 0
	case "config":
		return scope&SyncConfig != 0
	default:
		return true
	}
}

// Utility functions

// validatePeerURL checks that a peer node URL is valid and warns about
// non-HTTPS endpoints. Unlike external URL validation, cluster peer URLs
// are expected to be on private networks, so private IPs are allowed
// but scheme and format are still validated.
func validatePeerURL(address string) error {
	u, err := url.Parse(address)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("peer URL must use http or https scheme, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("peer URL has empty host")
	}
	// Warn on non-HTTPS peer URLs
	if u.Scheme == "http" {
		log.Printf("[clustersync] WARNING: peer %s uses HTTP — cluster traffic may be intercepted", address)
	}
	// Warn on localhost/loopback (likely misconfiguration for cluster peers)
	if host == "localhost" || strings.HasSuffix(host, ".local") {
		log.Printf("[clustersync] WARNING: peer %s targets localhost/local — may be misconfigured", address)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			log.Printf("[clustersync] WARNING: peer %s targets loopback address — may be misconfigured", address)
		}
		if ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("must not target link-local/unspecified addresses")
		}
	}
	return nil
}

func generateEventID() string {
	return fmt.Sprintf("evt-%d-%s", time.Now().UnixNano(), generateRandomString(8))
}

func generateNodeIDFromAddress(address string) string {
	hash := sha256.Sum256([]byte(address))
	return "node-" + hex.EncodeToString(hash[:8])
}

func calculateChecksum(data map[string]any) string {
	if data == nil {
		return ""
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(jsonData)
	return hex.EncodeToString(hash[:16])
}

func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is extremely rare. Do NOT fall back to
		// predictable time-based values — fail explicitly rather than
		// generate guessable identifiers.
		log.Printf("[CRITICAL] crypto/rand failed to generate random string: %v — event IDs may be predictable", err)
		// Use whatever bytes were read (likely partial) rather than time-based fallback
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}
