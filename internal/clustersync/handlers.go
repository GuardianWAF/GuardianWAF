// Package clustersync provides HTTP handlers for cluster synchronization.
package clustersync

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"
)

// Handler provides HTTP handlers for cluster management.
type Handler struct {
	manager *Manager
}

// NewHandler creates a new cluster handler.
func NewHandler(manager *Manager) *Handler {
	return &Handler{manager: manager}
}

// RegisterRoutes registers cluster routes.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Internal cluster endpoints
	mux.HandleFunc("/api/cluster/health", h.handleHealth)
	mux.HandleFunc("/api/cluster/sync", h.handleSync)
	mux.HandleFunc("/api/cluster/events", h.handleEvents)

	// Dashboard/management endpoints
	mux.HandleFunc("/api/clusters", h.handleClusters)
	mux.HandleFunc("/api/clusters/", h.handleClusterDetail)
	mux.HandleFunc("/api/nodes", h.handleNodes)
	mux.HandleFunc("/api/sync/stats", h.handleStats)
	mux.HandleFunc("/api/sync/status", h.handleReplicationStatus)
}

// handleHealth returns node health status.
func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.checkAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"status":    "healthy",
		"node_id":   h.manager.config.NodeID,
		"node_name": h.manager.config.NodeName,
		"timestamp": time.Now().Unix(),
	}); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

// handleSync receives sync events from other nodes.
func (h *Handler) handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.checkAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var event SyncEvent
	// Limit request body to 10MB to prevent OOM from malicious nodes
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.manager.ReceiveEvent(&event); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

// handleEvents returns events since a given time.
func (h *Handler) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.checkAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse since parameter
	sinceStr := r.URL.Query().Get("since")
	var since time.Time
	if sinceStr != "" {
		if ts, err := strconv.ParseInt(sinceStr, 10, 64); err == nil {
			since = time.Unix(ts, 0)
		}
	}

	// Get events from all handlers
	// Snapshot handlers under lock to avoid data race
	h.manager.mu.RLock()
	handlers := make([]SyncHandler, 0, len(h.manager.handlers))
	for _, handler := range h.manager.handlers {
		handlers = append(handlers, handler)
	}
	h.manager.mu.RUnlock()

	events := make([]*SyncEvent, 0)
	for _, handler := range handlers {
		if h, ok := handler.(interface {
			List(since time.Time) ([]*SyncEvent, error)
		}); ok {
			list, err := h.List(since)
			if err == nil {
				events = append(events, list...)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(events); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

// handleClusters manages cluster configuration.
func (h *Handler) handleClusters(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listClusters(w, r)
	case http.MethodPost:
		h.createCluster(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) listClusters(w http.ResponseWriter, r *http.Request) {
	if !h.checkAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	clusters := h.manager.GetClusters()

	// Convert to serializable format (avoid copying mutex)
	result := make([]map[string]any, len(clusters))
	for i, c := range clusters {
		c.mu.RLock()
		nodes := make([]string, len(c.Nodes))
		copy(nodes, c.Nodes)
		c.mu.RUnlock()
		result[i] = map[string]any{
			"id":          c.ID,
			"name":        c.Name,
			"description": c.Description,
			"nodes":       nodes,
			"sync_scope":  c.SyncScope.String(),
			"created_at":  c.CreatedAt,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

func (h *Handler) createCluster(w http.ResponseWriter, r *http.Request) {
	if !h.checkAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var cluster Cluster
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
	if err := json.NewDecoder(r.Body).Decode(&cluster); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cluster.CreatedAt = time.Now()
	if cluster.ID == "" {
		cluster.ID = "cluster-" + time.Now().Format("20060102-150405")
	}

	if err := h.manager.AddCluster(&cluster); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"id":          cluster.ID,
		"name":        cluster.Name,
		"description": cluster.Description,
		"nodes":       cluster.Nodes,
		"sync_scope":  cluster.SyncScope.String(),
		"created_at":  cluster.CreatedAt,
	}); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

// handleClusterDetail handles single cluster operations.
func (h *Handler) handleClusterDetail(w http.ResponseWriter, r *http.Request) {
	clusterID := r.URL.Path[len("/api/clusters/"):]
	if clusterID == "" {
		http.Error(w, "Cluster ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getCluster(w, r, clusterID)
	case http.MethodDelete:
		h.deleteCluster(w, r, clusterID)
	case http.MethodPost:
		action := r.URL.Query().Get("action")
		if action == "join" {
			h.joinCluster(w, r, clusterID)
		} else if action == "leave" {
			h.leaveCluster(w, r, clusterID)
		} else {
			http.Error(w, "Unknown action", http.StatusBadRequest)
		}
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) getCluster(w http.ResponseWriter, r *http.Request, clusterID string) {
	if !h.checkAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	cluster := h.manager.GetCluster(clusterID)
	if cluster == nil {
		http.Error(w, "Cluster not found", http.StatusNotFound)
		return
	}

	cluster.mu.RLock()
	nodes := make([]string, len(cluster.Nodes))
	copy(nodes, cluster.Nodes)
	cluster.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"id":          cluster.ID,
		"name":        cluster.Name,
		"description": cluster.Description,
		"nodes":       nodes,
		"sync_scope":  cluster.SyncScope.String(),
		"created_at":  cluster.CreatedAt,
	}); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

func (h *Handler) deleteCluster(w http.ResponseWriter, r *http.Request, clusterID string) {
	if !h.checkAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := h.manager.RemoveCluster(clusterID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) joinCluster(w http.ResponseWriter, r *http.Request, clusterID string) {
	if !h.checkAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var node Node
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if node.ID == "" {
		node.ID = generateNodeIDFromAddress(node.Address)
	}

	if err := h.manager.AddNodeToCluster(clusterID, &node); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"id":        node.ID,
		"name":      node.Name,
		"address":   node.Address,
		"healthy":   node.Healthy,
		"version":   node.Version,
		"last_seen": node.LastSeen,
	}); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

func (h *Handler) leaveCluster(w http.ResponseWriter, r *http.Request, clusterID string) {
	if !h.checkAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}

	if err := h.manager.RemoveNodeFromCluster(clusterID, nodeID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleNodes returns all known nodes.
func (h *Handler) handleNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.checkAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	nodes := h.manager.GetNodes()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(nodes); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

// handleStats returns sync statistics.
func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.checkAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	stats := h.manager.GetStats()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

// handleReplicationStatus returns replication status for all nodes.
func (h *Handler) handleReplicationStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.checkAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	status := h.manager.GetReplicationStatus()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"local_node": h.manager.config.NodeID,
		"nodes":      status,
	}); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

func (h *Handler) checkAuth(r *http.Request) bool {
	// Shared secret is required for cluster sync — without it, all cluster
	// endpoints (sync, join, config) would be unauthenticated.
	if h.manager.config.SharedSecret == "" {
		log.Printf("[ERROR] Cluster sync shared secret is not configured — refusing request. Set SharedSecret before enabling cluster sync.")
		return false
	}
	// Check shared secret auth using constant-time comparison
	authHeader := r.Header.Get("X-Cluster-Auth")
	if authHeader != "" && subtle.ConstantTimeCompare([]byte(authHeader), []byte(h.manager.config.SharedSecret)) == 1 {
		return true
	}

	return false
}
