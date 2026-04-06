// Package clustersync provides active-active replication between GuardianWAF nodes.
package clustersync

import (
	"sync"
	"time"
)

// SyncScope defines what data to synchronize.
type SyncScope int

const (
	SyncTenants SyncScope = 1 << iota
	SyncRules
	SyncConfig
	SyncAll = SyncTenants | SyncRules | SyncConfig
)

// ParseSyncScope parses a string scope.
func ParseSyncScope(s string) SyncScope {
	switch s {
	case "tenants":
		return SyncTenants
	case "rules":
		return SyncRules
	case "config":
		return SyncConfig
	case "all":
		return SyncAll
	default:
		return SyncTenants // Default
	}
}

// String returns scope name.
func (s SyncScope) String() string {
	switch s {
	case SyncTenants:
		return "tenants"
	case SyncRules:
		return "rules"
	case SyncConfig:
		return "config"
	case SyncAll:
		return "all"
	default:
		return "custom"
	}
}

// Node represents a peer node in the cluster.
type Node struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Address   string    `json:"address"`    // https://host:port
	APIKey    string    `json:"api_key"`    // Shared secret for auth
	LastSeen  time.Time `json:"last_seen"`
	Healthy   bool      `json:"healthy"`
	Version   string    `json:"version"`
	IsLocal   bool      `json:"is_local"`
}

// Cluster represents a named group of nodes.
type Cluster struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Nodes       []string          `json:"nodes"`        // Node IDs
	SyncScope   SyncScope         `json:"sync_scope"`
	CreatedAt   time.Time         `json:"created_at"`
	mu          sync.RWMutex
}

// SyncEvent represents a data change to replicate.
type SyncEvent struct {
	ID          string                 `json:"id"`
	Timestamp   int64                  `json:"timestamp"`    // Unix nano
	SourceNode  string                 `json:"source_node"`
	ClusterID   string                 `json:"cluster_id"`
	EntityType  string                 `json:"entity_type"`  // "tenant", "rule", "config"
	EntityID    string                 `json:"entity_id"`
	Action      string                 `json:"action"`       // "create", "update", "delete"
	Data        map[string]any `json:"data,omitempty"`
	Checksum    string                 `json:"checksum"`
	VectorClock map[string]int64       `json:"vector_clock"` // For conflict resolution
}

// ConflictResolution defines how to handle concurrent updates.
type ConflictResolution int

const (
	LastWriteWins ConflictResolution = iota
	SourcePriority
	Manual
)

// ReplicationStatus tracks sync state.
type ReplicationStatus struct {
	NodeID           string            `json:"node_id"`
	LastReplication  time.Time         `json:"last_replication"`
	PendingEvents    int               `json:"pending_events"`
	FailedAttempts   int               `json:"failed_attempts"`
	LagMilliseconds  int64             `json:"lag_ms"`
	SyncStatus       map[string]string `json:"sync_status"` // entity -> "ok" | "lagging" | "failed"
}

// SyncStats provides replication statistics.
type SyncStats struct {
	TotalEventsSent     int64     `json:"total_events_sent"`
	TotalEventsReceived int64     `json:"total_events_received"`
	TotalConflicts      int64     `json:"total_conflicts"`
	TotalResolved       int64     `json:"total_resolved"`
	ActiveConnections   int       `json:"active_connections"`
	LastConflictAt      time.Time `json:"last_conflict_at"`
}

// Config for cluster sync.
type Config struct {
	Enabled            bool               `json:"enabled"`
	NodeID             string             `json:"node_id"`
	NodeName           string             `json:"node_name"`
	BindAddress        string             `json:"bind_address"`
	APIPort            int                `json:"api_port"`
	SharedSecret       string             `json:"shared_secret"`
	Clusters           []ClusterConfig    `json:"clusters"`
	SyncInterval       time.Duration      `json:"sync_interval"`
	ConflictResolution ConflictResolution `json:"conflict_resolution"`
	MaxRetries         int                `json:"max_retries"`
	RetryDelay         time.Duration      `json:"retry_delay"`
}

// ClusterConfig defines a cluster membership.
type ClusterConfig struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Nodes       []Node   `json:"nodes"`
	SyncScope   string   `json:"sync_scope"`
	Bidirectional bool   `json:"bidirectional"`
}

// DefaultConfig returns default sync config.
func DefaultConfig() *Config {
	return &Config{
		Enabled:            false,
		NodeID:             generateNodeID(),
		NodeName:           "node-1",
		BindAddress:        "0.0.0.0",
		APIPort:            9444,
		SyncInterval:       30 * time.Second,
		ConflictResolution: LastWriteWins,
		MaxRetries:         3,
		RetryDelay:         5 * time.Second,
		Clusters:           []ClusterConfig{},
	}
}

func generateNodeID() string {
	return "gwaf-" + time.Now().Format("20060102-150405")
}
