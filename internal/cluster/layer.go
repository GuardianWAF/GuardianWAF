package cluster

import (
	"net"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Layer provides cluster integration as a WAF layer.
type Layer struct {
	cluster *Cluster
	config  *LayerConfig
}

// LayerConfig for cluster layer.
type LayerConfig struct {
	Enabled bool    `yaml:"enabled"`
	Config  *Config `yaml:"cluster_config"`
}

// NewLayer creates a new cluster layer.
func NewLayer(cfg *LayerConfig) (*Layer, error) {
	if cfg == nil {
		cfg = &LayerConfig{
			Enabled: false,
			Config:  DefaultConfig(),
		}
	}

	if !cfg.Enabled {
		return &Layer{config: cfg}, nil
	}

	cluster, err := New(cfg.Config)
	if err != nil {
		return nil, err
	}

	return &Layer{
		cluster: cluster,
		config:  cfg,
	}, nil
}

// Name returns the layer name.
func (l *Layer) Name() string {
	return "cluster"
}

// Process implements the layer interface.
// Checks if the request IP is banned cluster-wide.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	result := engine.LayerResult{
		Action: engine.ActionPass,
	}

	if !l.config.Enabled || l.cluster == nil {
		return result
	}

	// Check if IP is banned cluster-wide
	ip := ctx.ClientIP.String()
	if l.cluster.IsIPBanned(ip) {
		result.Action = engine.ActionBlock
		result.Score = 100
		result.Findings = append(result.Findings, engine.Finding{
			DetectorName: "cluster",
			Category:     "policy",
			Description:  "IP banned cluster-wide",
			Severity:     engine.SeverityCritical,
		})
	}

	return result
}

// Start starts the cluster layer.
func (l *Layer) Start() error {
	if l.cluster == nil {
		return nil
	}
	return l.cluster.Start()
}

// Stop stops the cluster layer.
func (l *Layer) Stop() error {
	if l.cluster == nil {
		return nil
	}
	return l.cluster.Stop()
}

// GetCluster returns the underlying cluster instance.
func (l *Layer) GetCluster() *Cluster {
	return l.cluster
}

// IsLeader returns true if this node is the cluster leader.
func (l *Layer) IsLeader() bool {
	if l.cluster == nil {
		return false
	}
	return l.cluster.IsLeader()
}

// GetNodeCount returns the number of nodes in the cluster.
func (l *Layer) GetNodeCount() int {
	if l.cluster == nil {
		return 1 // Local node only
	}
	return l.cluster.GetNodeCount()
}

// BanIP adds an IP to the cluster-wide ban list.
func (l *Layer) BanIP(ip net.IP, ttl time.Duration) {
	if l.cluster == nil {
		return
	}
	l.cluster.BanIP(ip.String(), ttl)
}
