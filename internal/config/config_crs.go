package config

import (
	"time"
)

// CRSConfig controls OWASP Core Rule Set integration.
type CRSConfig struct {
	Enabled          bool     `yaml:"enabled"`
	RulePath         string   `yaml:"rule_path"`          // Path to CRS rules directory
	ParanoiaLevel    int      `yaml:"paranoia_level"`     // 1-4 (default: 1)
	AnomalyThreshold int      `yaml:"anomaly_threshold"`  // Block threshold (default: 5)
	Exclusions       []string `yaml:"exclusions"`         // Rule exclusions
	DisabledRules    []string `yaml:"disabled_rules"`     // Rule IDs to disable
}

// VirtualPatchConfig controls virtual patching for known CVEs.
type VirtualPatchConfig struct {
	Enabled           bool          `yaml:"enabled"`
	AutoUpdate        bool          `yaml:"auto_update"`        // Auto-update CVE DB
	UpdateInterval    time.Duration `yaml:"update_interval"`    // Default: 24h
	CVEPath           string        `yaml:"cve_path"`           // Local CVE DB path
	NVDFeedURL        string        `yaml:"nvd_feed_url"`       // NVD API endpoint
	AutoGenerateRules bool          `yaml:"auto_generate_rules"` // Generate rules from CVEs
	BlockSeverity     []string      `yaml:"block_severity"`     // ["CRITICAL", "HIGH"]
	NotifyOnPatch     bool          `yaml:"notify_on_patch"`
}
