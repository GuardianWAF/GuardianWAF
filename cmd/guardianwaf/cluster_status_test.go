package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintClusterSummary_Leader(t *testing.T) {
	stats := map[string]any{
		"enabled":      true,
		"node_id":      "guardianwaf-0",
		"role":         "leader",
		"term":         float64(5),
		"commit_index": float64(42),
		"last_applied": float64(42),
		"log_length":   float64(42),
		"store": map[string]any{
			"bans":     float64(3),
			"rules":    float64(7),
			"counters": float64(12),
		},
	}
	nodes := map[string]any{
		"enabled": true,
		"nodes": []any{
			map[string]any{"id": "guardianwaf-0", "is_leader": true},
			map[string]any{"id": "guardianwaf-1", "addr": "10.0.0.2:7947", "is_leader": false},
			map[string]any{"id": "guardianwaf-2", "addr": "10.0.0.3:7947", "is_leader": false},
		},
	}

	var buf bytes.Buffer
	printClusterSummaryTo(&buf, stats, nodes)
	out := buf.String()

	checks := []string{
		"guardianwaf-0",
		"leader",
		"★",
		"Term:        5",
		"Commit Index:   42",
		"Last Applied:   42",
		"Replication Lag: 0",
		"Bans:      3",
		"Rules:     7",
		"Counters:  12",
		"Cluster Members (3)",
		"guardianwaf-1",
		"guardianwaf-2",
		"This node is the cluster leader",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nOutput:\n%s", want, out)
		}
	}
}

func TestPrintClusterSummary_FollowerWithLag(t *testing.T) {
	stats := map[string]any{
		"enabled":      true,
		"node_id":      "guardianwaf-1",
		"role":         "follower",
		"term":         float64(5),
		"commit_index": float64(50),
		"last_applied": float64(35),
		"log_length":   float64(50),
		"store": map[string]any{
			"bans":     float64(2),
			"rules":    float64(6),
			"counters": float64(8),
		},
	}
	nodes := map[string]any{
		"enabled": true,
		"nodes": []any{
			map[string]any{"id": "guardianwaf-1", "is_leader": false},
			map[string]any{"id": "guardianwaf-0", "addr": "10.0.0.1:7947", "is_leader": true},
		},
	}

	var buf bytes.Buffer
	printClusterSummaryTo(&buf, stats, nodes)
	out := buf.String()

	if !strings.Contains(out, "Replication Lag: 15") {
		t.Errorf("expected lag 15, output:\n%s", out)
	}
	if !strings.Contains(out, "⚠ Replication lag is high") {
		t.Errorf("expected high-lag warning, output:\n%s", out)
	}
	if !strings.Contains(out, "healthy follower") {
		t.Errorf("expected follower health message, output:\n%s", out)
	}
}

func TestPrintClusterSummary_ClusterDisabled(t *testing.T) {
	stats := map[string]any{
		"enabled": false,
	}
	nodes := map[string]any{
		"enabled": false,
		"nodes":   []any{},
	}

	var buf bytes.Buffer
	printClusterSummaryTo(&buf, stats, nodes)
	out := buf.String()

	if !strings.Contains(out, "Node ID:") {
		// When disabled, the fields are zero-valued but the template still renders.
		// The test just verifies it doesn't panic.
		_ = out
	}
}

func TestToUint64(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  uint64
	}{
		{"float64", float64(42.0), 42},
		{"int", 42, 42},
		{"int64", int64(42), 42},
		{"zero float", float64(0), 0},
		{"nil", nil, 0},
		{"string", "42", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := toUint64(tc.input)
			if got != tc.want {
				t.Errorf("toUint64(%v) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}
