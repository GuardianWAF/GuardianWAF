package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// cmdCluster is the entry point for cluster-related CLI subcommands.
// Usage: guardianwaf cluster <subcommand> [options]
//
// Currently supports:
//
//	status   Query the local node's cluster status and print a summary
func cmdCluster(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: guardianwaf cluster <status> [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Subcommands:")
		fmt.Fprintln(os.Stderr, "  status    Show cluster membership, Raft state, and replicated store stats")
		return 1
	}

	switch args[0] {
	case "status":
		return cmdClusterStatus(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown cluster subcommand: %s\n\n", args[0])
		fmt.Fprintln(os.Stderr, "Available subcommands: status")
		return 1
	}
}

// cmdClusterStatus queries the local GuardianWAF node's cluster API and
// prints a human-readable summary. It reads the dashboard listen address
// from the config file (or accepts --url override) and uses the API key
// for authentication.
func cmdClusterStatus(args []string) int {
	fs := flag.NewFlagSet("cluster status", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to config file (default: platform-specific)")
	fs.StringVar(configPath, "c", "", "Path to config file (short)")
	apiURL := fs.String("url", "", "Cluster API base URL (default: derived from config dashboard.listen)")
	apiKey := fs.String("api-key", "", "Dashboard API key (default: from config or GWAF_DASHBOARD_API_KEY)")
	timeout := fs.Duration("timeout", 5*time.Second, "Request timeout")
	_ = fs.Parse(args) // nolint:errcheck // ExitOnError flag set never returns an error

	// Determine the API base URL.
	base := *apiURL
	if base == "" {
		cfg := loadConfig(*configPath, *configPath != "")
		if err := config.LoadEnv(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "cluster status: invalid environment: %v\n", err)
			return 1
		}
		base = "http://" + probeHostPort(cfg.Dashboard.Listen)
	}
	base = strings.TrimRight(base, "/")

	// Determine the API key.
	key := *apiKey
	if key == "" {
		key = os.Getenv("GWAF_DASHBOARD_API_KEY")
	}
	if key == "" {
		// Try config file.
		cfg := loadConfig(*configPath, *configPath != "")
		_ = config.LoadEnv(cfg) // nolint:errcheck // env already loaded above if URL was derived
		key = cfg.Dashboard.APIKey
	}

	client := &http.Client{Timeout: *timeout}

	// Query /api/v1/cluster/node/stats for the local node's Raft + store stats.
	statsURL := base + "/api/v1/cluster/node/stats"
	statsBody, status, err := fetchJSON(client, statsURL, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cluster status: failed to query %s: %v\n", statsURL, err)
		return 1
	}
	if status == http.StatusNotFound || (status == http.StatusOK && statsBody["enabled"] == false) {
		fmt.Println("Cluster mode is not enabled on this node.")
		fmt.Println("Enable cluster mode in the config file (cluster.enabled: true) to see status.")
		return 0
	}
	if status != http.StatusOK {
		fmt.Fprintf(os.Stderr, "cluster status: %s returned HTTP %d\n", statsURL, status)
		return 1
	}

	// Query /api/v1/cluster/nodes for the peer list.
	nodesURL := base + "/api/v1/cluster/nodes"
	nodesBody, _, err := fetchJSON(client, nodesURL, key)
	if err != nil {
		// Non-fatal — show what we have.
		nodesBody = map[string]any{"nodes": []any{}}
	}

	// Print the summary.
	printClusterSummary(statsBody, nodesBody)
	return 0
}

// fetchJSON makes an authenticated GET request and returns the parsed JSON body.
func fetchJSON(client *http.Client, url, apiKey string) (map[string]any, int, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() // nolint:errcheck // read-only response

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB max
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}

	var body map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("parse JSON: %w", err)
		}
	}
	return body, resp.StatusCode, nil
}

// printClusterSummary writes a human-readable cluster status report to stdout.
func printClusterSummary(stats, nodes map[string]any) {
	printClusterSummaryTo(os.Stdout, stats, nodes)
}

// printClusterSummaryTo writes the cluster status report to the given writer.
// Separated from printClusterSummary for testability.
func printClusterSummaryTo(w io.Writer, stats, nodes map[string]any) {
	nodeID, _ := stats["node_id"].(string)
	role, _ := stats["role"].(string)
	term := toUint64(stats["term"])
	commitIdx := toUint64(stats["commit_index"])
	lastApplied := toUint64(stats["last_applied"])
	logLen := toUint64(stats["log_length"])

	var bans, rules, counters int
	if store, ok := stats["store"].(map[string]any); ok {
		bans = int(toUint64(store["bans"]))
		rules = int(toUint64(store["rules"]))
		counters = int(toUint64(store["counters"]))
	}

	// Header
	fmt.Fprintln(w, "┌─────────────────────────────────────────────┐")
	fmt.Fprintln(w, "│          GuardianWAF Cluster Status          │")
	fmt.Fprintln(w, "└─────────────────────────────────────────────┘")
	fmt.Fprintln(w)

	// Node identity
	fmt.Fprintf(w, "  Node ID:     %s\n", nodeID)
	fmt.Fprintf(w, "  Role:        %s", role)
	if role == "leader" {
		fmt.Fprint(w, "  ★")
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Term:        %d\n", term)
	fmt.Fprintln(w)

	// Raft replication
	lag := commitIdx - lastApplied
	fmt.Fprintln(w, "  Raft Consensus:")
	fmt.Fprintf(w, "    Commit Index:   %d\n", commitIdx)
	fmt.Fprintf(w, "    Last Applied:   %d\n", lastApplied)
	fmt.Fprintf(w, "    Log Length:     %d\n", logLen)
	if lag > 0 {
		fmt.Fprintf(w, "    Replication Lag: %d entries (apply is behind commit)\n", lag)
	} else {
		fmt.Fprintf(w, "    Replication Lag: 0 (up to date)\n")
	}
	fmt.Fprintln(w)

	// Replicated store
	fmt.Fprintln(w, "  Replicated Store:")
	fmt.Fprintf(w, "    Bans:      %d\n", bans)
	fmt.Fprintf(w, "    Rules:     %d\n", rules)
	fmt.Fprintf(w, "    Counters:  %d\n", counters)
	fmt.Fprintln(w)

	// Peer list
	if nodeList, ok := nodes["nodes"].([]any); ok && len(nodeList) > 0 {
		fmt.Fprintf(w, "  Cluster Members (%d):\n", len(nodeList))
		for _, raw := range nodeList {
			n, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			id, _ := n["id"].(string)
			isLeader, _ := n["is_leader"].(bool)
			addr, _ := n["addr"].(string)

			marker := "  "
			if isLeader {
				marker = "★ "
			}
			if addr != "" {
				fmt.Fprintf(w, "    %s%s (%s)\n", marker, id, addr)
			} else {
				fmt.Fprintf(w, "    %s%s (self)\n", marker, id)
			}
		}
	} else {
		fmt.Fprintln(w, "  No peer information available.")
	}
	fmt.Fprintln(w)

	// Health summary
	if lag > 10 {
		fmt.Fprintln(w, "  ⚠ Replication lag is high — check node health.")
	}
	if role == "leader" {
		fmt.Fprintln(w, "  ✓ This node is the cluster leader.")
	} else if role == "follower" {
		fmt.Fprintln(w, "  ✓ This node is a healthy follower.")
	}
}

// toUint64 safely extracts a uint64 from an any value that might be
// float64 (JSON default), int, or json.Number.
func toUint64(v any) uint64 {
	switch n := v.(type) {
	case float64:
		return uint64(n)
	case int:
		return uint64(n)
	case int64:
		return uint64(n)
	case json.Number:
		i, _ := n.Int64()
		return uint64(i)
	default:
		return 0
	}
}
