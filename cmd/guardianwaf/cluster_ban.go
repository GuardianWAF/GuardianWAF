package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// cmdClusterBan bans an IP cluster-wide via the dashboard API.
// It follows 307 leader redirects automatically so it works against
// any node in the cluster (leader or follower).
//
// Usage:
//
//	guardianwaf cluster ban <ip> [--reason "..."] [--duration 1h] [--url URL] [--api-key KEY]
func cmdClusterBan(args []string) int {
	fs := flag.NewFlagSet("cluster ban", flag.ExitOnError)
	reason := fs.String("reason", "manual ban from CLI", "Reason for the ban")
	duration := fs.String("duration", "1h", "Ban duration (e.g. 30m, 1h, 24h, 720h)")
	apiURL := fs.String("url", "", "Dashboard URL (default: from config)")
	apiKey := fs.String("api-key", "", "Dashboard API key (default: GWAF_DASHBOARD_API_KEY env)")
	configPath := fs.String("config", "", "Path to config file (for deriving --url)")
	_ = fs.Parse(args) // nolint:errcheck // ExitOnError

	rest := fs.Args()
	if len(rest) < 1 || rest[0] == "" {
		fmt.Fprintln(os.Stderr, "Usage: guardianwaf cluster ban <ip> [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "The ban is replicated to all cluster nodes via Raft consensus.")
		fmt.Fprintln(os.Stderr, "If this node is a follower, the request is automatically redirected to the leader.")
		return 1
	}
	ip := rest[0]

	// Validate duration.
	ttl, err := time.ParseDuration(*duration)
	if err != nil || ttl <= 0 {
		fmt.Fprintf(os.Stderr, "invalid duration %q: %v\n", *duration, err)
		return 1
	}

	baseURL, key := resolveClusterEndpoint(*apiURL, *apiKey, *configPath)

	body := map[string]string{
		"ip":       ip,
		"reason":   *reason,
		"duration": *duration,
	}
	bodyBytes, _ := json.Marshal(body)

	resp, status, err := doClusterRequest("POST", baseURL+"/api/v1/bans", key, bodyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ban failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close() // nolint:errcheck

	if status == http.StatusOK {
		fmt.Printf("✓ Banned %s for %s (cluster-wide)\n", ip, ttl.String())
		return 0
	}

	// Read error body.
	errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	fmt.Fprintf(os.Stderr, "ban failed: HTTP %d: %s\n", status, strings.TrimSpace(string(errBody)))
	return 1
}

// cmdClusterUnban removes a cluster-wide ban.
//
// Usage:
//
//	guardianwaf cluster unban <ip> [--url URL] [--api-key KEY]
func cmdClusterUnban(args []string) int {
	fs := flag.NewFlagSet("cluster unban", flag.ExitOnError)
	apiURL := fs.String("url", "", "Dashboard URL (default: from config)")
	apiKey := fs.String("api-key", "", "Dashboard API key (default: GWAF_DASHBOARD_API_KEY env)")
	configPath := fs.String("config", "", "Path to config file (for deriving --url)")
	_ = fs.Parse(args) // nolint:errcheck // ExitOnError

	rest := fs.Args()
	if len(rest) < 1 || rest[0] == "" {
		fmt.Fprintln(os.Stderr, "Usage: guardianwaf cluster unban <ip> [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "The unban is replicated to all cluster nodes via Raft consensus.")
		return 1
	}
	ip := rest[0]

	baseURL, key := resolveClusterEndpoint(*apiURL, *apiKey, *configPath)

	body := map[string]string{"ip": ip}
	bodyBytes, _ := json.Marshal(body)

	resp, status, err := doClusterRequest("DELETE", baseURL+"/api/v1/bans", key, bodyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unban failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close() // nolint:errcheck

	if status == http.StatusOK {
		fmt.Printf("✓ Removed ban on %s (cluster-wide)\n", ip)
		return 0
	}

	errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	fmt.Fprintf(os.Stderr, "unban failed: HTTP %d: %s\n", status, strings.TrimSpace(string(errBody)))
	return 1
}

// resolveClusterEndpoint determines the dashboard URL and API key from
// flags, environment, or config file — in that priority order.
func resolveClusterEndpoint(flagURL, flagKey, configPath string) (url, key string) {
	// URL: flag → env → config.
	url = flagURL
	if url == "" {
		url = os.Getenv("GWAF_DASHBOARD_URL")
	}
	if url == "" {
		cfg := loadConfig(configPath, configPath != "")
		if cfg.Dashboard.Enabled && cfg.Dashboard.Listen != "" {
			url = "http://" + probeHostPort(cfg.Dashboard.Listen)
		} else {
			url = "http://127.0.0.1:9443"
		}
	}

	// API key: flag → env.
	key = flagKey
	if key == "" {
		key = os.Getenv("GWAF_DASHBOARD_API_KEY")
	}

	return url, key
}

// doClusterRequest sends a JSON request to the dashboard API with the API key
// header, following up to 3 leader-redirect (307) responses automatically.
// This makes ban/unban work against any node — follower requests are
// transparently redirected to the leader.
func doClusterRequest(method, url, apiKey string, body []byte) (*http.Response, int, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		// Don't follow redirects automatically — the manual loop below
		// handles 307 leader redirects and re-attaches the API key header.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Follow up to 3 redirects manually to handle leader-redirect (307).
	currentURL := url
	for i := 0; i < 4; i++ {
		req, err := http.NewRequest(method, currentURL, bytes.NewReader(body))
		if err != nil {
			return nil, 0, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if apiKey != "" {
			req.Header.Set("X-API-Key", apiKey)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, fmt.Errorf("request to %s: %w", currentURL, err)
		}

		// If we get a 307 redirect, follow it manually.
		if resp.StatusCode == http.StatusTemporaryRedirect {
			location := resp.Header.Get("Location")
			resp.Body.Close() // nolint:errcheck
			if location == "" {
				return nil, resp.StatusCode, fmt.Errorf("got 307 redirect without Location header")
			}
			currentURL = location
			continue
		}

		return resp, resp.StatusCode, nil
	}

	return nil, 0, fmt.Errorf("too many leader redirects (>3)")
}

// cmdClusterBans lists all active cluster-wide bans from the dashboard API.
//
// Usage:
//
//	guardianwaf cluster bans [--url URL] [--api-key KEY]
func cmdClusterBans(args []string) int {
	fs := flag.NewFlagSet("cluster bans", flag.ExitOnError)
	apiURL := fs.String("url", "", "Dashboard URL (default: from config)")
	apiKey := fs.String("api-key", "", "Dashboard API key (default: GWAF_DASHBOARD_API_KEY env)")
	configPath := fs.String("config", "", "Path to config file (for deriving --url)")
	timeout := fs.Duration("timeout", 5*time.Second, "Request timeout")
	_ = fs.Parse(args) // nolint:errcheck

	baseURL, key := resolveClusterEndpoint(*apiURL, *apiKey, *configPath)

	client := &http.Client{Timeout: *timeout}
	url := strings.TrimRight(baseURL, "/") + "/api/v1/cluster/bans"
	body, status, err := fetchJSON(client, url, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cluster bans: %v\n", err)
		return 1
	}
	if status != http.StatusOK {
		errStr := "unknown"
		if e, ok := body["error"].(string); ok {
			errStr = e
		}
		fmt.Fprintf(os.Stderr, "cluster bans: HTTP %d: %s\n", status, errStr)
		return 1
	}

	if enabled, _ := body["enabled"].(bool); !enabled {
		fmt.Println("Cluster mode is not enabled on this node.")
		return 0
	}

	bansRaw, ok := body["bans"].([]any)
	if !ok {
		fmt.Println("No active cluster-wide bans.")
		return 0
	}
	if len(bansRaw) == 0 {
		fmt.Println("No active cluster-wide bans.")
		return 0
	}

	// Print table header.
	fmt.Printf("%-45s %-25s %s\n", "IP", "BANNED AT", "EXPIRES AT")
	fmt.Println(strings.Repeat("-", 45) + " " + strings.Repeat("-", 25) + " " + strings.Repeat("-", 25))

	for _, b := range bansRaw {
		entry, ok := b.(map[string]any)
		if !ok {
			continue
		}
		ip, _ := entry["ip"].(string)
		bannedAt, _ := entry["banned_at"].(string)
		expiresAt, _ := entry["expires_at"].(string)
		if expiresAt == "" {
			expiresAt = "permanent"
		}
		if bannedAt == "" {
			bannedAt = "unknown"
		}
		fmt.Printf("%-45s %-25s %s\n", ip, bannedAt, expiresAt)
	}

	fmt.Printf("\n%d active cluster-wide ban(s)\n", len(bansRaw))
	return 0
}
