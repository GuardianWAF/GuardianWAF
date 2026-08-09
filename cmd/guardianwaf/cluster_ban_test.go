package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCmdClusterBan_MissingIP(t *testing.T) {
	exitCode := cmdClusterBan([]string{})
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for missing IP, got %d", exitCode)
	}
}

func TestCmdClusterBan_InvalidDuration(t *testing.T) {
	exitCode := cmdClusterBan([]string{"1.2.3.4", "-duration", "not-a-duration"})
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid duration, got %d", exitCode)
	}
}

func TestCmdClusterBan_ConnectionRefused(t *testing.T) {
	exitCode := cmdClusterBan([]string{
		"1.2.3.4",
		"--url", "http://127.0.0.1:1", // port 1 — connection refused
		"--duration", "1h",
	})
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for connection refused, got %d", exitCode)
	}
}

func TestCmdClusterBan_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/bans" || r.Method != "POST" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)

		if body["ip"] != "10.0.0.5" {
			t.Errorf("expected ip 10.0.0.5, got %s", body["ip"])
		}
		if body["duration"] != "2h" {
			t.Errorf("expected duration 2h, got %s", body["duration"])
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok","ip":"10.0.0.5"}`)
	}))
	defer srv.Close()

	exitCode := cmdClusterBan([]string{
		"--url", srv.URL,
		"--duration", "2h",
		"--reason", "test ban",
		"10.0.0.5",
	})
	if exitCode != 0 {
		t.Errorf("expected exit code 0 for successful ban, got %d", exitCode)
	}
}

func TestCmdClusterBan_FollowsLeaderRedirect(t *testing.T) {
	// Follower returns 307 → leader handles the ban.
	leaderHandled := false
	leader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaderHandled = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer leader.Close()

	follower := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", leader.URL+"/api/v1/bans")
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = io.WriteString(w, `{"error":"not raft leader","leader_url":"`+leader.URL+`"}`)
	}))
	defer follower.Close()

	exitCode := cmdClusterBan([]string{
		"--url", follower.URL,
		"192.168.1.1",
	})
	if exitCode != 0 {
		t.Errorf("expected exit code 0 after redirect, got %d", exitCode)
	}
	if !leaderHandled {
		t.Error("leader server did not receive the redirected request")
	}
}

func TestCmdClusterBan_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	exitCode := cmdClusterBan([]string{
		"--url", srv.URL,
		"10.0.0.1",
	})
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for server error, got %d", exitCode)
	}
}

func TestCmdClusterUnban_MissingIP(t *testing.T) {
	exitCode := cmdClusterUnban([]string{})
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for missing IP, got %d", exitCode)
	}
}

func TestCmdClusterUnban_ConnectionRefused(t *testing.T) {
	exitCode := cmdClusterUnban([]string{
		"--url", "http://127.0.0.1:1",
		"1.2.3.4",
	})
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for connection refused, got %d", exitCode)
	}
}

func TestCmdClusterUnban_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/bans" || r.Method != "DELETE" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)

		if body["ip"] != "10.0.0.5" {
			t.Errorf("expected ip 10.0.0.5, got %s", body["ip"])
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok","ip":"10.0.0.5"}`)
	}))
	defer srv.Close()

	exitCode := cmdClusterUnban([]string{
		"--url", srv.URL,
		"10.0.0.5",
	})
	if exitCode != 0 {
		t.Errorf("expected exit code 0 for successful unban, got %d", exitCode)
	}
}

func TestResolveClusterEndpoint_FlagPriority(t *testing.T) {
	url, key := resolveClusterEndpoint("http://flag:9999", "flagkey", "")
	if url != "http://flag:9999" {
		t.Errorf("expected flag URL, got %s", url)
	}
	if key != "flagkey" {
		t.Errorf("expected flag key, got %s", key)
	}
}

func TestDoClusterRequest_TooManyRedirects(t *testing.T) {
	// Server always returns 307 → client should exhaust redirect limit.
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srvURL+r.URL.String())
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	srvURL = srv.URL
	defer srv.Close()

	_, _, err := doClusterRequest("POST", srv.URL+"/api/v1/bans", "", []byte("{}"))
	if err == nil {
		t.Fatal("expected error for redirect loop")
	}
	if !strings.Contains(err.Error(), "too many") {
		t.Errorf("expected 'too many redirects' error, got: %v", err)
	}
}

func TestCmdClusterBans_Success(t *testing.T) {
	var capturedURL, capturedKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.Path
		capturedKey = r.Header.Get("X-API-Key")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled": true,
			"bans": []map[string]any{
				{"ip": "10.0.0.1", "banned_at": "2026-08-07T10:00:00Z", "expires_at": "2026-08-07T11:00:00Z"},
				{"ip": "10.0.0.2", "banned_at": "2026-08-07T09:00:00Z"},
			},
		})
	}))
	defer srv.Close()

	code := cmdClusterBans([]string{"--url", srv.URL, "--api-key", "test-key"})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if capturedURL != "/api/v1/cluster/bans" {
		t.Errorf("URL = %q, want /api/v1/cluster/bans", capturedURL)
	}
	if capturedKey != "test-key" {
		t.Errorf("API key = %q, want test-key", capturedKey)
	}
}

func TestCmdClusterBans_EmptyList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled": true,
			"bans":    []any{},
		})
	}))
	defer srv.Close()

	code := cmdClusterBans([]string{"--url", srv.URL})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
}

func TestCmdClusterBans_ClusterDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled": false,
			"bans":    []any{},
		})
	}))
	defer srv.Close()

	code := cmdClusterBans([]string{"--url", srv.URL})
	if code != 0 {
		t.Fatalf("expected exit 0 for disabled cluster, got %d", code)
	}
}

func TestCmdClusterBans_ConnectionError(t *testing.T) {
	// Use port 1 — guaranteed to refuse connections.
	code := cmdClusterBans([]string{"--url", "http://127.0.0.1:1"})
	if code == 0 {
		t.Fatal("expected exit 1 for connection error, got 0")
	}
}

func TestCmdClusterBans_HttpError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "invalid api key",
		})
	}))
	defer srv.Close()

	code := cmdClusterBans([]string{"--url", srv.URL, "--api-key", "wrong"})
	if code == 0 {
		t.Fatal("expected exit 1 for HTTP 401, got 0")
	}
}

func TestCmdClusterNodes_WithNodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled": true,
			"nodes": []any{
				map[string]any{
					"id":        "guardianwaf-0",
					"role":      "leader",
					"is_leader": true,
				},
				map[string]any{
					"id":        "guardianwaf-1",
					"addr":      "10.0.0.2:7947",
					"is_leader": false,
				},
				map[string]any{
					"id":        "guardianwaf-2",
					"addr":      "10.0.0.3:7947",
					"is_leader": false,
				},
			},
		})
	}))
	defer srv.Close()

	code := cmdClusterNodes([]string{"--url", srv.URL})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
}

func TestCmdClusterNodes_Disabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled": false,
			"nodes":   []any{},
		})
	}))
	defer srv.Close()

	code := cmdClusterNodes([]string{"--url", srv.URL})
	if code != 0 {
		t.Fatalf("expected exit 0 for disabled cluster, got %d", code)
	}
}

func TestCmdClusterNodes_ConnectionError(t *testing.T) {
	code := cmdClusterNodes([]string{"--url", "http://127.0.0.1:1"})
	if code == 0 {
		t.Fatal("expected exit 1 for connection error, got 0")
	}
}

func TestCmdClusterNodes_HttpError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	code := cmdClusterNodes([]string{"--url", srv.URL, "--api-key", "wrong"})
	if code == 0 {
		t.Fatal("expected exit 1 for HTTP 401, got 0")
	}
}

func TestCmdClusterHealth_Healthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":    "leader",
			"healthy":   true,
			"leader_id": "guardianwaf-0",
			"term":      float64(5),
		})
	}))
	defer srv.Close()

	code := cmdClusterHealth([]string{"--url", srv.URL})
	if code != 0 {
		t.Fatalf("expected exit 0 for healthy cluster, got %d", code)
	}
}

func TestCmdClusterHealth_Follower(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":    "follower",
			"healthy":   true,
			"leader_id": "guardianwaf-0",
			"term":      float64(5),
		})
	}))
	defer srv.Close()

	code := cmdClusterHealth([]string{"--url", srv.URL})
	if code != 0 {
		t.Fatalf("expected exit 0 for healthy follower, got %d", code)
	}
}

func TestCmdClusterHealth_SingleNode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "single-node",
			"healthy": true,
		})
	}))
	defer srv.Close()

	code := cmdClusterHealth([]string{"--url", srv.URL})
	if code != 0 {
		t.Fatalf("expected exit 0 for single-node, got %d", code)
	}
}

func TestCmdClusterHealth_Unhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "",
			"healthy": false,
		})
	}))
	defer srv.Close()

	code := cmdClusterHealth([]string{"--url", srv.URL})
	if code == 0 {
		t.Fatal("expected exit 1 for unhealthy cluster, got 0")
	}
}

func TestCmdClusterHealth_ConnectionError(t *testing.T) {
	code := cmdClusterHealth([]string{"--url", "http://127.0.0.1:1"})
	if code == 0 {
		t.Fatal("expected exit 1 for connection error, got 0")
	}
}
