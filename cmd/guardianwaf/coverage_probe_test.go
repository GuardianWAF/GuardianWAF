package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

func TestCmdServe_DashboardClosuresProbe(t *testing.T) {
	oldSignalNotify := signalNotify
	oldOsExit := osExit
	defer func() {
		signalNotify = oldSignalNotify
		osExit = oldOsExit
	}()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	// Capture os.Exit calls
	exitCalled := make(chan int, 1)
	osExit = func(code int) {
		exitCalled <- code
	}

	ln1, _ := net.Listen("tcp", "127.0.0.1:0")
	mainPort := ln1.Addr().(*net.TCPAddr).Port
	ln1.Close()
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	dashPort := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()

	dir := t.TempDir()
	geoCSV := filepath.Join(dir, "geo.csv")
	_ = os.WriteFile(geoCSV, []byte("1.0.0.0,1.0.0.255,AU\n"), 0o644)
	cfgPath := filepath.Join(dir, "serve.yaml")
	cfg := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
dashboard:
  enabled: true
  listen: "127.0.0.1:%d"
  api_key: testsecret
mcp:
  enabled: false
events:
  max_events: 100
waf:
  challenge:
    enabled: false
  custom_rules:
    enabled: true
    rules:
      - id: rule1
        name: test rule
        enabled: true
        priority: 1
        action: block
        score: 10
        conditions:
          - field: path
            op: equals
            value: /trigger-rule
  geoip:
    enabled: true
    db_path: %s
  bot_detection:
    enabled: false
  detection:
    enabled: false
upstreams:
  - name: default
    targets:
      - url: http://127.0.0.1:9999
routes:
  - path: /
    upstream: default
`, mainPort, dashPort, geoCSV)
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdServe([]string{"-config", cfgPath})
	}()

	// Wait for server to be ready with longer timeout for race detector
	serverReady := false
	for i := 0; i < 100; i++ {
		// Check if os.Exit was called
		select {
		case code := <-exitCalled:
			t.Fatalf("Server exited with code %d - config validation failed", code)
		default:
		}

		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", dashPort), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			serverReady = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !serverReady {
		t.Fatal("Server failed to start within timeout")
	}

	// Trigger all dashboard mutation endpoints and verify 200
	endpoints := []struct {
		method string
		path   string
		body   string
	}{
		{"POST", "/api/v1/rules", `{"id":"r2","name":"new","enabled":true,"priority":1,"action":"block","score":5,"conditions":[]}`},
		{"PUT", "/api/v1/routing", `{"upstreams":[{"name":"default","targets":[{"url":"http://127.0.0.1:9999"}]}],"routes":[{"path":"/","upstream":"default"}]}`},
		{"PUT", "/api/v1/config", `{"mode":"enforce"}`},
		{"GET", "/api/v1/geoip/lookup?ip=1.0.0.1", ""},
	}

	for _, ep := range endpoints {
		var bodyReader io.Reader
		if ep.body != "" {
			bodyReader = strings.NewReader(ep.body)
		}
		req, _ := http.NewRequestWithContext(context.Background(), ep.method, fmt.Sprintf("http://127.0.0.1:%d%s", dashPort, ep.path), bodyReader)
		req.Header.Set("X-API-Key", "testsecret")
		if ep.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s error: %v", ep.method, ep.path, err)
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			t.Fatalf("%s %s expected 200, got %d", ep.method, ep.path, resp.StatusCode)
		}
		resp.Body.Close()
	}

	shutdownCh <- syscall.SIGTERM
	<-done
}

func TestStartMCPServer_Probe(t *testing.T) {
	eng, _ := engine.NewEngine(config.DefaultConfig(), events.NewMemoryStore(100), events.NewEventBus())
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(100)

	done := make(chan struct{})
	go func() {
		defer close(done)
		startMCPServer(eng, cfg, store, nil, strings.NewReader(""), io.Discard)
	}()

	select {
	case <-done:
		// Expected: returns quickly because stdin is EOF
	case <-time.After(2 * time.Second):
		t.Fatal("startMCPServer did not return quickly")
	}
}

func TestLoadGeoIP_NoPathNoDownload(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.GeoIP.DBPath = ""
	cfg.WAF.GeoIP.AutoDownload = false

	eng, _ := engine.NewEngine(cfg, events.NewMemoryStore(100), events.NewEventBus())
	db, cleanup := loadGeoIP(cfg, eng)
	if db != nil {
		t.Error("expected nil db when no path and no download")
	}
	cleanup()
}

func TestLoadGeoIP_InvalidPath(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.GeoIP.DBPath = "this-file-does-not-exist-12345.csv"
	cfg.WAF.GeoIP.AutoDownload = false

	eng, _ := engine.NewEngine(cfg, events.NewMemoryStore(100), events.NewEventBus())
	db, cleanup := loadGeoIP(cfg, eng)
	if db != nil {
		t.Error("expected nil db when file missing and auto-download disabled")
	}
	cleanup()
}
