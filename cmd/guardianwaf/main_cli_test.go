package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
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

type exitError struct {
	code int
}

func captureExit(t *testing.T, fn func()) (code int) {
	t.Helper()
	oldExit := osExit
	defer func() { osExit = oldExit }()

	exited := false
	osExit = func(c int) {
		code = c
		exited = true
		panic(exitError{code: c})
	}

	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(exitError); !ok {
				panic(r)
			}
		} else if !exited {
			t.Fatal("expected osExit to be called")
		}
	}()

	fn()
	return
}

func captureOptionalExit(t *testing.T, fn func()) (code int, called bool) {
	t.Helper()
	oldExit := osExit
	defer func() { osExit = oldExit }()

	osExit = func(c int) {
		code = c
		called = true
		panic(exitError{code: c})
	}

	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(exitError); !ok {
				panic(r)
			}
		}
	}()

	fn()
	return
}

func TestRunMain_NoArgs(t *testing.T) {
	code := runMain([]string{"guardianwaf"})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestRunMain_Serve(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gwaf.yaml")
	os.WriteFile(cfgPath, []byte("mode: enforce\nlisten: 127.0.0.1:0\ndashboard:\n  enabled: false\nmcp:\n  enabled: false\n"), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		runMain([]string{"guardianwaf", "serve", "-config", cfgPath})
	}()

	time.Sleep(200 * time.Millisecond)
	shutdownCh <- syscall.SIGTERM

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmdServe did not shut down in time")
	}
}

func TestRunMain_Sidecar(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		runMain([]string{"guardianwaf", "sidecar", "--listen", "127.0.0.1:0", "--upstream", "http://127.0.0.1:9999"})
	}()

	time.Sleep(200 * time.Millisecond)
	shutdownCh <- syscall.SIGTERM

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmdSidecar did not shut down in time")
	}
}

func TestRunMain_Check(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	cfg := `mode: enforce
waf:
  detection:
    enabled: false
  bot_detection:
    enabled: false
`
	os.WriteFile(path, []byte(cfg), 0o644)
	code := runMain([]string{"guardianwaf", "check", "--url", "/health", "--config", path})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestRunMain_CheckAttack(t *testing.T) {
	code := captureExit(t, func() {
		runMain([]string{"guardianwaf", "check", "--url", "/test?q=' OR 1=1 --"})
	})
	if code != 2 {
		t.Errorf("expected exit code 2 for block, got %d", code)
	}
}

func TestRunMain_Validate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "valid.yaml")
	os.WriteFile(path, []byte("mode: enforce\n"), 0o644)

	code := runMain([]string{"guardianwaf", "validate", "--config", path})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestMainFunc(t *testing.T) {
	oldArgs := os.Args
	oldExit := osExit
	defer func() {
		os.Args = oldArgs
		osExit = oldExit
	}()

	osExit = func(c int) {
		panic(exitError{code: c})
	}
	os.Args = []string{"guardianwaf", "version"}

	defer func() {
		if r := recover(); r != nil {
			if ee, ok := r.(exitError); !ok || ee.code != 0 {
				t.Errorf("expected exit code 0, got %v", r)
			}
		} else {
			t.Fatal("expected osExit to be called")
		}
	}()

	main()
}

func TestRunMain_Version(t *testing.T) {
	code := runMain([]string{"guardianwaf", "version"})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestRunMain_Help(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		code := runMain([]string{"guardianwaf", arg})
		if code != 0 {
			t.Errorf("expected exit code 0 for %s, got %d", arg, code)
		}
	}
}

func TestRunMain_UnknownCommand(t *testing.T) {
	code := runMain([]string{"guardianwaf", "unknown"})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCmdServe_InvalidListenAddress(t *testing.T) {
	code := captureExit(t, func() {
		cmdServe([]string{"--listen", "not-an-address::xyz"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCmdSidecar_NoUpstream(t *testing.T) {
	code := captureExit(t, func() {
		cmdSidecar([]string{"--listen", "127.0.0.1:0"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCmdSidecar_InvalidListenAddress(t *testing.T) {
	code := captureExit(t, func() {
		cmdSidecar([]string{"--upstream", "http://127.0.0.1:1", "--listen", "not-an-address::xyz"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCmdCheckRunMain_MissingURL(t *testing.T) {
	code := captureExit(t, func() {
		cmdCheck([]string{})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCmdValidateRunMain_InvalidFile(t *testing.T) {
	code := captureExit(t, func() {
		cmdValidate([]string{"--config", "/nonexistent/path/file.yaml"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestStartMCPServer(t *testing.T) {
	r, w := io.Pipe()
	go func() {
		time.Sleep(50 * time.Millisecond)
		w.Close()
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		cfg := config.DefaultConfig()
		store := events.NewMemoryStore(100)
		bus := events.NewEventBus()
		eng, _ := engine.NewEngine(cfg, store, bus)
		defer eng.Close()
		startMCPServer(eng, cfg, store, nil, r, io.Discard)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("startMCPServer did not return")
	}
}

func TestCmdServe_ValidationError(t *testing.T) {
	code := captureExit(t, func() {
		cmdServe([]string{"--mode", "invalidmode"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCmdSidecar_ValidationError(t *testing.T) {
	code := captureExit(t, func() {
		cmdSidecar([]string{"--upstream", "http://127.0.0.1:1", "--mode", "badmode"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCmdServe_EngineError(t *testing.T) {
	code := captureExit(t, func() {
		cmdServe([]string{"--listen", "127.0.0.1:0", "--config", "/nonexistent/xyz.yaml"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCmdSidecar_EngineError(t *testing.T) {
	code := captureExit(t, func() {
		cmdSidecar([]string{"--upstream", "http://127.0.0.1:1", "--config", "/nonexistent/xyz.yaml"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCmdCheck_Verbose(t *testing.T) {
	code := captureExit(t, func() {
		cmdCheck([]string{"--url", "/test?q=<script>alert(1)</script>", "--verbose", "-v"})
	})
	if code != 2 {
		t.Errorf("expected exit code 2 for block, got %d", code)
	}
}

func TestCmdCheck_WithHeaders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	cfg := `mode: enforce\nwaf:\n  detection:\n    enabled: false\n  bot_detection:\n    enabled: false\n`
	os.WriteFile(path, []byte(cfg), 0o644)
	code, called := captureOptionalExit(t, func() {
		cmdCheck([]string{"--config", path, "--url", "/test", "-H", "User-Agent: test", "-H", "X-Test: value"})
	})
	if called && code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestCmdCheck_WithBody(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	cfg := `mode: enforce
waf:
  detection:
    enabled: false
  bot_detection:
    enabled: false
  ato_protection:
    enabled: false
  api_security:
    enabled: false
`
	os.WriteFile(path, []byte(cfg), 0o644)
	code, called := captureOptionalExit(t, func() {
		cmdCheck([]string{"--config", path, "--url", "/test", "--method", "POST", "--body", "username=admin&password=123"})
	})
	if called && code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestCmdValidateRunMain_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "valid.yaml")
	os.WriteFile(path, []byte("mode: enforce\n"), 0o644)

	code, called := captureOptionalExit(t, func() {
		cmdValidate([]string{"--config", path})
	})
	if called && code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestCmdServe_SignalShutdown(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gwaf.yaml")
	os.WriteFile(cfgPath, []byte("mode: enforce\nlisten: 127.0.0.1:0\ndashboard:\n  enabled: false\nmcp:\n  enabled: false\n"), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdServe([]string{"-config", cfgPath})
	}()

	time.Sleep(300 * time.Millisecond)
	shutdownCh <- syscall.SIGTERM

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmdServe did not shut down")
	}
}

func TestCmdSidecar_FullFeatures(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	// Use fixed port for the actual test
	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	dir := t.TempDir()
	cfg := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
logging:
  log_blocked: true
  log_allowed: true
  format: json
waf:
  challenge:
    enabled: true
    difficulty: 4
    cookie_name: gwaf_challenge
upstreams:
  - name: default
    targets:
      - url: http://127.0.0.1:9999
routes:
  - path: /
    upstream: default
`, port)
	cfgPath := filepath.Join(dir, "sidecar.yaml")
	os.WriteFile(cfgPath, []byte(cfg), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdSidecar([]string{"-config", cfgPath})
	}()

	// Wait for server
	started := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !started {
		shutdownCh <- syscall.SIGTERM
		t.Fatal("sidecar did not start")
	}

	// Hit healthz
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
	if err == nil {
		resp.Body.Close()
	}

	// Hit metrics
	resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", port))
	if err == nil {
		resp.Body.Close()
	}

	// Hit main handler (should pass through WAF)
	resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/test", port))
	if err == nil {
		resp.Body.Close()
	}

	shutdownCh <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sidecar did not shut down")
	}
}

func TestCmdSidecar_NoUpstreamConfigured(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sidecar.yaml")
	cfg := `mode: enforce
listen: 127.0.0.1:0
upstreams: []
routes: []
`
	os.WriteFile(cfgPath, []byte(cfg), 0o644)

	// Need an upstream to pass validation, so add one via config
	cfg2 := `mode: enforce
listen: 127.0.0.1:0
upstreams:
  - name: default
    targets:
      - url: http://127.0.0.1:9999
routes:
  - path: /
    upstream: default
`
	cfgPath2 := filepath.Join(dir, "sidecar2.yaml")
	os.WriteFile(cfgPath2, []byte(cfg2), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdSidecar([]string{"-config", cfgPath2})
	}()

	time.Sleep(200 * time.Millisecond)
	shutdownCh <- syscall.SIGTERM

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sidecar did not shut down")
	}
}

func TestCmdSidecar_SignalShutdown(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdSidecar([]string{"--listen", "127.0.0.1:0", "--upstream", "http://127.0.0.1:9999"})
	}()

	time.Sleep(300 * time.Millisecond)
	shutdownCh <- syscall.SIGTERM

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmdSidecar did not shut down")
	}
}

func TestCmdServe_FullFeatures(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	// Find free ports
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mainPort := ln1.Addr().(*net.TCPAddr).Port
	ln1.Close()

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dashPort := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()

	dir := t.TempDir()

	// GeoIP CSV
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
  enabled: true
  transport: sse
logging:
  log_blocked: true
  log_allowed: true
  format: json
  level: debug
events:
  max_events: 100
waf:
  challenge:
    enabled: true
    difficulty: 4
    cookie_name: gwaf_challenge
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
  ai_analysis:
    enabled: true
    store_path: %s
    batch_size: 5
    batch_interval: 1s
    min_score: 10
  bot_detection:
    enabled: false
  detection:
    enabled: true
    threshold:
      block: 10
      log: 5
alerting:
  enabled: true
  webhooks:
    - name: test
      url: http://127.0.0.1:1/webhook
      type: generic
      events: [block]
docker:
  enabled: true
  socket_path: /nonexistent/docker.sock
upstreams:
  - name: default
    targets:
      - url: http://127.0.0.1:9999
routes:
  - path: /
    upstream: default
virtual_hosts:
  - domains: [test.local]
    routes:
      - path: /
        upstream: default
`, mainPort, dashPort, geoCSV, filepath.Join(dir, "ai_store.json"))
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdServe([]string{"-config", cfgPath})
	}()

	// Wait for main server
	started := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", mainPort), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !started {
		shutdownCh <- syscall.SIGTERM
		t.Fatal("cmdServe did not start")
	}

	// Wait for dashboard
	dashStarted := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", dashPort), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			dashStarted = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !dashStarted {
		shutdownCh <- syscall.SIGTERM
		t.Fatal("dashboard did not start")
	}

	// Hit healthz
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", mainPort))
	if err == nil {
		resp.Body.Close()
	}

	// Hit metrics
	resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", mainPort))
	if err == nil {
		resp.Body.Close()
	}

	// Hit main handler (triggers access log)
	resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/test", mainPort))
	if err == nil {
		resp.Body.Close()
	}

	// Hit dashboard health
	req, _ := http.NewRequestWithContext(context.Background(), "GET", fmt.Sprintf("http://127.0.0.1:%d/api/v1/health", dashPort), nil)
	req.Header.Set("X-API-Key", "testsecret")
	resp, err = http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}

	// Hit MCP SSE endpoint (requires API key)
	req2, _ := http.NewRequestWithContext(context.Background(), "GET", fmt.Sprintf("http://127.0.0.1:%d/mcp/sse", dashPort), nil)
	req2.Header.Set("Authorization", "Bearer testsecret")
	resp2, err := http.DefaultClient.Do(req2)
	if err == nil {
		resp2.Body.Close()
	}

	// Dashboard API calls to trigger cmdServe closures
	// Add a rule
	ruleBody := `{"id":"r2","name":"new","enabled":true,"priority":1,"action":"block","score":5,"conditions":[]}`
	req3, _ := http.NewRequestWithContext(context.Background(), "POST", fmt.Sprintf("http://127.0.0.1:%d/api/v1/rules", dashPort), strings.NewReader(ruleBody))
	req3.Header.Set("Authorization", "Bearer testsecret")
	req3.Header.Set("Content-Type", "application/json")
	resp3, _ := http.DefaultClient.Do(req3)
	if resp3 != nil {
		resp3.Body.Close()
	}

	// Update routing to trigger rebuild
	routingBody := `{"upstreams":[{"name":"default","targets":[{"url":"http://127.0.0.1:9999"}]}],"routes":[{"path":"/","upstream":"default"}]}`
	req4, _ := http.NewRequestWithContext(context.Background(), "PUT", fmt.Sprintf("http://127.0.0.1:%d/api/v1/routing", dashPort), strings.NewReader(routingBody))
	req4.Header.Set("Authorization", "Bearer testsecret")
	req4.Header.Set("Content-Type", "application/json")
	resp4, _ := http.DefaultClient.Do(req4)
	if resp4 != nil {
		resp4.Body.Close()
	}

	// Save config
	req5, _ := http.NewRequestWithContext(context.Background(), "PUT", fmt.Sprintf("http://127.0.0.1:%d/api/v1/config", dashPort), strings.NewReader(`{"mode":"enforce"}`))
	req5.Header.Set("Authorization", "Bearer testsecret")
	req5.Header.Set("Content-Type", "application/json")
	resp5, _ := http.DefaultClient.Do(req5)
	if resp5 != nil {
		resp5.Body.Close()
	}

	// GeoIP lookup
	req6, _ := http.NewRequestWithContext(context.Background(), "GET", fmt.Sprintf("http://127.0.0.1:%d/api/v1/geoip/lookup?ip=1.0.0.1", dashPort), nil)
	req6.Header.Set("Authorization", "Bearer testsecret")
	resp6, _ := http.DefaultClient.Do(req6)
	if resp6 != nil {
		resp6.Body.Close()
	}

	// Trigger a block event for alerting webhook
	respBlock, _ := http.Get(fmt.Sprintf("http://127.0.0.1:%d/?q=' OR 1=1 --", mainPort))
	if respBlock != nil {
		respBlock.Body.Close()
	}

	shutdownCh <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmdServe did not shut down")
	}
}

func generateTempCerts(t *testing.T, dir string) (certPath, keyPath string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Test"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certOut, _ := os.Create(certPath)
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()
	keyOut, _ := os.Create(keyPath)
	_ = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	return
}

func TestCmdServe_TLSRedirect(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpPort := ln1.Addr().(*net.TCPAddr).Port
	ln1.Close()

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsPort := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()

	dir := t.TempDir()
	certPath, keyPath := generateTempCerts(t, dir)

	cfgPath := filepath.Join(dir, "tls.yaml")
	cfg := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
tls:
  enabled: true
  listen: "127.0.0.1:%d"
  cert_file: %s
  key_file: %s
  http_redirect: true
dashboard:
  enabled: false
mcp:
  enabled: false
waf:
  detection:
    enabled: false
  bot_detection:
    enabled: false
`, httpPort, tlsPort, certPath, keyPath)
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdServe([]string{"-config", cfgPath})
	}()

	// Wait for HTTP server
	started := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !started {
		shutdownCh <- syscall.SIGTERM
		t.Fatal("HTTP server did not start")
	}

	// Request to HTTP should redirect
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 2 * time.Second,
	}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", httpPort))
	if err != nil {
		shutdownCh <- syscall.SIGTERM
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("expected 301, got %d", resp.StatusCode)
	}

	// TLS request should work (skip verify)
	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 2 * time.Second,
	}
	resp2, err := tlsClient.Get(fmt.Sprintf("https://127.0.0.1:%d/healthz", tlsPort))
	if err == nil {
		resp2.Body.Close()
	}

	shutdownCh <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmdServe did not shut down")
	}
}

func TestCmdServe_TextAccessLog(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "serve.yaml")
	cfg := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
dashboard:
  enabled: false
mcp:
  enabled: false
logging:
  log_blocked: true
  log_allowed: true
  format: text
waf:
  detection:
    enabled: true
    threshold:
      block: 10
      log: 5
`, port)
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdServe([]string{"-config", cfgPath})
	}()

	started := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !started {
		shutdownCh <- syscall.SIGTERM
		t.Fatal("cmdServe did not start")
	}

	resp1, _ := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if resp1 != nil {
		resp1.Body.Close()
	}
	resp2, _ := http.Get(fmt.Sprintf("http://127.0.0.1:%d/?q=<script>", port))
	if resp2 != nil {
		resp2.Body.Close()
	}

	shutdownCh <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmdServe did not shut down")
	}
}

func TestCmdServe_NoUpstream(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "serve.yaml")
	cfg := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
dashboard:
  enabled: false
mcp:
  enabled: false
waf:
  detection:
    enabled: false
  bot_detection:
    enabled: false
`, port)
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdServe([]string{"-config", cfgPath})
	}()

	started := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !started {
		shutdownCh <- syscall.SIGTERM
		t.Fatal("cmdServe did not start")
	}

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err == nil {
		resp.Body.Close()
	}

	shutdownCh <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmdServe did not shut down")
	}
}

func TestCmdServe_DashboardOverride(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "serve.yaml")
	cfg := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
dashboard:
  enabled: true
  listen: "127.0.0.1:0"
mcp:
  enabled: false
waf:
  detection:
    enabled: false
  bot_detection:
    enabled: false
`, port)
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdServe([]string{"-config", cfgPath, "--dashboard", "127.0.0.1:0", "--log-level", "debug"})
	}()

	started := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !started {
		shutdownCh <- syscall.SIGTERM
		t.Fatal("cmdServe did not start")
	}

	shutdownCh <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmdServe did not shut down")
	}
}

func TestCmdServe_ChallengeSecret(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "serve.yaml")
	cfg := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
dashboard:
  enabled: false
mcp:
  enabled: false
waf:
  challenge:
    enabled: true
    secret_key: 68656c6c6f776f726c64
  detection:
    enabled: false
  bot_detection:
    enabled: false
`, port)
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdServe([]string{"-config", cfgPath})
	}()

	started := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !started {
		shutdownCh <- syscall.SIGTERM
		t.Fatal("cmdServe did not start")
	}

	shutdownCh <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmdServe did not shut down")
	}
}

func TestCmdSidecar_TextAccessLog(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sidecar.yaml")
	cfg := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
upstreams:
  - name: default
    targets:
      - url: http://127.0.0.1:9999
routes:
  - path: /
    upstream: default
logging:
  log_blocked: true
  log_allowed: true
  format: text
waf:
  detection:
    enabled: true
    threshold:
      block: 10
      log: 5
`, port)
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdSidecar([]string{"-config", cfgPath})
	}()

	started := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !started {
		shutdownCh <- syscall.SIGTERM
		t.Fatal("sidecar did not start")
	}

	resp3, _ := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if resp3 != nil {
		resp3.Body.Close()
	}
	resp4, _ := http.Get(fmt.Sprintf("http://127.0.0.1:%d/?q=1' OR 1=1", port))
	if resp4 != nil {
		resp4.Body.Close()
	}

	shutdownCh <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("sidecar did not shut down")
	}
}

func TestCmdSidecar_ChallengeSecret(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sidecar.yaml")
	cfg := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
upstreams:
  - name: default
    targets:
      - url: http://127.0.0.1:9999
routes:
  - path: /
    upstream: default
waf:
  challenge:
    enabled: true
    secret_key: 68656c6c6f776f726c64
  detection:
    enabled: false
  bot_detection:
    enabled: false
`, port)
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdSidecar([]string{"-config", cfgPath})
	}()

	started := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !started {
		shutdownCh <- syscall.SIGTERM
		t.Fatal("sidecar did not start")
	}

	shutdownCh <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("sidecar did not shut down")
	}
}

func TestCmdSidecar_NoUpstreamHandler(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sidecar.yaml")
	cfg := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
upstreams: []
routes: []
waf:
  detection:
    enabled: false
  bot_detection:
    enabled: false
`, port)
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o644)

	// Need upstream to pass validation, so we also provide --upstream flag
	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdSidecar([]string{"-config", cfgPath, "--upstream", "http://127.0.0.1:9999"})
	}()

	started := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !started {
		shutdownCh <- syscall.SIGTERM
		t.Fatal("sidecar did not start")
	}

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err == nil {
		resp.Body.Close()
	}

	shutdownCh <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("sidecar did not shut down")
	}
}

func TestCmdServe_MCPStdio(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "serve.yaml")
	cfg := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
dashboard:
  enabled: false
mcp:
  enabled: true
  transport: stdio
waf:
  detection:
    enabled: false
  bot_detection:
    enabled: false
`, port)
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdServe([]string{"-config", cfgPath})
	}()

	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	shutdownCh <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmdServe did not shut down")
	}
}

func TestCmdServe_AccessLogFilters(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "serve.yaml")
	cfg := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
dashboard:
  enabled: false
mcp:
  enabled: false
logging:
  log_blocked: false
  log_allowed: true
  format: json
waf:
  detection:
    enabled: true
    threshold:
      block: 10
      log: 5
`, port)
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdServe([]string{"-config", cfgPath})
	}()

	started := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !started {
		shutdownCh <- syscall.SIGTERM
		t.Fatal("cmdServe did not start")
	}

	// Trigger a block so the log_blocked=false return branch executes
	resp5, _ := http.Get(fmt.Sprintf("http://127.0.0.1:%d/?q=<script>alert(1)</script>", port))
	if resp5 != nil {
		resp5.Body.Close()
	}

	shutdownCh <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmdServe did not shut down")
	}
}

func TestCmdServe_AccessLogFilters_AllowedFalse(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "serve.yaml")
	cfg := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
dashboard:
  enabled: false
mcp:
  enabled: false
logging:
  log_blocked: true
  log_allowed: false
  format: json
waf:
  detection:
    enabled: false
  bot_detection:
    enabled: false
`, port)
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdServe([]string{"-config", cfgPath})
	}()

	started := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !started {
		shutdownCh <- syscall.SIGTERM
		t.Fatal("cmdServe did not start")
	}

	// Normal request should hit log_allowed=false return branch
	resp6, _ := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if resp6 != nil {
		resp6.Body.Close()
	}

	shutdownCh <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmdServe did not shut down")
	}
}

func TestCmdSidecar_LogLevelOverride(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdSidecar([]string{"--listen", fmt.Sprintf("127.0.0.1:%d", port), "--upstream", "http://127.0.0.1:9999", "--log-level", "debug"})
	}()

	time.Sleep(200 * time.Millisecond)
	shutdownCh <- syscall.SIGTERM

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmdSidecar did not shut down")
	}
}

func TestCmdServe_ACMERedirectBypass(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpPort := ln1.Addr().(*net.TCPAddr).Port
	ln1.Close()

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsPort := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()

	dir := t.TempDir()
	certPath, keyPath := generateTempCerts(t, dir)

	cfgPath := filepath.Join(dir, "tls.yaml")
	cfg := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
tls:
  enabled: true
  listen: "127.0.0.1:%d"
  cert_file: %s
  key_file: %s
  http_redirect: true
  acme:
    enabled: true
    email: test@example.com
    cache_dir: %s
    domains: [test.local]
dashboard:
  enabled: false
mcp:
  enabled: false
waf:
  detection:
    enabled: false
  bot_detection:
    enabled: false
`, httpPort, tlsPort, certPath, keyPath, filepath.Join(dir, "acme_cache"))
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdServe([]string{"-config", cfgPath})
	}()

	started := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !started {
		shutdownCh <- syscall.SIGTERM
		t.Fatal("HTTP server did not start")
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 2 * time.Second,
	}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/.well-known/acme-challenge/test-token", httpPort))
	if err != nil {
		shutdownCh <- syscall.SIGTERM
		t.Fatalf("ACME request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusMovedPermanently {
		shutdownCh <- syscall.SIGTERM
		t.Fatal("ACME challenge was redirected to HTTPS")
	}

	shutdownCh <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmdServe did not shut down")
	}
}

func TestLoadGeoIP_Errors(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.GeoIP.Enabled = true
	cfg.WAF.GeoIP.DBPath = "/nonexistent/path/to/geoip.csv"
	cfg.WAF.GeoIP.AutoDownload = true
	cfg.WAF.GeoIP.DownloadURL = "http://127.0.0.1:1/nonexistent.gz"

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, _ := engine.NewEngine(cfg, store, bus)
	defer eng.Close()

	db, stop := loadGeoIP(cfg, eng)
	if db != nil {
		t.Error("expected nil DB for failed load+download")
	}
	stop()
}

func TestCmdServe_DashboardClosuresErrors(t *testing.T) {
	oldSignalNotify := signalNotify
	defer func() { signalNotify = oldSignalNotify }()

	shutdownCh := make(chan os.Signal, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range shutdownCh {
				c <- s
			}
		}()
	}

	ln1, _ := net.Listen("tcp", "127.0.0.1:0")
	mainPort := ln1.Addr().(*net.TCPAddr).Port
	ln1.Close()
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	dashPort := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "serve.yaml")
	cfg := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
dashboard:
  enabled: true
  listen: "127.0.0.1:%d"
  api_key: testsecret
mcp:
  enabled: false
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
    enabled: false
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
`, mainPort, dashPort)
	_ = os.WriteFile(cfgPath, []byte(cfg), 0o644)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdServe([]string{"-config", cfgPath})
	}()

	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", dashPort), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	client := &http.Client{Timeout: 2 * time.Second}

	// Missing rule id should trigger error branch
	req1, _ := http.NewRequestWithContext(context.Background(), "POST", fmt.Sprintf("http://127.0.0.1:%d/api/v1/rules", dashPort), strings.NewReader(`{"name":"bad","enabled":true,"priority":1,"action":"block","score":5,"conditions":[]}`))
	req1.Header.Set("X-API-Key", "testsecret")
	req1.Header.Set("Content-Type", "application/json")
	resp1, _ := client.Do(req1)
	if resp1 != nil {
		resp1.Body.Close()
	}

	// Update nonexistent rule
	req2, _ := http.NewRequestWithContext(context.Background(), "PUT", fmt.Sprintf("http://127.0.0.1:%d/api/v1/rules/nosuchrule", dashPort), strings.NewReader(`{"id":"nosuchrule","name":"bad","enabled":true,"priority":1,"action":"block","score":5,"conditions":[]}`))
	req2.Header.Set("X-API-Key", "testsecret")
	req2.Header.Set("Content-Type", "application/json")
	resp2, _ := client.Do(req2)
	if resp2 != nil {
		resp2.Body.Close()
	}

	// Delete nonexistent rule
	req3, _ := http.NewRequestWithContext(context.Background(), "DELETE", fmt.Sprintf("http://127.0.0.1:%d/api/v1/rules/nosuchrule", dashPort), nil)
	req3.Header.Set("X-API-Key", "testsecret")
	resp3, _ := client.Do(req3)
	if resp3 != nil {
		resp3.Body.Close()
	}

	// Toggle nonexistent rule
	req4, _ := http.NewRequestWithContext(context.Background(), "POST", fmt.Sprintf("http://127.0.0.1:%d/api/v1/rules/nosuchrule/toggle", dashPort), strings.NewReader(`{"enabled":false}`))
	req4.Header.Set("X-API-Key", "testsecret")
	req4.Header.Set("Content-Type", "application/json")
	resp4, _ := client.Do(req4)
	if resp4 != nil {
		resp4.Body.Close()
	}

	shutdownCh <- syscall.SIGTERM
	<-done
}
