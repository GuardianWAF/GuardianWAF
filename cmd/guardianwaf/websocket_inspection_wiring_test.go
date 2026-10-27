package main

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/websocket"
	"github.com/guardianwaf/guardianwaf/internal/runtime/layerregistry"
)

// Regression: `waf.websocket.enabled: true` must actually enable WebSocket
// inspection in serve mode.
//
// docs/configuration.md § WebSocket Inspection documents `enabled` as the
// switch ("Enable WebSocket inspection") and CLAUDE.md names
// `waf.websocket.enabled` as the wiring condition for
// websocket_runtime.go -> eng.SetWebSocketInterceptor. But
// Layer.Wrap returns `next` unchanged unless Config.AllowedBackendHosts is
// non-empty (the SSRF guard: dialing the client-supplied Host must be
// operator-constrained), and AllowedBackendHosts is set by NOTHING outside the
// layer package — no config key exists and setupWebSocketRuntime never passes
// it. So in a serve deployment the layer never hijacks an upgrade: no frame
// inspection, no origin validation, no binary/empty blocking, no per-IP cap,
// no idle timeout.
//
// The test drives the real serve wiring: config -> setupWebSocketRuntime ->
// engine middleware -> layer, against a loopback WebSocket backend. Assertion 1
// (documented switch): the upgrade must be intercepted, so the wrapped proxy
// handler must never be reached. Assertion 2 (documented purpose): a frame
// carrying an attack payload must not reach the backend.
const attackPayload = `' UNION SELECT password FROM users-- <script>alert(1)</script>`

func TestWebSocketInspectionEnabledByServeWiring(t *testing.T) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()

	var mu sync.Mutex
	var received [][]byte

	// WebSocket-speaking backend: answers the relayed handshake with 101, then
	// records every frame the WAF forwards to it.
	go func() {
		for {
			conn, aerr := backendLn.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, rerr := br.ReadString('\n')
					if rerr != nil || line == "\r\n" {
						break
					}
				}
				_, _ = c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
				// Frames arrive masked: the layer is the client toward the backend.
				fr := websocket.NewMaskedFrameReader(c, 1<<20)
				for {
					f, ferr := fr.ReadFrame()
					if ferr != nil {
						return
					}
					mu.Lock()
					received = append(received, append([]byte(nil), f.Payload...))
					mu.Unlock()
				}
			}(conn)
		}
	}()

	cfg := config.DefaultConfig()
	cfg.WAF.WebSocket.Enabled = true
	cfg.WAF.WebSocket.ScanPayloads = true
	// The operator's configured upstream — the only target the WAF may dial.
	cfg.Upstreams = []config.UpstreamConfig{{
		Name:    "app",
		Targets: []config.TargetConfig{{URL: "http://" + backendAddr}},
	}}

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(64), events.NewEventBus())
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer func() { _ = eng.Close() }()

	// Serve mode also wires the detection pipeline into the same engine; the WS
	// layer's CheckPayload delegates to eng.ScanPayload, so without it every
	// frame scores zero.
	detection, ok, err := layerregistry.BuildLayer("detection", cfg)
	if err != nil || !ok {
		t.Fatalf("detection layer: ok=%v err=%v", ok, err)
	}
	eng.AddLayer(detection)

	setupWebSocketRuntime(cfg, eng) // the real serve wiring

	var nextReached atomic.Bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextReached.Store(true)
		w.WriteHeader(http.StatusNotImplemented) // proxy fallback: uninspected
	})
	srv := httptest.NewServer(eng.Middleware(next))
	defer srv.Close()

	client, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	req := "GET /ws HTTP/1.1\r\nHost: " + backendAddr + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}

	br := bufio.NewReader(client)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	for {
		line, rerr := br.ReadString('\n')
		if rerr != nil || line == "\r\n" {
			break
		}
	}

	// --- Assertion 1: the documented switch must make the layer intercept. ---
	if nextReached.Load() {
		t.Fatalf("FAIL: waf.websocket.enabled=true did not enable inspection — the upgrade fell through "+
			"to the proxy handler (response %q). Layer.Wrap returns next unchanged while "+
			"Config.AllowedBackendHosts is empty, and nothing outside the layer package ever sets it "+
			"(no config key, no runtime wiring)", strings.TrimSpace(statusLine))
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("FAIL: upgrade not established through the layer: %q", strings.TrimSpace(statusLine))
	}

	// --- Assertion 2: an attack frame must be blocked, not forwarded. ---
	var frame bytes.Buffer
	if err := websocket.WriteFrameMasked(&frame, &websocket.Frame{
		FIN: true, Opcode: websocket.OpText, Payload: []byte(attackPayload),
	}); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	if _, err := client.Write(frame.Bytes()); err != nil {
		t.Fatalf("send frame: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, p := range received {
		if bytes.Contains(p, []byte(attackPayload)) {
			t.Fatalf("FAIL: an attack frame reached the backend uninspected: %q", p)
		}
	}
}
