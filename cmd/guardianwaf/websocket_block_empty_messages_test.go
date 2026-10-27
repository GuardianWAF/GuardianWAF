package main

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
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

// Regression: `waf.websocket.block_empty_messages: true` is documented as
// "Block empty payloads" (docs/configuration.md § WebSocket Inspection, table
// row with default false) and is parsed into config (config.go:485,
// defaults.go:301) — but it is read by NOTHING outside internal/config: the
// layer has no such field, setupWebSocketRuntime never maps it, and no frame
// path enforces it. So the operator's explicit policy is silently ignored and
// empty frames are forwarded like any other.
//
// The test drives the real serve wiring (config -> setupWebSocketRuntime ->
// engine middleware -> layer) against a loopback WebSocket backend that
// records every frame it receives. Assertion: with the setting enabled, an
// empty text frame must not reach the backend. Control: a benign non-empty
// text frame must still reach it (so a broken harness cannot masquerade as the
// defect).
const benignFramePayload = "hello-from-client"

func TestBlockEmptyMessagesRefusesEmptyFrameThroughServeWiring(t *testing.T) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()

	type gotFrame struct {
		opcode  websocket.Opcode
		payload []byte
	}
	var mu sync.Mutex
	var received []gotFrame

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
				fr := websocket.NewMaskedFrameReader(c, 1<<20)
				for {
					f, ferr := fr.ReadFrame()
					if ferr != nil {
						return
					}
					mu.Lock()
					received = append(received, gotFrame{opcode: f.Opcode, payload: append([]byte(nil), f.Payload...)})
					mu.Unlock()
				}
			}(conn)
		}
	}()

	cfg := config.DefaultConfig()
	cfg.WAF.WebSocket.Enabled = true
	cfg.WAF.WebSocket.ScanPayloads = true
	cfg.WAF.WebSocket.BlockEmptyMessages = true // the documented policy under test
	cfg.Upstreams = []config.UpstreamConfig{{
		Name:    "app",
		Targets: []config.TargetConfig{{URL: "http://" + backendAddr}},
	}}

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(64), events.NewEventBus())
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer func() { _ = eng.Close() }()

	detection, ok, err := layerregistry.BuildLayer("detection", cfg)
	if err != nil || !ok {
		t.Fatalf("detection layer: ok=%v err=%v", ok, err)
	}
	eng.AddLayer(detection)

	setupWebSocketRuntime(cfg, eng)

	var nextReached atomic.Bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextReached.Store(true)
		w.WriteHeader(http.StatusNotImplemented)
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
	if nextReached.Load() || !bytes.Contains([]byte(statusLine), []byte("101")) {
		t.Fatalf("harness: inspection is not active (status %q, nextReached=%v)", statusLine, nextReached.Load())
	}

	// Control: a benign text frame must reach the backend.
	sendFrame := func(payload []byte) {
		var frame bytes.Buffer
		if werr := websocket.WriteFrameMasked(&frame, &websocket.Frame{
			FIN: true, Opcode: websocket.OpText, Payload: payload,
		}); werr != nil {
			t.Fatalf("write frame: %v", werr)
		}
		if _, werr := client.Write(frame.Bytes()); werr != nil {
			t.Fatalf("send frame: %v", werr)
		}
	}
	sendFrame([]byte(benignFramePayload))

	waitFor := func(want int, timeout time.Duration) {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			mu.Lock()
			n := len(received)
			mu.Unlock()
			if n >= want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor(1, 2*time.Second)

	mu.Lock()
	controlOK := len(received) == 1 && received[0].opcode == websocket.OpText &&
		string(received[0].payload) == benignFramePayload
	mu.Unlock()
	if !controlOK {
		t.Fatalf("CONTROL FAILED: the benign frame did not reach the backend (%v) — harness problem, not the defect", received)
	}
	t.Log("CONTROL PASS: a benign text frame is forwarded")

	// The defect: an empty text frame is forwarded despite block_empty_messages.
	sendFrame(nil)
	waitFor(2, 2*time.Second)
	time.Sleep(200 * time.Millisecond) // allow any forwarded frame to land

	mu.Lock()
	defer mu.Unlock()
	for _, f := range received {
		if f.opcode == websocket.OpText && len(f.payload) == 0 {
			t.Fatalf("FAIL: waf.websocket.block_empty_messages=true (\"Block empty payloads\", " +
				"docs/configuration.md § WebSocket Inspection) was ignored — an empty text frame reached " +
				"the backend. The setting is parsed into config but read by nothing outside internal/config: " +
				"websocket.Config has no such field, setupWebSocketRuntime never maps it, and the frame path " +
				"never enforces it")
		}
	}
	t.Logf("PASS: no empty text frame reached the backend (%d frame(s) recorded)", len(received))
}
