package main

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/websocket"
	"github.com/guardianwaf/guardianwaf/internal/runtime/layerregistry"
)

// Regression: the documented control-frame exemption of
// `waf.websocket.block_empty_messages` ("Block empty payloads", ADR/config docs).
//
// The empty-message policy is enforced in inspectAndForward AFTER the
// always-forward-control-frames branch, so an empty ping/pong/close — which is
// legitimate RFC 6455 protocol traffic (keepalive, teardown) — must still reach
// the peer, and the connection must survive: the policy must not tear down a
// connection because the peer sent an empty control frame.
//
// The test drives the real serve wiring (config -> setupWebSocketRuntime ->
// engine middleware -> layer) against a loopback WebSocket backend that records
// every frame it receives, then:
//  1. sends an empty PING   -> must be forwarded (exemption);
//  2. sends a benign TEXT   -> must still be forwarded (connection survived).
const benignAfterPingPayload = "still-alive"

func TestBlockEmptyMessagesExemptsControlFrames(t *testing.T) {
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
	cfg.WAF.WebSocket.BlockEmptyMessages = true // the policy under test
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

	srv := httptest.NewServer(eng.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	})))
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
	if !bytes.Contains([]byte(statusLine), []byte("101")) {
		t.Fatalf("harness: upgrade not established through the layer (%q)", statusLine)
	}

	send := func(opcode websocket.Opcode, payload []byte) {
		var frame bytes.Buffer
		if werr := websocket.WriteFrameMasked(&frame, &websocket.Frame{
			FIN: true, Opcode: opcode, Payload: payload,
		}); werr != nil {
			t.Fatalf("write frame: %v", werr)
		}
		if _, werr := client.Write(frame.Bytes()); werr != nil {
			t.Fatalf("send frame: %v", werr)
		}
	}
	waitFor := func(want int) {
		deadline := time.Now().Add(2 * time.Second)
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

	// 1. An empty PING must be forwarded despite block_empty_messages.
	send(websocket.OpPing, nil)
	waitFor(1)

	mu.Lock()
	if len(received) == 0 || received[0].opcode != websocket.OpPing || len(received[0].payload) != 0 {
		mu.Unlock()
		t.Fatalf("FAIL: an empty PING was not forwarded while block_empty_messages=true "+
			"(received %v) — the documented policy covers data frames only; an empty ping/pong/close "+
			"is legitimate RFC 6455 protocol traffic", received)
	}
	mu.Unlock()

	// 2. The connection must survive: a benign text frame still gets through.
	send(websocket.OpText, []byte(benignAfterPingPayload))
	waitFor(2)

	mu.Lock()
	defer mu.Unlock()
	for _, f := range received {
		if f.opcode == websocket.OpText && string(f.payload) == benignAfterPingPayload {
			return // both the exemption and connection survival are pinned
		}
	}
	t.Fatalf("FAIL: the connection did not survive an empty control frame — a benign text frame "+
		"sent afterwards never reached the backend (received %v)", received)
}
