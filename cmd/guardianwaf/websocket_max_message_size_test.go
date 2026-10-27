package main

// Regression: `waf.websocket.max_message_size` was a documented-but-inert
// setting. It parses into config (internal/config/config.go:479) and has a
// default (internal/config/defaults.go:295), and docs/adr/0035-websocket-proxy.md
// specifies the enforcement ("Enforce max_message_size — close with code 1009
// (message too big) if exceeded"; :116 names the unbounded fragmented-message
// buffer as a memory-exhaustion risk) — but it was read by NOTHING outside
// internal/config: websocket.Config had no such field, setupWebSocketRuntime
// never mapped it, and the reassembly buffer was bounded only by the hardcoded
// maxAssembledMessageBytes (8 MiB). So an operator's explicit message-size
// policy was silently ignored.
//
// The tests drive the real serve wiring (config -> setupWebSocketRuntime ->
// engine.Middleware -> websocket layer) against a loopback WebSocket backend
// that records every frame it receives, and assert the documented behaviour:
// an over-limit message is refused with close code 1009 and never reaches the
// backend, while a message within the limit is relayed intact.

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

type wsMaxMsgFrame struct {
	opcode  websocket.Opcode
	payload []byte
}

type wsMaxMsgHarness struct {
	t         *testing.T
	mu        sync.Mutex
	received  []wsMaxMsgFrame
	client    net.Conn
	backendLn net.Listener
	srv       *httptest.Server
}

// startWSPartialHarness wires the WebSocket inspection layer exactly the way
// the serve command does, with the given waf.websocket.max_message_size.
func startWSMaxMsgHarness(t *testing.T, maxMessageSize int64) *wsMaxMsgHarness {
	t.Helper()

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	backendAddr := backendLn.Addr().String()

	h := &wsMaxMsgHarness{t: t, backendLn: backendLn}

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
					h.mu.Lock()
					h.received = append(h.received, wsMaxMsgFrame{opcode: f.Opcode, payload: append([]byte(nil), f.Payload...)})
					h.mu.Unlock()
				}
			}(conn)
		}
	}()

	cfg := config.DefaultConfig()
	cfg.WAF.WebSocket.Enabled = true
	cfg.WAF.WebSocket.ScanPayloads = true
	cfg.WAF.WebSocket.MaxMessageSize = maxMessageSize // the documented policy under test
	cfg.Upstreams = []config.UpstreamConfig{{
		Name:    "app",
		Targets: []config.TargetConfig{{URL: "http://" + backendAddr}},
	}}

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(64), events.NewEventBus())
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })

	detection, ok, err := layerregistry.BuildLayer("detection", cfg)
	if err != nil || !ok {
		t.Fatalf("detection layer: ok=%v err=%v", ok, err)
	}
	eng.AddLayer(detection)

	setupWebSocketRuntime(cfg, eng)

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	})
	h.srv = httptest.NewServer(eng.Middleware(next))
	t.Cleanup(h.srv.Close)

	client, err := net.Dial("tcp", h.srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	h.client = client
	t.Cleanup(func() { _ = client.Close() })

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
		t.Fatalf("harness: inspection is not active (status %q)", statusLine)
	}
	return h
}

func (h *wsMaxMsgHarness) frames() []wsMaxMsgFrame {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]wsMaxMsgFrame, len(h.received))
	copy(out, h.received)
	return out
}

// sendFragmented sends a fragmented text message: the first 512 bytes in an
// OpText frame (FIN=0), the remainder in an OpContinuation frame (FIN=1).
func (h *wsMaxMsgHarness) sendFragmented(total int) {
	h.t.Helper()
	first := 512
	if total < first {
		first = total
	}
	h.send(websocket.OpText, false, bytes.Repeat([]byte("A"), first))
	if total > first {
		h.send(websocket.OpContinuation, true, bytes.Repeat([]byte("B"), total-first))
	}
}

func (h *wsMaxMsgHarness) send(op websocket.Opcode, fin bool, payload []byte) {
	h.t.Helper()
	var frame bytes.Buffer
	if werr := websocket.WriteFrameMasked(&frame, &websocket.Frame{
		FIN: fin, Opcode: op, Payload: payload,
	}); werr != nil {
		h.t.Fatalf("write frame: %v", werr)
	}
	if _, werr := h.client.Write(frame.Bytes()); werr != nil {
		h.t.Fatalf("send frame: %v", werr)
	}
}

func (h *wsMaxMsgHarness) waitFrames(want int, timeout time.Duration) []wsMaxMsgFrame {
	deadline := time.Now().Add(timeout)
	for {
		fr := h.frames()
		if len(fr) >= want || time.Now().After(deadline) {
			return fr
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// hasDataPayload reports whether a data frame with exactly size bytes of the
// given filler byte reached the backend.
func hasWSMaxMsgDataPayload(frames []wsMaxMsgFrame, b byte, size int) bool {
	for _, f := range frames {
		if f.opcode.IsControl() {
			continue
		}
		if len(f.payload) == size && bytes.Equal(f.payload, bytes.Repeat([]byte{b}, size)) {
			return true
		}
	}
	return false
}

// wsMaxMsgCloseCode returns the close code of the first close frame, or 0.
func wsMaxMsgCloseCode(frames []wsMaxMsgFrame) int {
	for _, f := range frames {
		if f.opcode == websocket.OpClose && len(f.payload) >= 2 {
			return int(f.payload[0])<<8 | int(f.payload[1])
		}
	}
	return 0
}

// An over-limit fragmented message must be refused with close code 1009 and
// must never reach the backend.
func TestWebSocketMaxMessageSizeRefusesOversizedFragmentedMessage(t *testing.T) {
	const limit = 1024
	const total = 1536

	h := startWSMaxMsgHarness(t, limit)
	h.sendFragmented(total)
	h.waitFrames(2, 3*time.Second)
	time.Sleep(300 * time.Millisecond) // allow any forwarded frame to land
	frames := h.frames()

	if hasWSMaxMsgDataPayload(frames, 'B', total-512) {
		t.Fatalf("FAIL: waf.websocket.max_message_size=%d was ignored — a %d-byte fragmented message "+
			"reached the backend. The setting is parsed into config (config.go:479, defaults.go:295) and "+
			"documented as enforced in docs/adr/0035-websocket-proxy.md:59 (\"close with code 1009 (message "+
			"too big) if exceeded\"), but websocket.Config had no such field and setupWebSocketRuntime never "+
			"mapped it", limit, total)
	}
	if code := wsMaxMsgCloseCode(frames); code != 1009 {
		t.Fatalf("FAIL: the over-limit message was not refused with close code 1009 (got %d)", code)
	}
}

// Boundary: a fragmented message whose assembled size is exactly the limit is
// within policy and must be relayed intact.
func TestWebSocketMaxMessageSizeAllowsMessageAtLimit(t *testing.T) {
	const limit = 1024
	const total = 1024

	h := startWSMaxMsgHarness(t, limit)
	h.sendFragmented(total)
	frames := h.waitFrames(2, 3*time.Second)

	if !hasWSMaxMsgDataPayload(frames, 'B', total-512) {
		t.Fatalf("FAIL: a %d-byte message (exactly at the %d-byte limit) was not relayed to the backend "+
			"(frames: %d)", total, limit, len(frames))
	}
	if code := wsMaxMsgCloseCode(frames); code == 1009 {
		t.Fatalf("FAIL: a message exactly at the limit was refused with 1009")
	}
}

// Control: a generous limit must relay the same message.
func TestWebSocketMaxMessageSizeRelaysMessageWithinLimit(t *testing.T) {
	const limit = 1 << 20
	const total = 1536

	h := startWSMaxMsgHarness(t, limit)
	h.sendFragmented(total)
	frames := h.waitFrames(2, 3*time.Second)

	if !hasWSMaxMsgDataPayload(frames, 'B', total-512) {
		t.Fatalf("FAIL: the fragmented message did not reach the backend with a 1 MiB limit (frames: %d)",
			len(frames))
	}
}

// Secondary branch: a message that arrives in a single frame is bounded by
// max_frame_size only, so the configured message limit must apply to it too.
func TestWebSocketMaxMessageSizeRefusesOversizedSingleFrame(t *testing.T) {
	const limit = 1024

	h := startWSMaxMsgHarness(t, limit)
	h.send(websocket.OpText, true, bytes.Repeat([]byte("C"), 2048))
	h.waitFrames(1, 3*time.Second)
	time.Sleep(300 * time.Millisecond)
	frames := h.frames()

	if hasWSMaxMsgDataPayload(frames, 'C', 2048) {
		t.Fatalf("FAIL: a single-frame 2048-byte message reached the backend despite "+
			"waf.websocket.max_message_size=%d", limit)
	}
	if code := wsMaxMsgCloseCode(frames); code != 1009 {
		t.Fatalf("FAIL: the over-limit single-frame message was not refused with close code 1009 (got %d)", code)
	}
}
