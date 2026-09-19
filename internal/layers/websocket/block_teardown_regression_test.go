package websocket

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Regression (round 2026-09-18): the refuse paths in inspectAndForward (block / framing violation / over-cap) wrote a close frame toward dst and returned without closing either connection — the sibling relay (joined only at wg.Wait()), the deferred connection closes, and the per-IP slot stayed held until the REMOTE peer closed. With a backend that streams and ignores closes the blocked side sat on a zombie connection indefinitely, violating Config.s contract "the frame is dropped and the connection is closed".
//
// Config's contract for CheckPayload (layer.go): "the frame is dropped and
// the connection is closed". Every refuse path in inspectAndForward writes a
// close frame toward dst and returns WITHOUT closing either connection: the
// two relay goroutines join only at wg.Wait(), and the deferred
// clientConn/backendConn closes plus the per-IP slot fire only after BOTH
// directions exit. With a backend that ignores the close frame or simply
// keeps streaming, the blocked side stays on a zombie connection
// indefinitely: its relay is dead, the other direction keeps relaying, and
// the held resources are never released.
func TestProofBlockedConnectionTeardown(t *testing.T) {
	const probe = "EVOKE-BLOCK-PROBE"
	const benignFrame = "\x81\x02hi" // FIN+text, len 2, unmasked (backend→client)

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()
	backendHost := strings.Split(backendAddr, ":")[0]

	// Non-compliant streaming backend: emits the 101, then streams benign
	// frames every 10ms and NEVER reacts to close frames — the zombie
	// condition the refuse paths must not depend on the peer to avoid.
	go func() {
		for {
			conn, aerr := backendLn.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				br := bufio.NewReader(c)
				for {
					line, rerr := br.ReadString('\n')
					if rerr != nil || line == "\r\n" {
						break
					}
				}
				c.SetWriteDeadline(time.Now().Add(3 * time.Second))
				if _, werr := c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")); werr != nil {
					return
				}
				for {
					c.SetWriteDeadline(time.Now().Add(3 * time.Second))
					if _, werr := c.Write([]byte(benignFrame)); werr != nil {
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
			}(conn)
		}
	}()

	layer := NewLayer(&Config{
		Enabled:             true,
		ScanPayloads:        true,
		IdleTimeout:         time.Second,
		AllowedBackendHosts: []string{backendHost},
		CheckPayload: func(clientIP, path string, payload []byte) (int, bool) {
			if strings.Contains(string(payload), probe) {
				return 100, true
			}
			return 0, false
		},
	})
	srv := httptest.NewServer(layer.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	})))
	defer srv.Close()

	client, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// Upgrade request without an Origin header — non-browser clients pass the
	// origin gate so the proof exercises the relay, not the gate.
	req := "GET /ws HTTP/1.1\r\nHost: " + backendAddr + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}

	reader := bufio.NewReader(client)
	for {
		line, rerr := reader.ReadString('\n')
		if rerr != nil {
			t.Fatalf("read 101: %v", rerr)
		}
		if line == "\r\n" {
			break
		}
	}

	// One masked text frame carrying the probe — trips the refuse path.
	if err := WriteFrameMasked(client, &Frame{FIN: true, Opcode: OpText, Payload: []byte(probe)}); err != nil {
		t.Fatalf("write probe frame: %v", err)
	}

	// The refuse path must tear the connection down: handleWebSocket returns,
	// releasing the per-IP slot and decrementing activeConns. With a backend
	// that streams and ignores closes, only an actual teardown ends this.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if layer.ActiveConnections() == 0 {
			return // torn down — PASS
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("FAIL: blocked connection not torn down — ActiveConnections() still %d; the refuse path abandoned the sibling relay, the deferred connection closes, and the per-IP slot while the backend streams", layer.ActiveConnections())
}
