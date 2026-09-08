package websocket

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Regression: the takeover's leftover-forward read the backend's buffered
// bytes (its first frames, sent in the same TCP segment as the 101) and wrote
// them BACK to backendConn — the client never received them and the backend
// received its own frames echoed as input. The leftover belongs to the client.
func TestLeftoverFramesReachClient(t *testing.T) {
	const frame = "\x81\x05hello" // FIN+text, len 5, unmasked (backend→client)
	const head101 = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"

	backendEcho := make(chan string, 1)
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()
	backendHost := strings.Split(backendAddr, ":")[0]

	go func() {
		for {
			conn, aerr := backendLn.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Drain the forwarded request headers (bounded).
				c.SetReadDeadline(time.Now().Add(time.Second))
				br := bufio.NewReader(c)
				for {
					line, rerr := br.ReadString('\n')
					if rerr != nil || line == "\r\n" {
						break
					}
				}
				// Emit the 101 + the first frame in ONE write so both land
				// in the layer's bufio buffer behind the parsed 101.
				if _, werr := c.Write([]byte(head101 + frame)); werr != nil {
					return
				}
				// Echo detector: anything the layer sends back after the
				// 101+frame (the pre-fix echo lands here).
				c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				buf := make([]byte, 256)
				if n, _ := c.Read(buf); n > 0 {
					select {
					case backendEcho <- string(buf[:n]):
					default:
					}
				}
			}(conn)
		}
	}()

	layer := NewLayer(&Config{
		Enabled:             true,
		ScanPayloads:        true,
		IdleTimeout:         50 * time.Millisecond,
		AllowedBackendHosts: []string{backendHost},
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

	req := "GET /ws HTTP/1.1\r\nHost: " + backendAddr + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}

	// Read through the 101 headers, then expect the backend's first frame.
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
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(frame))
	if _, err := io.ReadFull(reader, got); err != nil {
		echo := ""
		select {
		case e := <-backendEcho:
			echo = e
		default:
		}
		t.Fatalf("FAIL: client never received the backend's first frame (%v); backend echo after its 101: %q — the leftover was forwarded to the backend instead of the client", err, echo)
	}
	if string(got) != frame {
		t.Fatalf("client received corrupted frame %q, want %q", got, frame)
	}
}
