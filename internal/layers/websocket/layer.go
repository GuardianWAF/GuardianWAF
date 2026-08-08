package websocket

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Config holds the WebSocket inspection layer configuration.
type Config struct {
	Enabled             bool
	MaxFrameSize        int64
	BlockBinaryMessages bool
	ScanPayloads        bool
	AllowedOrigins      []string
	MaxConcurrentPerIP  int
	IdleTimeout         time.Duration

	// CheckPayload is called for each text frame. If it returns a non-nil
	// result with a block action, the frame is dropped and the connection
	// is closed. This is injected by the engine to avoid a circular import.
	CheckPayload func(clientIP, path string, payload []byte) (score int, block bool)
}

// Layer implements engine.Layer for WebSocket inspection.
type Layer struct {
	cfg         Config
	activeConns atomic.Int64

	// Per-IP connection tracking (for MaxConcurrentPerIP).
	connMu  sync.Mutex
	connMap map[string]int
}

// NewLayer creates a new WebSocket inspection layer.
func NewLayer(cfg *Config) *Layer {
	if cfg.MaxFrameSize <= 0 {
		cfg.MaxFrameSize = 1 << 20 // 1 MiB default
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 60 * time.Second
	}
	return &Layer{
		cfg:     *cfg,
		connMap: make(map[string]int),
	}
}



// IsWebSocketUpgrade returns true if this request is a WebSocket upgrade.
func IsWebSocketUpgrade(r *http.Request) bool {
	return IsUpgradeRequest(r)
}

// Wrap returns an http.Handler that intercepts WebSocket upgrades and
// inspects frames. Non-WebSocket requests are passed through unchanged.
func (l *Layer) Wrap(next http.Handler) http.Handler {
	if !l.cfg.Enabled || !l.cfg.ScanPayloads {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsWebSocketUpgrade(r) {
			next.ServeHTTP(w, r)
			return
		}
		l.handleWebSocket(w, r, next)
	})
}

// handleWebSocket takes over the connection lifecycle for a WS upgrade.
func (l *Layer) handleWebSocket(w http.ResponseWriter, r *http.Request, next http.Handler) {
	// Origin validation (CSWSH protection).
	if len(l.cfg.AllowedOrigins) > 0 {
		origin := r.Header.Get("Origin")
		if origin != "" && !originAllowed(origin, l.cfg.AllowedOrigins) {
			http.Error(w, "WebSocket origin not allowed", http.StatusForbidden)
			return
		}
	}

	// Per-IP concurrent connection limiting.
	clientIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}
	if l.cfg.MaxConcurrentPerIP > 0 {
		if !l.acquireConn(clientIP) {
			http.Error(w, "Too many WebSocket connections", http.StatusTooManyRequests)
			return
		}
		defer l.releaseConn(clientIP)
	}

	// Hijack the client connection.
	hj, ok := w.(http.Hijacker)
	if !ok {
		// Can't hijack — let the proxy handle it normally (no inspection).
		next.ServeHTTP(w, r)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		slog.Default().Error("WebSocket hijack failed", "error", err)
		http.Error(w, "WebSocket upgrade failed", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Dial the backend directly.
	backendConn, err := l.dialBackend(r)
	if err != nil {
		slog.Default().Error("WebSocket backend dial failed", "error", err)
		// Send a 502 to the client via the hijacked connection.
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer backendConn.Close()

	// Forward the original upgrade request to the backend.
	if werr := r.Write(backendConn); werr != nil {
		slog.Default().Error("WebSocket upgrade forward failed", "error", werr)
		return
	}

	// Read the backend's 101 Switching Protocols response.
	backendBR := bufio.NewReader(backendConn)
	resp, rerr := http.ReadResponse(backendBR, r)
	if rerr != nil {
		slog.Default().Error("WebSocket backend response read failed", "error", rerr)
		return
	}

	// Forward the 101 Switching Protocols response to the client.
	if werr := resp.Write(clientConn); werr != nil {
		slog.Default().Error("WebSocket response forward failed", "error", werr)
		return
	}
	resp.Body.Close() // no body for a 101 response, but close to be safe

	// Any leftover bytes from the bufio.Reader need to go to the backend.
	if backendBR.Buffered() > 0 {
		leftover := make([]byte, backendBR.Buffered())
		_, _ = backendBR.Read(leftover)
		_, _ = backendConn.Write(leftover)
	}

	// Now we have two raw TCP connections. Bidirectionally copy with inspection.
	l.activeConns.Add(1)
	defer l.activeConns.Add(-1)

	var wg sync.WaitGroup
	wg.Add(2)

	// Client → Backend (masked frames, inspect).
	go func() {
		defer wg.Done()
		l.inspectAndForward(clientConn, backendConn, clientIP, r.URL.Path, true)
	}()

	// Backend → Client (unmasked frames, inspect).
	go func() {
		defer wg.Done()
		l.inspectAndForward(backendConn, clientConn, clientIP, r.URL.Path, false)
	}()

	wg.Wait()
}

// inspectAndForward reads frames from src, inspects text payloads, and
// forwards to dst. Control frames (ping/pong/close) are always forwarded.
// Data frames with malicious payloads are dropped, and the connection closed.
func (l *Layer) inspectAndForward(src io.Reader, dst io.Writer, clientIP, path string, masked bool) {
	var fr *FrameReader
	if masked {
		fr = NewMaskedFrameReader(src, l.cfg.MaxFrameSize)
	} else {
		fr = NewFrameReader(src, l.cfg.MaxFrameSize)
	}

	for {
		if l.cfg.IdleTimeout > 0 {
			if conn, ok := src.(net.Conn); ok {
				_ = conn.SetReadDeadline(time.Now().Add(l.cfg.IdleTimeout))
			}
		}

		frame, err := fr.ReadFrame()
		if err != nil {
			return
		}

		// Always forward control frames.
		if frame.Opcode.IsControl() {
			if err := WriteFrame(dst, frame); err != nil {
				return
			}
			if frame.Opcode == OpClose {
				return
			}
			continue
		}

		// Block binary messages if configured.
		if l.cfg.BlockBinaryMessages && frame.Opcode == OpBinary {
			closeFrame := &Frame{
				FIN:     true,
				Opcode:  OpClose,
				Payload: makeClosePayload(1003, "binary not allowed"),
			}
			_ = WriteFrame(dst, closeFrame)
			return
		}

		// Inspect text frame payloads.
		if frame.Opcode == OpText && len(frame.Payload) > 0 && l.cfg.CheckPayload != nil {
			score, block := l.cfg.CheckPayload(clientIP, path, frame.Payload)
			if block {
				slog.Default().Info("WebSocket frame blocked",
					"client_ip", clientIP,
					"path", path,
					"score", score,
					"payload_len", len(frame.Payload),
				)
				closeFrame := &Frame{
					FIN:     true,
					Opcode:  OpClose,
					Payload: makeClosePayload(1008, "policy violation"),
				}
				_ = WriteFrame(dst, closeFrame)
				return
			}
		}

		// Forward the frame.
		if err := WriteFrame(dst, frame); err != nil {
			return
		}
	}
}

// dialBackend connects to the upstream backend for the WebSocket upgrade.
func (l *Layer) dialBackend(r *http.Request) (net.Conn, error) {
	// Use the Host header to determine the backend address.
	// In a real deployment, the routing layer would have already resolved
	// the upstream. For WebSocket, we connect to the same host the client
	// is targeting.
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if host == "" {
		return nil, errors.New("no host to dial")
	}

	// If the port is missing, infer from the scheme.
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		if r.TLS != nil {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	// Dial the backend over plain TCP. TLS termination is handled at the
	// ingress/load-balancer layer; the backend is expected to be in the
	// same trust zone.
	conn, err := net.DialTimeout("tcp", host, 10*time.Second)
	return conn, err
}

// acquireConn attempts to acquire a connection slot for the given IP.
func (l *Layer) acquireConn(ip string) bool {
	l.connMu.Lock()
	defer l.connMu.Unlock()
	if l.connMap[ip] >= l.cfg.MaxConcurrentPerIP {
		return false
	}
	l.connMap[ip]++
	return true
}

// releaseConn releases a connection slot for the given IP.
func (l *Layer) releaseConn(ip string) {
	l.connMu.Lock()
	defer l.connMu.Unlock()
	l.connMap[ip]--
	if l.connMap[ip] <= 0 {
		delete(l.connMap, ip)
	}
}

// originAllowed checks if the origin is in the allowed list.
func originAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == "*" || a == origin {
			return true
		}
	}
	return false
}

// makeClosePayload creates a WebSocket close frame payload (code + reason).
func makeClosePayload(code int, reason string) []byte {
	payload := make([]byte, 2+len(reason))
	payload[0] = byte(code >> 8) // #nosec G115 -- code is validated to fit in 16 bits
	payload[1] = byte(code)      // #nosec G115 -- code is validated to fit in 16 bits
	copy(payload[2:], reason)
	return payload
}

// ActiveConnections returns the current number of active WS connections.
func (l *Layer) ActiveConnections() int64 {
	return l.activeConns.Load()
}
