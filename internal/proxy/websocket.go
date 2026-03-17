package proxy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// IsWebSocketUpgrade checks if the request is a WebSocket upgrade request.
func IsWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// HandleWebSocket proxies a WebSocket connection bidirectionally.
// It hijacks the client connection and establishes a raw TCP connection
// to the upstream backend, then copies data in both directions.
func (p *Proxy) HandleWebSocket(w http.ResponseWriter, r *http.Request, backend *Backend) {
	// 1. Determine the upstream address
	targetHost := backend.URL.Host
	if !strings.Contains(targetHost, ":") {
		if backend.URL.Scheme == "https" || backend.URL.Scheme == "wss" {
			targetHost += ":443"
		} else {
			targetHost += ":80"
		}
	}

	// 2. Connect to the upstream backend via raw TCP
	dialer := net.Dialer{
		Timeout: p.config.ConnectTimeout,
	}
	upstreamConn, err := dialer.Dial("tcp", targetHost)
	if err != nil {
		http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
		return
	}
	defer upstreamConn.Close()

	// 3. Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "WebSocket hijack failed", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// 4. Forward the original HTTP upgrade request to the upstream
	if err := r.Write(upstreamConn); err != nil {
		return
	}

	// 5. Flush any buffered data from the client to the upstream
	if clientBuf.Reader.Buffered() > 0 {
		buffered := make([]byte, clientBuf.Reader.Buffered())
		n, _ := clientBuf.Read(buffered)
		if n > 0 {
			upstreamConn.Write(buffered[:n])
		}
	}

	// 6. Bidirectional copy
	doneCh := make(chan struct{}, 2)

	// upstream -> client
	go func() {
		io.Copy(clientConn, upstreamConn)
		// Signal that this direction is done
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		doneCh <- struct{}{}
	}()

	// client -> upstream
	go func() {
		io.Copy(upstreamConn, clientConn)
		// Signal that this direction is done
		if tc, ok := upstreamConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		doneCh <- struct{}{}
	}()

	// Wait for one direction to finish, then give the other a deadline
	<-doneCh

	// Set a deadline for the remaining direction to drain
	deadline := time.Now().Add(5 * time.Second)
	clientConn.SetDeadline(deadline)
	upstreamConn.SetDeadline(deadline)

	// Wait for the second direction
	<-doneCh
}
