package mcp

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// SSEHandler serves the MCP protocol over HTTP using Server-Sent Events.
// Client→Server: POST /message with JSON-RPC body
// Server→Client: GET /sse for SSE event stream
// Auth: X-API-Key header or ?api_key query param
type SSEHandler struct {
	server *Server
	apiKey string

	mu      sync.Mutex
	clients map[*sseClient]bool
}

type sseClient struct {
	w       http.ResponseWriter
	flusher http.Flusher
	done    chan struct{}
	closed  bool // guarded by mu on parent SSEHandler
	mu      sync.Mutex // Protects writes to w
}

// NewSSEHandler creates an HTTP handler that serves MCP over SSE.
func NewSSEHandler(srv *Server, apiKey string) *SSEHandler {
	return &SSEHandler{
		server:  srv,
		apiKey:  apiKey,
		clients: make(map[*sseClient]bool),
	}
}

// RegisterRoutes registers the MCP SSE endpoints on the given mux.
func (h *SSEHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /mcp/sse", h.handleSSE)
	mux.HandleFunc("POST /mcp/message", h.handleMessage)
}

func (h *SSEHandler) authenticate(r *http.Request) bool {
	if h.apiKey == "" {
		return true
	}
	if key := r.Header.Get("X-API-Key"); key != "" {
		return subtle.ConstantTimeCompare([]byte(key), []byte(h.apiKey)) == 1
	}
	if key := r.URL.Query().Get("api_key"); key != "" {
		log.Printf("[WARN] MCP API key passed via query parameter from %s — rejected, use X-API-Key header", r.RemoteAddr)
		return false // Reject query-param-based API keys to prevent credential leakage
	}
	return false
}

// handleSSE establishes the SSE connection for server→client messages.
func (h *SSEHandler) handleSSE(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	client := &sseClient{w: w, flusher: flusher, done: make(chan struct{})}

	h.mu.Lock()
	h.clients[client] = true
	h.mu.Unlock()

	// Remove client on disconnect — prevents zombie client memory leak
	defer func() {
		h.mu.Lock()
		delete(h.clients, client)
		if !client.closed {
			client.closed = true
			close(client.done)
		}
		h.mu.Unlock()
	}()

	// Send endpoint event — tells the client where to POST messages
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	messageURL := fmt.Sprintf("%s://%s/mcp/message", scheme, r.Host)
	client.mu.Lock()
	fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", messageURL)
	flusher.Flush()
	client.mu.Unlock()

	// Keep connection alive until client disconnects
	// Periodic heartbeat ensures dead connections are cleaned up
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			// Send comment-only heartbeat to detect broken connections.
			// If the write fails, the client is dead — remove immediately.
			client.mu.Lock()
			_, err := fmt.Fprint(w, ": heartbeat\n\n")
			if err == nil {
				flusher.Flush()
			}
			client.mu.Unlock()
			if err != nil {
				return // Client disconnected — trigger defer cleanup
			}
		}
	}
}

// handleMessage receives JSON-RPC requests from the client via POST.
func (h *SSEHandler) handleMessage(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1*1024*1024))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	// Process via HandleRequestJSON (thread-safe, no writer swap)
	respData, err := h.server.HandleRequestJSON(body)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Broadcast response to all SSE clients
	var resp JSONRPCResponse
	if json.Unmarshal(respData, &resp) == nil {
		h.broadcastResponse(resp)
	}

	w.WriteHeader(http.StatusAccepted)
}

// broadcastResponse sends a JSON-RPC response to all connected SSE clients.
func (h *SSEHandler) broadcastResponse(resp JSONRPCResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	for client := range h.clients {
		select {
		case <-client.done:
			continue
		default:
		}
		client.mu.Lock()
		if _, err := fmt.Fprintf(client.w, "event: message\ndata: %s\n\n", string(data)); err != nil {
			client.mu.Unlock()
			if !client.closed {
				client.closed = true
				close(client.done)
			}
			delete(h.clients, client)
			continue
		}
		client.flusher.Flush()
		client.mu.Unlock()
	}
}

// ClientCount returns the number of connected SSE clients.
func (h *SSEHandler) ClientCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}
