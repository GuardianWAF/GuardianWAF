package mcp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/logging"
)

// SSEHandler serves the MCP protocol over HTTP using Server-Sent Events.
// Client→Server: POST /message with JSON-RPC body
// Server→Client: GET /sse for SSE event stream
// Auth: X-API-Key header or ?api_key query param
type SSEHandler struct {
	server         *Server
	apiKey         string
	apiKeyProvider func() string

	mu                sync.Mutex
	clients           map[*sseClient]bool
	sessions          map[string]*sseClient
	log               *slog.Logger
	heartbeatInterval time.Duration
}

type sseClient struct {
	id      string
	w       http.ResponseWriter
	flusher http.Flusher
	done    chan struct{}
	closed  bool        // guarded by mu on parent SSEHandler
	ch      chan []byte // outbound queue; only the handler goroutine writes to w
}

// sseClientQueue bounds a client's pending outbound responses. A client that
// falls this far behind has messages dropped rather than blocking other sessions.
const sseClientQueue = 64

// maxMCPSSEClients limits concurrent SSE connections to prevent resource exhaustion.
const maxMCPSSEClients = 256
const maxMCPMessageBody = 1 * 1024 * 1024

// NewSSEHandler creates an HTTP handler that serves MCP over SSE.
func NewSSEHandler(srv *Server, apiKey string) *SSEHandler {
	return &SSEHandler{
		server:            srv,
		apiKey:            apiKey,
		clients:           make(map[*sseClient]bool),
		sessions:          make(map[string]*sseClient),
		log:               logging.NewLogger("mcp-sse"),
		heartbeatInterval: 30 * time.Second,
	}
}

// NewSSEHandlerWithAPIKeyProvider creates an SSE handler whose authentication
// key is loaded for every request. Dashboard key rotation therefore takes
// effect immediately instead of leaving a startup-time key copy.
func NewSSEHandlerWithAPIKeyProvider(srv *Server, provider func() string) *SSEHandler {
	h := NewSSEHandler(srv, "")
	h.apiKeyProvider = provider
	return h
}

// RegisterRoutes registers the MCP SSE endpoints on the given mux.
func (h *SSEHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /mcp/sse", h.handleSSE)
	mux.HandleFunc("POST /mcp/message", h.handleMessage)
}

func (h *SSEHandler) authenticate(r *http.Request) bool {
	_, ok := h.authenticateContext(r)
	return ok
}

func (h *SSEHandler) authenticateContext(r *http.Request) (*AuditContext, bool) {
	apiKey := h.currentAPIKey()
	if apiKey == "" {
		h.log.Warn("SECURITY: rejecting unauthenticated request — no API key configured", "remote_addr", r.RemoteAddr)
		return nil, false
	}
	if key := r.Header.Get("X-API-Key"); key != "" {
		if subtle.ConstantTimeCompare([]byte(key), []byte(apiKey)) == 1 {
			return &AuditContext{
				Transport:  "sse",
				AuthType:   "api_key",
				Principal:  "dashboard_api_key",
				RemoteAddr: r.RemoteAddr,
			}, true
		}
		return nil, false
	}
	if key := r.URL.Query().Get("api_key"); key != "" {
		h.log.Warn("MCP API key passed via query parameter — rejected, use X-API-Key header", "remote_addr", r.RemoteAddr)
		return nil, false // Reject query-param-based API keys to prevent credential leakage
	}
	return nil, false
}

func (h *SSEHandler) currentAPIKey() string {
	if h.apiKeyProvider != nil {
		return h.apiKeyProvider()
	}
	return h.apiKey
}

// handleSSE establishes the SSE connection for server→client messages.
func (h *SSEHandler) handleSSE(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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

	// Clear the server WriteTimeout for this long-lived stream; otherwise the
	// 30s heartbeat races the deadline and the connection is dropped.
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetWriteDeadline(time.Time{}) //nolint:errcheck // best-effort; falls back to WriteTimeout if unsupported
	}

	sessionID, err := newSSESessionID()
	if err != nil {
		h.log.Error("failed to generate MCP SSE session identifier", "error", err)
		http.Error(w, "session initialization failed", http.StatusInternalServerError)
		return
	}
	client := &sseClient{id: sessionID, w: w, flusher: flusher, done: make(chan struct{}), ch: make(chan []byte, sseClientQueue)}

	h.mu.Lock()
	if len(h.clients) >= maxMCPSSEClients {
		h.mu.Unlock()
		http.Error(w, "too many SSE connections", http.StatusServiceUnavailable)
		return
	}
	h.clients[client] = true
	h.sessions[client.id] = client
	h.mu.Unlock()

	// Remove client on disconnect — prevents zombie client/session leaks.
	defer func() {
		h.mu.Lock()
		delete(h.clients, client)
		delete(h.sessions, client.id)
		if !client.closed {
			client.closed = true
			close(client.done)
		}
		h.mu.Unlock()
	}()

	// Send endpoint event — tells this client where to POST messages. The opaque
	// session ID binds each request/response exchange to this connection only.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := sanitizeSSEEndpointHost(r.Host)
	if host == "" {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	messageURL := fmt.Sprintf("%s://%s/mcp/message?session_id=%s", scheme, host, client.id)
	// All writes to w happen in this single goroutine (endpoint event, queued
	// responses, heartbeats), so no per-write lock is needed and w is never
	// touched after this handler returns.
	if _, err := fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", messageURL); err != nil { // #nosec G705 -- messageURL uses a fixed path and a Host value sanitized against SSE/control injection.
		return
	}
	flusher.Flush()

	// Keep connection alive until client disconnects
	// Periodic heartbeat ensures dead connections are cleaned up
	ticker := time.NewTicker(h.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-client.ch:
			if _, err := fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg); err != nil {
				return // Client disconnected — trigger defer cleanup
			}
			flusher.Flush()
		case <-ticker.C:
			// Send comment-only heartbeat to detect broken connections.
			// If the write fails, the client is dead — remove immediately.
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return // Client disconnected — trigger defer cleanup
			}
			flusher.Flush()
		}
	}
}

func sanitizeSSEEndpointHost(host string) string {
	if host == "" || strings.ContainsAny(host, "@/\\") {
		return ""
	}
	for _, r := range host {
		if r <= 0x20 || r == 0x7f {
			return ""
		}
	}
	return host
}

func newSSESessionID() (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// handleMessage receives JSON-RPC requests from the client via POST.
func (h *SSEHandler) handleMessage(w http.ResponseWriter, r *http.Request) {
	authCtx, ok := h.authenticateContext(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	client, status, err := h.messageClient(r.URL.Query().Get("session_id"))
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxMCPMessageBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	// Process only after the target session has been authenticated and resolved,
	// then enqueue the response to that connection alone.
	respData, _ := h.server.HandleRequestJSONWithAuditContext(body, authCtx)
	if client != nil {
		h.enqueueResponse(client, respData)
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *SSEHandler) messageClient(sessionID string) (*sseClient, int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if sessionID != "" {
		client, ok := h.sessions[sessionID]
		if !ok || client.closed {
			return nil, http.StatusNotFound, errors.New("MCP SSE session not found")
		}
		return client, 0, nil
	}
	if len(h.clients) == 0 {
		// Preserve direct authenticated POST compatibility for callers that do
		// not use SSE and therefore do not expect an asynchronous response.
		return nil, 0, nil
	}
	return nil, http.StatusBadRequest, errors.New("session_id is required when an MCP SSE client is connected")
}

func (h *SSEHandler) enqueueResponse(client *sseClient, data []byte) {
	select {
	case <-client.done:
		return
	default:
	}
	select {
	case client.ch <- data:
	default:
		// Slow clients cannot block unrelated requests or other connections.
		h.log.Warn("dropping MCP SSE response for slow client", "session_id", client.id)
	}
}

// ClientCount returns the number of connected SSE clients.
func (h *SSEHandler) ClientCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}
