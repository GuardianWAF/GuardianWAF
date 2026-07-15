package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- SSE ---

func (d *Dashboard) handleSSE(w http.ResponseWriter, r *http.Request) {
	d.sse.HandleSSE(w, r)
}

// --- SSE Broadcaster ---

// SSEBroadcaster manages Server-Sent Events client connections.
// Each client is registered with a tenant scope: an empty scope receives all
// events; a non-empty scope (a tenant-scoped API key) receives only that
// tenant's events, preventing live cross-tenant event disclosure.
type SSEBroadcaster struct {
	mu         sync.RWMutex
	clients    map[chan string]string // channel -> tenant scope ("" = all)
	maxClients int
}

const defaultMaxSSEClients = 1000

// NewSSEBroadcaster creates a new SSEBroadcaster.
func NewSSEBroadcaster() *SSEBroadcaster {
	return &SSEBroadcaster{
		clients:    make(map[chan string]string),
		maxClients: defaultMaxSSEClients,
	}
}

// HandleSSE is the HTTP handler for SSE connections.
func (b *SSEBroadcaster) HandleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// SSE is a long-lived stream; the server's WriteTimeout would otherwise
	// abort it after ~30s. Clear the per-request write deadline so the stream
	// stays open until the client disconnects.
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetWriteDeadline(time.Time{}) //nolint:errcheck // best-effort; falls back to WriteTimeout if unsupported
	}

	// Check client cap and register atomically. Tenant-scoped keys only
	// receive their own tenant's events.
	scope := tenantScope(r)
	ch := make(chan string, 64)
	b.mu.Lock()
	if len(b.clients) >= b.maxClients {
		b.mu.Unlock()
		http.Error(w, "too many SSE connections", http.StatusServiceUnavailable)
		return
	}
	b.clients[ch] = scope
	b.mu.Unlock()
	defer b.removeClient(ch)

	fmt.Fprintf(w, "data: {\"type\":\"connected\"}\n\n")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case msg := <-ch:
			// Split on newlines per SSE spec: each line gets its own "data:" prefix
			for _, line := range strings.Split(msg, "\n") {
				fmt.Fprintf(w, "data: %s\n", line)
			}
			fmt.Fprint(w, "\n")
			flusher.Flush()
		case <-ctx.Done():
			return
		}
	}
}

// BroadcastEvent serializes and broadcasts a WAF event to all SSE clients.
// Uses json.Marshal on the Event struct directly (which has json tags).
func (b *SSEBroadcaster) BroadcastEvent(event engine.Event) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch, scope := range b.clients {
		// A tenant-scoped client only receives its own tenant's events.
		if scope != "" && scope != event.TenantID {
			continue
		}
		select {
		case ch <- string(data):
		default:
		}
	}
}

// ClientCount returns the number of connected SSE clients.
func (b *SSEBroadcaster) ClientCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients)
}

func (b *SSEBroadcaster) addClient(ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.clients[ch] = ""
}

func (b *SSEBroadcaster) removeClient(ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.clients, ch)
	close(ch)
}
