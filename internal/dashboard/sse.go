package dashboard

import (
	"fmt"
	"net/http"
	"sync"
)

// SSEBroadcaster manages Server-Sent Events client connections
// and broadcasts events to all connected clients.
type SSEBroadcaster struct {
	mu      sync.RWMutex
	clients map[chan string]struct{}
}

// NewSSEBroadcaster creates a new SSEBroadcaster.
func NewSSEBroadcaster() *SSEBroadcaster {
	return &SSEBroadcaster{
		clients: make(map[chan string]struct{}),
	}
}

// addClient registers a new SSE client channel.
func (b *SSEBroadcaster) addClient(ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.clients[ch] = struct{}{}
}

// removeClient unregisters an SSE client channel and closes it.
func (b *SSEBroadcaster) removeClient(ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.clients, ch)
	close(ch)
}

// HandleSSE is the HTTP handler for SSE connections.
// It sets the appropriate headers and streams events until the client disconnects.
func (b *SSEBroadcaster) HandleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := make(chan string, 64)
	b.addClient(ch)
	defer b.removeClient(ch)

	// Send initial connection confirmation
	fmt.Fprintf(w, "data: {\"type\":\"connected\"}\n\n")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-ctx.Done():
			return
		}
	}
}

// Broadcast sends a message to all connected SSE clients.
// eventType is included in the JSON payload; data is the raw JSON string.
func (b *SSEBroadcaster) Broadcast(eventType, data string) {
	msg := fmt.Sprintf("{\"type\":%q,\"data\":%s}", eventType, data)

	b.mu.RLock()
	defer b.mu.RUnlock()

	for ch := range b.clients {
		select {
		case ch <- msg:
		default:
			// Drop message if client buffer is full
		}
	}
}

// ClientCount returns the number of connected SSE clients.
func (b *SSEBroadcaster) ClientCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients)
}
