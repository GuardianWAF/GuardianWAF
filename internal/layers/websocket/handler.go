package websocket

import (
	"encoding/json"
	"net/http"
)

// Handler provides HTTP API for WebSocket monitoring.
type Handler struct {
	security *Security
}

// NewHandler creates a new WebSocket handler.
func NewHandler(security *Security) *Handler {
	return &Handler{security: security}
}

// ServeHTTP implements http.Handler interface.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/websocket/stats":
		h.handleStats(w, r)
	case "/api/v1/websocket/connections":
		h.handleConnections(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleStats returns WebSocket statistics.
func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.security.GetStats()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		// Client disconnected - error ignored intentionally
		_ = err
	}
}

// handleConnections returns active connections.
func (h *Handler) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	conns := h.security.GetAllConnections()

	// Build response with connection info
	type connInfo struct {
		ID         string `json:"id"`
		RemoteAddr string `json:"remote_addr"`
		Origin     string `json:"origin"`
		Path       string `json:"path"`
		Connected  string `json:"connected"`
		LastSeen   string `json:"last_seen"`
		MsgCount   int64  `json:"msg_count"`
		ByteCount  int64  `json:"byte_count"`
	}

	info := make([]connInfo, 0, len(conns))
	for _, conn := range conns {
		conn.mu.RLock()
		info = append(info, connInfo{
			ID:         conn.ID,
			RemoteAddr: conn.RemoteAddr,
			Origin:     conn.Origin,
			Path:       conn.Path,
			Connected:  conn.Connected.Format("2006-01-02T15:04:05Z"),
			LastSeen:   conn.LastSeen.Format("2006-01-02T15:04:05Z"),
			MsgCount:   conn.MsgCount,
			ByteCount:  conn.ByteCount,
		})
		conn.mu.RUnlock()
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"connections": info,
		"count":       len(info),
	}); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}
