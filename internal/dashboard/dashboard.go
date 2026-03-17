// Package dashboard provides the web dashboard and REST API for GuardianWAF.
// It serves a real-time monitoring UI with SSE event streaming,
// REST endpoints for stats/events/config, and embedded static assets.
package dashboard

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

//go:embed static/index.html static/style.css static/app.js
var staticFiles embed.FS

// Dashboard is the web dashboard server.
type Dashboard struct {
	engine     *engine.Engine
	eventStore events.EventStore
	sse        *SSEBroadcaster
	mux        *http.ServeMux
	apiKey     string
}

// New creates a new Dashboard wired to the given engine and event store.
func New(eng *engine.Engine, store events.EventStore, apiKey string) *Dashboard {
	d := &Dashboard{
		engine:     eng,
		eventStore: store,
		sse:        NewSSEBroadcaster(),
		mux:        http.NewServeMux(),
		apiKey:     apiKey,
	}

	// Login/logout (always accessible)
	d.mux.HandleFunc("GET /login", d.handleLoginPage)
	d.mux.HandleFunc("POST /login", d.handleLoginSubmit)
	d.mux.HandleFunc("GET /logout", d.handleLogout)

	// Health check (always accessible, no sensitive data)
	d.mux.HandleFunc("GET /api/v1/health", d.handleHealth)

	// Protected API routes
	d.mux.HandleFunc("GET /api/v1/stats", d.authWrap(d.handleGetStats))
	d.mux.HandleFunc("GET /api/v1/events", d.authWrap(d.handleGetEvents))
	d.mux.HandleFunc("GET /api/v1/events/{id}", d.authWrap(d.handleGetEvent))
	d.mux.HandleFunc("GET /api/v1/sse", d.authWrap(d.handleSSE))

	// Protected static files
	d.mux.HandleFunc("/", d.authWrap(d.handleIndex))
	d.mux.HandleFunc("/style.css", d.authWrap(d.handleStatic("static/style.css", "text/css; charset=utf-8")))
	d.mux.HandleFunc("/app.js", d.authWrap(d.handleStatic("static/app.js", "application/javascript; charset=utf-8")))

	return d
}

// Handler returns the root http.Handler.
func (d *Dashboard) Handler() http.Handler {
	return d.mux
}

// SSE returns the SSE broadcaster for publishing events from outside.
func (d *Dashboard) SSE() *SSEBroadcaster {
	return d.sse
}

// --- Auth ---

func (d *Dashboard) authWrap(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !d.isAuthenticated(r) {
			// API requests get 401 JSON, browser requests get redirected to login
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}
		handler(w, r)
	}
}

func (d *Dashboard) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if d.apiKey == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if d.isAuthenticated(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(loginPage("")))
}

func (d *Dashboard) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if d.apiKey == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	key := r.FormValue("key")
	if key != d.apiKey {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(loginPage("Invalid API key. Please try again.")))
		return
	}
	setSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (d *Dashboard) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// --- Stats ---

func (d *Dashboard) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats := d.engine.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"total_requests":   stats.TotalRequests,
		"blocked_requests": stats.BlockedRequests,
		"logged_requests":  stats.LoggedRequests,
		"passed_requests":  stats.PassedRequests,
		"avg_latency_us":   stats.AvgLatencyUs,
	})
}

// --- Events ---

func (d *Dashboard) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit := 50
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = min(n, 1000)
		}
	}

	offset := 0
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	filter := events.EventFilter{
		Limit:     limit,
		Offset:    offset,
		Action:    q.Get("action"),
		ClientIP:  q.Get("client_ip"),
		Path:      q.Get("path"),
		SortBy:    q.Get("sort_by"),
		SortOrder: q.Get("sort_order"),
	}

	if v := q.Get("min_score"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.MinScore = n
		}
	}

	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Since = t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Until = t
		}
	}

	evts, total, err := d.eventStore.Query(filter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events": evts,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (d *Dashboard) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing event ID"})
		return
	}

	evt, err := d.eventStore.Get(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "event not found"})
		return
	}

	writeJSON(w, http.StatusOK, evt)
}

// --- Health ---

func (d *Dashboard) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "healthy"})
}

// --- SSE ---

func (d *Dashboard) handleSSE(w http.ResponseWriter, r *http.Request) {
	d.sse.HandleSSE(w, r)
}

// --- Static ---

func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	data, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func (d *Dashboard) handleStatic(path, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFiles.ReadFile(path)
		if err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Write(data)
	}
}

// --- SSE Broadcaster ---

// SSEBroadcaster manages Server-Sent Events client connections.
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
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := make(chan string, 64)
	b.addClient(ch)
	defer b.removeClient(ch)

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

// BroadcastEvent serializes and broadcasts a WAF event to all SSE clients.
// Uses json.Marshal on the Event struct directly (which has json tags).
func (b *SSEBroadcaster) BroadcastEvent(event engine.Event) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.clients {
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
	b.clients[ch] = struct{}{}
}

func (b *SSEBroadcaster) removeClient(ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.clients, ch)
	close(ch)
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func formatFindings(findings []engine.Finding) []map[string]any {
	result := make([]map[string]any, len(findings))
	for i, f := range findings {
		result[i] = map[string]any{
			"detector":    f.DetectorName,
			"category":    f.Category,
			"severity":    f.Severity.String(),
			"score":       f.Score,
			"description": f.Description,
			"location":    f.Location,
			"confidence":  f.Confidence,
		}
	}
	return result
}
