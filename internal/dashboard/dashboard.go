// Package dashboard provides the web dashboard and REST API for GuardianWAF.
package dashboard

import (
	"embed"
	"net/http"

	"github.com/ersinkoc/guardianwaf/internal/engine"
	"github.com/ersinkoc/guardianwaf/internal/events"
)

//go:embed static/index.html static/style.css static/app.js
var staticFiles embed.FS

// Dashboard is the web dashboard server that wires together the API,
// SSE broadcaster, authentication, and static file serving.
type Dashboard struct {
	api    *API
	sse    *SSEBroadcaster
	mux    *http.ServeMux
	apiKey string
}

// NewDashboard creates a new Dashboard wired to the given engine and event store.
// If apiKey is non-empty, all /api/ routes require authentication.
func NewDashboard(eng *engine.Engine, store events.EventStore, apiKey string) *Dashboard {
	d := &Dashboard{
		api:    NewAPI(eng, store),
		sse:    NewSSEBroadcaster(),
		mux:    http.NewServeMux(),
		apiKey: apiKey,
	}

	// Register API routes (protected by auth)
	apiMux := http.NewServeMux()
	d.api.RegisterRoutes(apiMux)
	d.mux.Handle("/api/", AuthMiddleware(apiKey, apiMux))

	// SSE endpoint (separate so it can optionally bypass auth)
	d.mux.HandleFunc("/api/v1/sse", d.sse.HandleSSE)

	// Static files
	d.mux.HandleFunc("/", d.handleIndex)
	d.mux.HandleFunc("/app.js", d.handleJS)
	d.mux.HandleFunc("/style.css", d.handleCSS)

	return d
}

// Handler returns the root http.Handler for the dashboard.
func (d *Dashboard) Handler() http.Handler {
	return d.mux
}

// SSE returns the SSE broadcaster for publishing events externally.
func (d *Dashboard) SSE() *SSEBroadcaster {
	return d.sse
}

// API returns the API instance.
func (d *Dashboard) API() *API {
	return d.api
}

// handleIndex serves the main HTML page.
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

// handleJS serves the JavaScript bundle.
func (d *Dashboard) handleJS(w http.ResponseWriter, r *http.Request) {
	data, err := staticFiles.ReadFile("static/app.js")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Write(data)
}

// handleCSS serves the stylesheet.
func (d *Dashboard) handleCSS(w http.ResponseWriter, r *http.Request) {
	data, err := staticFiles.ReadFile("static/style.css")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Write(data)
}
