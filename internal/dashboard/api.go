package dashboard

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ersinkoc/guardianwaf/internal/engine"
	"github.com/ersinkoc/guardianwaf/internal/events"
)

// Version is the current GuardianWAF version reported by the API.
const Version = "0.1.0"

// API holds the REST API handlers for the dashboard.
type API struct {
	engine     *engine.Engine
	eventStore events.EventStore

	// In-memory rule storage
	mu         sync.RWMutex
	whitelist  []RuleEntry
	blacklist  []RuleEntry
	rateLimits []RateLimitEntry
	exclusions []ExclusionEntry
	nextID     int
}

// RuleEntry is a whitelist or blacklist entry.
type RuleEntry struct {
	ID        string `json:"id"`
	Value     string `json:"value"`
	Reason    string `json:"reason,omitempty"`
	CreatedAt string `json:"created_at"`
}

// RateLimitEntry is a rate limit rule entry.
type RateLimitEntry struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	Limit  int    `json:"limit"`
	Window string `json:"window"`
	Action string `json:"action"`
}

// ExclusionEntry is a detection exclusion entry.
type ExclusionEntry struct {
	ID        string   `json:"id"`
	Path      string   `json:"path"`
	Detectors []string `json:"detectors"`
	Reason    string   `json:"reason,omitempty"`
}

// NewAPI creates a new API instance.
func NewAPI(eng *engine.Engine, store events.EventStore) *API {
	return &API{
		engine:     eng,
		eventStore: store,
		nextID:     1,
	}
}

// RegisterRoutes registers all API routes on the given mux.
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/stats", a.handleGetStats)
	mux.HandleFunc("GET /api/v1/events", a.handleGetEvents)
	mux.HandleFunc("GET /api/v1/events/{id}", a.handleGetEvent)
	mux.HandleFunc("GET /api/v1/health", a.handleHealth)
	mux.HandleFunc("GET /api/v1/version", a.handleVersion)
	mux.HandleFunc("GET /api/v1/config", a.handleGetConfig)
	mux.HandleFunc("PUT /api/v1/config", a.handleUpdateConfig)
	mux.HandleFunc("POST /api/v1/config/reload", a.handleReloadConfig)

	// Whitelist CRUD
	mux.HandleFunc("GET /api/v1/rules/whitelist", a.handleListWhitelist)
	mux.HandleFunc("POST /api/v1/rules/whitelist", a.handleAddWhitelist)
	mux.HandleFunc("DELETE /api/v1/rules/whitelist/{id}", a.handleRemoveWhitelist)

	// Blacklist CRUD
	mux.HandleFunc("GET /api/v1/rules/blacklist", a.handleListBlacklist)
	mux.HandleFunc("POST /api/v1/rules/blacklist", a.handleAddBlacklist)
	mux.HandleFunc("DELETE /api/v1/rules/blacklist/{id}", a.handleRemoveBlacklist)

	// Rate limit CRUD
	mux.HandleFunc("GET /api/v1/rules/ratelimit", a.handleListRateLimit)
	mux.HandleFunc("POST /api/v1/rules/ratelimit", a.handleAddRateLimit)
	mux.HandleFunc("DELETE /api/v1/rules/ratelimit/{id}", a.handleRemoveRateLimit)

	// Exclusions CRUD
	mux.HandleFunc("GET /api/v1/rules/exclusions", a.handleListExclusions)
	mux.HandleFunc("POST /api/v1/rules/exclusions", a.handleAddExclusion)
	mux.HandleFunc("DELETE /api/v1/rules/exclusions/{id}", a.handleRemoveExclusion)
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func (a *API) allocID() string {
	id := strconv.Itoa(a.nextID)
	a.nextID++
	return id
}

// ---------------------------------------------------------------------------
// Stats / Health / Version
// ---------------------------------------------------------------------------

func (a *API) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats := a.engine.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"total_requests":   stats.TotalRequests,
		"blocked_requests": stats.BlockedRequests,
		"logged_requests":  stats.LoggedRequests,
		"passed_requests":  stats.PassedRequests,
		"avg_latency_us":   stats.AvgLatencyUs,
	})
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "healthy",
		"uptime": time.Since(time.Time{}).String(),
	})
}

func (a *API) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":    Version,
		"go_version": "go1.23",
		"name":       "GuardianWAF",
	})
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

func (a *API) handleGetEvents(w http.ResponseWriter, r *http.Request) {
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

	evts, total, err := a.eventStore.Query(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events": evts,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (a *API) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "Missing event ID")
		return
	}

	evt, err := a.eventStore.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Event not found")
		return
	}

	writeJSON(w, http.StatusOK, evt)
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

func (a *API) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg := a.engine.Config()
	writeJSON(w, http.StatusOK, cfg)
}

func (a *API) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	// For safety, only allow updating select fields via a partial config
	var updates map[string]any
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Invalid JSON body")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Configuration update received",
		"updates": updates,
	})
}

func (a *API) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	cfg := a.engine.Config()
	if err := a.engine.Reload(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "reload_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Configuration reloaded successfully",
	})
}

// ---------------------------------------------------------------------------
// Whitelist CRUD
// ---------------------------------------------------------------------------

func (a *API) handleListWhitelist(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	list := a.whitelist
	if list == nil {
		list = []RuleEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": list})
}

func (a *API) handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	var entry RuleEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Invalid JSON body")
		return
	}
	if entry.Value == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "Missing 'value' field")
		return
	}

	a.mu.Lock()
	entry.ID = a.allocID()
	entry.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	a.whitelist = append(a.whitelist, entry)
	a.mu.Unlock()

	writeJSON(w, http.StatusCreated, entry)
}

func (a *API) handleRemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.mu.Lock()
	defer a.mu.Unlock()

	for i, e := range a.whitelist {
		if e.ID == id {
			a.whitelist = append(a.whitelist[:i], a.whitelist[i+1:]...)
			writeJSON(w, http.StatusOK, map[string]any{"message": "Removed"})
			return
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "Whitelist entry not found")
}

// ---------------------------------------------------------------------------
// Blacklist CRUD
// ---------------------------------------------------------------------------

func (a *API) handleListBlacklist(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	list := a.blacklist
	if list == nil {
		list = []RuleEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": list})
}

func (a *API) handleAddBlacklist(w http.ResponseWriter, r *http.Request) {
	var entry RuleEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Invalid JSON body")
		return
	}
	if entry.Value == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "Missing 'value' field")
		return
	}

	a.mu.Lock()
	entry.ID = a.allocID()
	entry.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	a.blacklist = append(a.blacklist, entry)
	a.mu.Unlock()

	writeJSON(w, http.StatusCreated, entry)
}

func (a *API) handleRemoveBlacklist(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.mu.Lock()
	defer a.mu.Unlock()

	for i, e := range a.blacklist {
		if e.ID == id {
			a.blacklist = append(a.blacklist[:i], a.blacklist[i+1:]...)
			writeJSON(w, http.StatusOK, map[string]any{"message": "Removed"})
			return
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "Blacklist entry not found")
}

// ---------------------------------------------------------------------------
// Rate Limit CRUD
// ---------------------------------------------------------------------------

func (a *API) handleListRateLimit(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	list := a.rateLimits
	if list == nil {
		list = []RateLimitEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": list})
}

func (a *API) handleAddRateLimit(w http.ResponseWriter, r *http.Request) {
	var entry RateLimitEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Invalid JSON body")
		return
	}
	if entry.Limit <= 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "Limit must be positive")
		return
	}

	a.mu.Lock()
	entry.ID = a.allocID()
	a.rateLimits = append(a.rateLimits, entry)
	a.mu.Unlock()

	writeJSON(w, http.StatusCreated, entry)
}

func (a *API) handleRemoveRateLimit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.mu.Lock()
	defer a.mu.Unlock()

	for i, e := range a.rateLimits {
		if e.ID == id {
			a.rateLimits = append(a.rateLimits[:i], a.rateLimits[i+1:]...)
			writeJSON(w, http.StatusOK, map[string]any{"message": "Removed"})
			return
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "Rate limit entry not found")
}

// ---------------------------------------------------------------------------
// Exclusions CRUD
// ---------------------------------------------------------------------------

func (a *API) handleListExclusions(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	list := a.exclusions
	if list == nil {
		list = []ExclusionEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": list})
}

func (a *API) handleAddExclusion(w http.ResponseWriter, r *http.Request) {
	var entry ExclusionEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Invalid JSON body")
		return
	}
	if entry.Path == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "Missing 'path' field")
		return
	}

	a.mu.Lock()
	entry.ID = a.allocID()
	a.exclusions = append(a.exclusions, entry)
	a.mu.Unlock()

	writeJSON(w, http.StatusCreated, entry)
}

func (a *API) handleRemoveExclusion(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.mu.Lock()
	defer a.mu.Unlock()

	for i, e := range a.exclusions {
		if e.ID == id {
			a.exclusions = append(a.exclusions[:i], a.exclusions[i+1:]...)
			writeJSON(w, http.StatusOK, map[string]any{"message": "Removed"})
			return
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "Exclusion entry not found")
}

// actionString converts engine.Action to its API string representation.
func actionString(a engine.Action) string {
	return strings.ToLower(a.String())
}
