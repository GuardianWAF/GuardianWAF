package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ersinkoc/guardianwaf/internal/config"
	"github.com/ersinkoc/guardianwaf/internal/engine"
	"github.com/ersinkoc/guardianwaf/internal/events"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// stubEventBus satisfies engine.EventPublisher for testing.
type stubEventBus struct{}

func (s *stubEventBus) Subscribe(ch chan<- engine.Event) {}
func (s *stubEventBus) Publish(event engine.Event)       {}
func (s *stubEventBus) Close()                           {}

// stubEventStore satisfies engine.EventStorer for testing.
type stubEventStore struct{}

func (s *stubEventStore) Store(event engine.Event) error { return nil }
func (s *stubEventStore) Close() error                   { return nil }

func testConfig() *config.Config {
	return &config.Config{
		Mode:   "enforce",
		Listen: ":8080",
		WAF: config.WAFConfig{
			Sanitizer: config.SanitizerConfig{
				MaxBodySize: 1 << 20,
			},
			Detection: config.DetectionConfig{
				Threshold: config.ThresholdConfig{
					Block: 50,
					Log:   25,
				},
			},
		},
		Dashboard: config.DashboardConfig{
			Enabled: true,
			Listen:  ":9090",
		},
	}
}

func testEngine(t *testing.T) *engine.Engine {
	t.Helper()
	cfg := testConfig()
	eng, err := engine.NewEngine(cfg, &stubEventStore{}, &stubEventBus{})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	return eng
}

func testDashboard(t *testing.T, apiKey string) *Dashboard {
	t.Helper()
	eng := testEngine(t)
	store := events.NewMemoryStore(1024)
	return NewDashboard(eng, store, apiKey)
}

// ---------------------------------------------------------------------------
// API Key Auth Tests
// ---------------------------------------------------------------------------

func TestAuthMiddleware_NoKey(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with no auth, got %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_ValidKey(t *testing.T) {
	apiKey := "test-secret-key-123"
	d := testDashboard(t, apiKey)
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/health", nil)
	req.Header.Set("X-GuardianWAF-Key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with valid key, got %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_InvalidKey(t *testing.T) {
	apiKey := "test-secret-key-123"
	d := testDashboard(t, apiKey)
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/health", nil)
	req.Header.Set("X-GuardianWAF-Key", "wrong-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong key, got %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_QueryParamKey(t *testing.T) {
	apiKey := "test-secret-key-123"
	d := testDashboard(t, apiKey)
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/health?api_key=" + apiKey)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with query param key, got %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_MissingKey(t *testing.T) {
	apiKey := "test-secret-key-123"
	d := testDashboard(t, apiKey)
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with missing key, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Stats Endpoint
// ---------------------------------------------------------------------------

func TestGetStats(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	for _, field := range []string{"total_requests", "blocked_requests", "logged_requests", "passed_requests", "avg_latency_us"} {
		if _, ok := data[field]; !ok {
			t.Errorf("missing expected field %q in stats response", field)
		}
	}
}

// ---------------------------------------------------------------------------
// Events Endpoints
// ---------------------------------------------------------------------------

func TestGetEvents(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if _, ok := data["events"]; !ok {
		t.Error("missing 'events' field")
	}
	if _, ok := data["total"]; !ok {
		t.Error("missing 'total' field")
	}
}

func TestGetEvents_Pagination(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/events?limit=5&offset=0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	limit, ok := data["limit"]
	if !ok {
		t.Fatal("missing 'limit' in response")
	}
	if int(limit.(float64)) != 5 {
		t.Errorf("expected limit 5, got %v", limit)
	}
}

func TestGetEvent_NotFound(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/events/nonexistent-id")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Health Endpoint
// ---------------------------------------------------------------------------

func TestHealth(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatal(err)
	}
	if data["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %v", data["status"])
	}
}

// ---------------------------------------------------------------------------
// Version Endpoint
// ---------------------------------------------------------------------------

func TestVersion(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/version")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatal(err)
	}
	if data["version"] != Version {
		t.Errorf("expected version %q, got %v", Version, data["version"])
	}
	if data["name"] != "GuardianWAF" {
		t.Errorf("expected name 'GuardianWAF', got %v", data["name"])
	}
}

// ---------------------------------------------------------------------------
// SSE Endpoint
// ---------------------------------------------------------------------------

func TestSSEEndpoint(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	// Just check it returns the SSE content-type and starts streaming
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/sse", nil)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if ct != "text/event-stream" {
		t.Errorf("expected Content-Type text/event-stream, got %q", ct)
	}

	// Read the initial connection message
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	data := string(buf[:n])
	if !strings.Contains(data, "connected") {
		t.Errorf("expected initial 'connected' event, got %q", data)
	}
}

// ---------------------------------------------------------------------------
// Static File Serving
// ---------------------------------------------------------------------------

func TestServeIndex(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html, got %q", ct)
	}
}

func TestServeJS(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/app.js")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "javascript") {
		t.Errorf("expected javascript content type, got %q", ct)
	}
}

func TestServeCSS(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/style.css")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "css") {
		t.Errorf("expected css content type, got %q", ct)
	}
}

func TestServe404(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// GenerateAPIKey
// ---------------------------------------------------------------------------

func TestGenerateAPIKey(t *testing.T) {
	key := GenerateAPIKey()
	if len(key) != 64 {
		t.Fatalf("expected 64-char hex string, got %d chars: %q", len(key), key)
	}

	// Ensure it's valid hex
	for _, c := range key {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("invalid hex character %q in key %q", string(c), key)
		}
	}

	// Keys should be unique
	key2 := GenerateAPIKey()
	if key == key2 {
		t.Fatal("two generated keys should not be equal")
	}
}

// ---------------------------------------------------------------------------
// SSE Broadcaster
// ---------------------------------------------------------------------------

func TestSSEBroadcasterClientCount(t *testing.T) {
	b := NewSSEBroadcaster()
	if b.ClientCount() != 0 {
		t.Fatalf("expected 0 clients, got %d", b.ClientCount())
	}

	ch := make(chan string, 64)
	b.addClient(ch)
	if b.ClientCount() != 1 {
		t.Fatalf("expected 1 client, got %d", b.ClientCount())
	}

	b.removeClient(ch)
	if b.ClientCount() != 0 {
		t.Fatalf("expected 0 clients after remove, got %d", b.ClientCount())
	}
}

func TestSSEBroadcasterBroadcast(t *testing.T) {
	b := NewSSEBroadcaster()

	ch1 := make(chan string, 64)
	ch2 := make(chan string, 64)
	b.addClient(ch1)
	b.addClient(ch2)

	b.Broadcast("test", `{"hello":"world"}`)

	msg1 := <-ch1
	msg2 := <-ch2

	if !strings.Contains(msg1, "test") {
		t.Errorf("ch1 message missing event type: %q", msg1)
	}
	if !strings.Contains(msg2, "hello") {
		t.Errorf("ch2 message missing data: %q", msg2)
	}

	b.removeClient(ch1)
	b.removeClient(ch2)
}

// ---------------------------------------------------------------------------
// Whitelist CRUD
// ---------------------------------------------------------------------------

func TestWhitelistCRUD(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	// List (empty)
	resp, err := http.Get(ts.URL + "/api/v1/rules/whitelist")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", resp.StatusCode)
	}

	// Add
	body := strings.NewReader(`{"value":"192.168.1.0/24","reason":"internal"}`)
	resp, err = http.Post(ts.URL+"/api/v1/rules/whitelist", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	var entry RuleEntry
	json.NewDecoder(resp.Body).Decode(&entry)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add: expected 201, got %d", resp.StatusCode)
	}
	if entry.ID == "" {
		t.Fatal("add: expected non-empty ID")
	}

	// Delete
	req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/rules/whitelist/"+entry.ID, nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d", resp.StatusCode)
	}

	// Delete non-existent
	req, _ = http.NewRequest("DELETE", ts.URL+"/api/v1/rules/whitelist/999", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("delete non-existent: expected 404, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Config Endpoints
// ---------------------------------------------------------------------------

func TestGetConfig(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/config")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestReloadConfig(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/config/reload", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
