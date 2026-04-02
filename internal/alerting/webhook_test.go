package alerting

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func testEvent(action engine.Action, score int, ip string) *engine.Event {
	return &engine.Event{
		ID:        "evt-001",
		Timestamp: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		ClientIP:  ip,
		Method:    "GET",
		Path:      "/admin",
		Action:    action,
		Score:     score,
		Findings: []engine.Finding{
			{DetectorName: "sqli", Description: "SQL injection detected", Score: 60},
		},
		UserAgent: "Mozilla/5.0",
	}
}

func TestNewManager(t *testing.T) {
	targets := []WebhookTarget{
		{Name: "hook1", URL: "http://localhost:9999", Type: "generic"},
		{Name: "hook2", URL: "http://localhost:9998", Type: "slack"},
	}
	m := NewManager(targets)
	if len(m.webhooks) != 2 {
		t.Fatalf("expected 2 webhooks, got %d", len(m.webhooks))
	}
	s := m.GetStats()
	if s.WebhookCount != 2 {
		t.Errorf("expected webhook_count=2, got %d", s.WebhookCount)
	}
	if s.Sent != 0 || s.Failed != 0 {
		t.Errorf("expected zero stats, got sent=%d failed=%d", s.Sent, s.Failed)
	}
}

func TestNewManager_DefaultCooldown(t *testing.T) {
	m := NewManager([]WebhookTarget{
		{Name: "t", URL: "http://localhost:1", Type: "generic", Cooldown: 0},
	})
	if m.webhooks[0].cooldown != 30*time.Second {
		t.Errorf("expected default cooldown 30s, got %v", m.webhooks[0].cooldown)
	}
}

func TestNewManager_CustomCooldown(t *testing.T) {
	m := NewManager([]WebhookTarget{
		{Name: "t", URL: "http://localhost:1", Type: "generic", Cooldown: 5 * time.Minute},
	})
	if m.webhooks[0].cooldown != 5*time.Minute {
		t.Errorf("expected cooldown 5m, got %v", m.webhooks[0].cooldown)
	}
}

func TestHandleEvent_GenericWebhook(t *testing.T) {
	var mu sync.Mutex
	var receivedBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json content-type")
		}
		if r.Header.Get("User-Agent") != "GuardianWAF-Alerting/1.0" {
			t.Errorf("expected GuardianWAF user-agent")
		}
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{
		{Name: "test", URL: srv.URL, Type: "generic", Events: []string{"block"}},
	})

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))

	// Wait for async send
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if receivedBody == nil {
		t.Fatal("webhook never received")
	}
	if receivedBody["action"] != "block" {
		t.Errorf("expected action=block, got %v", receivedBody["action"])
	}
	if receivedBody["client_ip"] != "1.2.3.4" {
		t.Errorf("expected client_ip=1.2.3.4, got %v", receivedBody["client_ip"])
	}

	s := m.GetStats()
	if s.Sent != 1 {
		t.Errorf("expected sent=1, got %d", s.Sent)
	}
}

func TestHandleEvent_SlackFormat(t *testing.T) {
	var mu sync.Mutex
	var receivedBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{
		{Name: "slack", URL: srv.URL, Type: "slack", Events: []string{"block"}},
	})

	m.HandleEvent(testEvent(engine.ActionBlock, 90, "10.0.0.1"))
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if receivedBody == nil {
		t.Fatal("webhook never received")
	}
	attachments, ok := receivedBody["attachments"].([]any)
	if !ok || len(attachments) == 0 {
		t.Fatal("expected slack attachments")
	}
	att := attachments[0].(map[string]any)
	if att["color"] != "#ff0000" {
		t.Errorf("expected red color for block, got %v", att["color"])
	}
}

func TestHandleEvent_DiscordFormat(t *testing.T) {
	var mu sync.Mutex
	var receivedBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{
		{Name: "discord", URL: srv.URL, Type: "discord", Events: []string{"log"}},
	})

	m.HandleEvent(testEvent(engine.ActionLog, 30, "10.0.0.2"))
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if receivedBody == nil {
		t.Fatal("webhook never received")
	}
	embeds, ok := receivedBody["embeds"].([]any)
	if !ok || len(embeds) == 0 {
		t.Fatal("expected discord embeds")
	}
	emb := embeds[0].(map[string]any)
	if emb["color"].(float64) != 0xffaa00 {
		t.Errorf("expected yellow color for log, got %v", emb["color"])
	}
}

func TestHandleEvent_EventFilter(t *testing.T) {
	called := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{
		{Name: "test", URL: srv.URL, Type: "generic", Events: []string{"block"}},
	})

	// Should NOT fire for "pass" action
	m.HandleEvent(testEvent(engine.ActionPass, 10, "1.2.3.4"))
	time.Sleep(100 * time.Millisecond)

	if called != 0 {
		t.Errorf("expected no webhook for pass event, got %d calls", called)
	}

	// Should fire for "block" action
	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	time.Sleep(100 * time.Millisecond)

	if called != 1 {
		t.Errorf("expected 1 webhook for block event, got %d calls", called)
	}
}

func TestHandleEvent_MinScore(t *testing.T) {
	called := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{
		{Name: "test", URL: srv.URL, Type: "generic", Events: []string{"block"}, MinScore: 60},
	})

	// Score below threshold — should NOT fire
	m.HandleEvent(testEvent(engine.ActionBlock, 40, "1.2.3.4"))
	time.Sleep(100 * time.Millisecond)
	if called != 0 {
		t.Errorf("expected no webhook for score 40, got %d", called)
	}

	// Score at threshold — should fire
	m.HandleEvent(testEvent(engine.ActionBlock, 60, "1.2.3.4"))
	time.Sleep(100 * time.Millisecond)
	if called != 1 {
		t.Errorf("expected 1 webhook for score 60, got %d", called)
	}
}

func TestHandleEvent_Cooldown(t *testing.T) {
	called := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{
		{Name: "test", URL: srv.URL, Type: "generic", Events: []string{"block"}, Cooldown: 5 * time.Second},
	})

	// First event fires
	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	time.Sleep(100 * time.Millisecond)

	// Second event from same IP — suppressed by cooldown
	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	time.Sleep(100 * time.Millisecond)

	if called != 1 {
		t.Errorf("expected 1 webhook (cooldown suppress), got %d", called)
	}

	// Different IP — should fire
	m.HandleEvent(testEvent(engine.ActionBlock, 80, "5.6.7.8"))
	time.Sleep(100 * time.Millisecond)

	if called != 2 {
		t.Errorf("expected 2 webhooks (different IP), got %d", called)
	}
}

func TestHandleEvent_FailedDelivery(t *testing.T) {
	m := NewManager([]WebhookTarget{
		{Name: "bad", URL: "http://127.0.0.1:1", Type: "generic", Events: []string{"block"}},
	})

	var logs []string
	m.SetLogger(func(_, msg string) { logs = append(logs, msg) })

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	time.Sleep(200 * time.Millisecond)

	s := m.GetStats()
	if s.Failed != 1 {
		t.Errorf("expected failed=1, got %d", s.Failed)
	}
	if len(logs) == 0 {
		t.Error("expected warning log for failed delivery")
	}
}

func TestHandleEvent_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{
		{Name: "err", URL: srv.URL, Type: "generic", Events: []string{"block"}},
	})

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	time.Sleep(200 * time.Millisecond)

	s := m.GetStats()
	if s.Failed != 1 {
		t.Errorf("expected failed=1 for 500 response, got %d", s.Failed)
	}
}

func TestHandleEvent_CustomHeaders(t *testing.T) {
	var mu sync.Mutex
	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{
		{
			Name:   "custom",
			URL:    srv.URL,
			Type:   "generic",
			Events: []string{"block"},
			Headers: map[string]string{
				"Authorization": "Bearer secret-token",
			},
		},
	})

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if gotAuth != "Bearer secret-token" {
		t.Errorf("expected custom auth header, got %q", gotAuth)
	}
}

func TestMatchesEvent(t *testing.T) {
	tests := []struct {
		events []string
		action string
		want   bool
	}{
		{nil, "block", true},              // default: only blocks
		{[]string{}, "block", true},       // empty: only blocks
		{[]string{"block"}, "block", true},
		{[]string{"block"}, "log", false},
		{[]string{"all"}, "log", true},
		{[]string{"all"}, "block", true},
		{[]string{"block", "log"}, "log", true},
		{[]string{"block", "log"}, "challenge", false},
	}

	for _, tt := range tests {
		got := matchesEvent(tt.events, tt.action)
		if got != tt.want {
			t.Errorf("matchesEvent(%v, %q) = %v, want %v", tt.events, tt.action, got, tt.want)
		}
	}
}

func TestHandleEvent_AllEvents(t *testing.T) {
	called := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{
		{Name: "test", URL: srv.URL, Type: "generic", Events: []string{"all"}},
	})

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.1.1.1"))
	m.HandleEvent(testEvent(engine.ActionLog, 30, "2.2.2.2"))
	m.HandleEvent(testEvent(engine.ActionChallenge, 50, "3.3.3.3"))
	m.HandleEvent(testEvent(engine.ActionPass, 5, "4.4.4.4"))
	time.Sleep(300 * time.Millisecond)

	if called != 4 {
		t.Errorf("expected 4 webhooks for 'all' events, got %d", called)
	}
}
