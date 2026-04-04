package alerting

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- Slack Payload Coverage ---

func TestSlackPayload_BlockAction(t *testing.T) {
	a := &Alert{
		Action:    "block",
		ClientIP:  "1.2.3.4",
		Method:    "POST",
		Path:      "/login",
		Score:     85,
		Findings:  []string{"SQL injection detected", "Known attack IP"},
		Timestamp: "2025-01-15T10:30:00Z",
	}

	payload := slackPayload(a)
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal slack payload: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	attachments := parsed["attachments"].([]any)
	att := attachments[0].(map[string]any)
	if att["color"] != "#ff0000" {
		t.Errorf("expected red for block, got %v", att["color"])
	}
}

func TestSlackPayload_LogAction(t *testing.T) {
	a := &Alert{
		Action:   "log",
		ClientIP: "5.6.7.8",
		Method:   "GET",
		Path:     "/api",
		Score:    30,
		Findings: []string{"suspicious pattern"},
	}
	payload := slackPayload(a)
	data, _ := json.Marshal(payload)
	var parsed map[string]any
	json.Unmarshal(data, &parsed)
	attachments := parsed["attachments"].([]any)
	att := attachments[0].(map[string]any)
	if att["color"] != "#ffaa00" {
		t.Errorf("expected yellow for log, got %v", att["color"])
	}
}

func TestSlackPayload_ChallengeAction(t *testing.T) {
	a := &Alert{
		Action:   "challenge",
		ClientIP: "9.8.7.6",
		Method:   "GET",
		Path:     "/page",
		Score:    50,
		Findings: []string{"bot detected"},
	}
	payload := slackPayload(a)
	data, _ := json.Marshal(payload)
	var parsed map[string]any
	json.Unmarshal(data, &parsed)
	attachments := parsed["attachments"].([]any)
	att := attachments[0].(map[string]any)
	if att["color"] != "#0066ff" {
		t.Errorf("expected blue for challenge, got %v", att["color"])
	}
}

func TestSlackPayload_NoFindings(t *testing.T) {
	a := &Alert{
		Action:   "block",
		ClientIP: "1.2.3.4",
		Method:   "POST",
		Path:     "/admin",
		Score:    90,
		Findings: []string{},
	}
	payload := slackPayload(a)
	data, _ := json.Marshal(payload)
	var parsed map[string]any
	json.Unmarshal(data, &parsed)
	attachments := parsed["attachments"].([]any)
	att := attachments[0].(map[string]any)
	fields := att["fields"].([]any)
	findingsField := fields[len(fields)-1].(map[string]any)
	if findingsField["value"] != "No specific findings" {
		t.Errorf("expected 'No specific findings', got %v", findingsField["value"])
	}
}

// --- Discord Payload Coverage ---

func TestDiscordPayload_BlockAction(t *testing.T) {
	a := &Alert{
		Action:    "block",
		ClientIP:  "1.2.3.4",
		Method:    "POST",
		Path:      "/login",
		Score:     85,
		Findings:  []string{"SQL injection detected"},
		Timestamp: "2025-01-15T10:30:00Z",
	}

	payload := discordPayload(a)
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal discord payload: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	embeds := parsed["embeds"].([]any)
	emb := embeds[0].(map[string]any)
	color, ok := emb["color"].(float64)
	if !ok || color != 0xff0000 {
		t.Errorf("expected red (0xff0000) for block, got %v", emb["color"])
	}
}

func TestDiscordPayload_LogAction(t *testing.T) {
	a := &Alert{Action: "log", ClientIP: "5.6.7.8", Score: 30, Findings: []string{"test"}}
	payload := discordPayload(a)
	data, _ := json.Marshal(payload)
	var parsed map[string]any
	json.Unmarshal(data, &parsed)
	embeds := parsed["embeds"].([]any)
	emb := embeds[0].(map[string]any)
	color := emb["color"].(float64)
	if color != 0xffaa00 {
		t.Errorf("expected yellow for log, got %v", color)
	}
}

func TestDiscordPayload_ChallengeAction(t *testing.T) {
	a := &Alert{Action: "challenge", ClientIP: "9.8.7.6", Score: 50, Findings: []string{"test"}}
	payload := discordPayload(a)
	data, _ := json.Marshal(payload)
	var parsed map[string]any
	json.Unmarshal(data, &parsed)
	embeds := parsed["embeds"].([]any)
	emb := embeds[0].(map[string]any)
	color := emb["color"].(float64)
	if color != 0x0066ff {
		t.Errorf("expected blue for challenge, got %v", color)
	}
}

func TestDiscordPayload_NoFindings(t *testing.T) {
	a := &Alert{Action: "block", ClientIP: "1.2.3.4", Score: 80, Findings: nil}
	payload := discordPayload(a)
	data, _ := json.Marshal(payload)
	var parsed map[string]any
	json.Unmarshal(data, &parsed)
	embeds := parsed["embeds"].([]any)
	emb := embeds[0].(map[string]any)
	fields := emb["fields"].([]any)
	findingsField := fields[len(fields)-1].(map[string]any)
	if findingsField["value"] != "No specific findings" {
		t.Errorf("expected 'No specific findings', got %v", findingsField["value"])
	}
}

// --- send with different types ---

func TestSend_SlackType(t *testing.T) {
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
		{Name: "slack-test", URL: srv.URL, Type: "slack", Events: []string{"block"}},
	})

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if receivedBody == nil {
		t.Fatal("expected slack payload")
	}
	if _, ok := receivedBody["attachments"]; !ok {
		t.Error("expected attachments in slack payload")
	}
}

func TestSend_DiscordType(t *testing.T) {
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
		{Name: "discord-test", URL: srv.URL, Type: "discord", Events: []string{"block"}},
	})

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if receivedBody == nil {
		t.Fatal("expected discord payload")
	}
	if _, ok := receivedBody["embeds"]; !ok {
		t.Error("expected embeds in discord payload")
	}
}

// --- matchesEvent additional coverage ---

func TestMatchesEvent_ChallengeWithBlockOnly(t *testing.T) {
	if matchesEvent([]string{"block"}, "challenge") {
		t.Error("challenge should not match block-only events")
	}
}

func TestMatchesEvent_DefaultLog(t *testing.T) {
	// Default (nil events) only matches block
	if matchesEvent(nil, "log") {
		t.Error("log should not match default events")
	}
}

// --- send: HTTP error paths ---

func TestSend_HTTPError(t *testing.T) {
	m := NewManager([]WebhookTarget{
		{Name: "fail", URL: "http://127.0.0.1:1/unreachable", Type: "generic", Events: []string{"block"}},
	})
	m.SetLogger(func(level, msg string) {})

	m.HandleEvent(testEvent(engine.ActionBlock, 85, "1.2.3.4"))
	time.Sleep(300 * time.Millisecond)

	stats := m.GetStats()
	if stats.Failed != 1 {
		t.Errorf("expected 1 failed send, got %d", stats.Failed)
	}
}

func TestSend_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{
		{Name: "err500", URL: srv.URL, Type: "generic", Events: []string{"block"}},
	})
	m.SetLogger(func(level, msg string) {})

	m.HandleEvent(testEvent(engine.ActionBlock, 85, "1.2.3.4"))
	time.Sleep(300 * time.Millisecond)

	stats := m.GetStats()
	if stats.Failed != 1 {
		t.Errorf("expected 1 failed (500), got %d", stats.Failed)
	}
	if stats.Sent != 0 {
		t.Errorf("expected 0 sent, got %d", stats.Sent)
	}
}

func TestSend_Server4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{
		{Name: "err403", URL: srv.URL, Type: "generic", Events: []string{"block"}},
	})
	m.SetLogger(func(level, msg string) {})

	m.HandleEvent(testEvent(engine.ActionBlock, 85, "1.2.3.4"))
	time.Sleep(300 * time.Millisecond)

	stats := m.GetStats()
	if stats.Failed != 1 {
		t.Errorf("expected 1 failed (403), got %d", stats.Failed)
	}
}

func TestSend_CustomHeaders(t *testing.T) {
	var receivedHeaders http.Header
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedHeaders = r.Header.Clone()
		mu.Unlock()
		wg.Done()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{
		{
			Name:    "custom",
			URL:     srv.URL,
			Type:    "generic",
			Events:  []string{"block"},
			Headers: map[string]string{"X-Custom-Auth": "Bearer test-token", "X-Extra": "value"},
		},
	})

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if receivedHeaders.Get("X-Custom-Auth") != "Bearer test-token" {
		t.Errorf("expected custom auth header, got %q", receivedHeaders.Get("X-Custom-Auth"))
	}
	if receivedHeaders.Get("X-Extra") != "value" {
		t.Errorf("expected X-Extra header, got %q", receivedHeaders.Get("X-Extra"))
	}
}

func TestSend_GenericType(t *testing.T) {
	var receivedBody map[string]any
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		wg.Done()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{
		{Name: "generic-test", URL: srv.URL, Type: "generic", Events: []string{"block"}},
	})

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "5.6.7.8"))
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if receivedBody == nil {
		t.Fatal("expected generic payload")
	}
	if receivedBody["action"] != "block" {
		t.Errorf("expected action=block, got %v", receivedBody["action"])
	}
	if receivedBody["client_ip"] != "5.6.7.8" {
		t.Errorf("expected client_ip=5.6.7.8, got %v", receivedBody["client_ip"])
	}
}

func TestSend_BadURL(t *testing.T) {
	m := NewManager([]WebhookTarget{
		{Name: "badurl", URL: "http://\x00invalid", Type: "generic", Events: []string{"block"}},
	})
	m.SetLogger(func(level, msg string) {})

	m.HandleEvent(testEvent(engine.ActionBlock, 85, "1.2.3.4"))
	time.Sleep(300 * time.Millisecond)

	stats := m.GetStats()
	if stats.Failed != 1 {
		t.Errorf("expected 1 failed send, got %d", stats.Failed)
	}
}

func TestMatchesEvent_DefaultBlock(t *testing.T) {
	if !matchesEvent(nil, "block") {
		t.Error("default (nil) events should match 'block'")
	}
}

// --- MCP Alerting Management Tests ---

func TestAddWebhook(t *testing.T) {
	m := NewManager([]WebhookTarget{})

	m.AddWebhook(WebhookTarget{
		Name:     "new-webhook",
		URL:      "http://example.com/webhook",
		Type:     "generic",
		Events:   []string{"block"},
		Cooldown: 30 * time.Second,
	})

	stats := m.GetStats()
	if stats.WebhookCount != 1 {
		t.Errorf("expected 1 webhook, got %d", stats.WebhookCount)
	}
}

func TestAddWebhook_DefaultCooldown(t *testing.T) {
	m := NewManager([]WebhookTarget{})

	m.AddWebhook(WebhookTarget{
		Name:     "no-cooldown",
		URL:      "http://example.com/webhook",
		Type:     "generic",
		Events:   []string{"block"},
		Cooldown: 0,
	})

	stats := m.GetStats()
	if stats.WebhookCount != 1 {
		t.Errorf("expected 1 webhook, got %d", stats.WebhookCount)
	}
}

func TestRemoveWebhook(t *testing.T) {
	m := NewManager([]WebhookTarget{
		{Name: "to-remove", URL: "http://example.com", Type: "generic"},
		{Name: "keep", URL: "http://keep.com", Type: "generic"},
	})

	if !m.RemoveWebhook("to-remove") {
		t.Error("expected RemoveWebhook to return true")
	}

	stats := m.GetStats()
	if stats.WebhookCount != 1 {
		t.Errorf("expected 1 webhook after removal, got %d", stats.WebhookCount)
	}
}

func TestRemoveWebhook_NotFound(t *testing.T) {
	m := NewManager([]WebhookTarget{
		{Name: "existing", URL: "http://example.com", Type: "generic"},
	})

	if m.RemoveWebhook("nonexistent") {
		t.Error("expected RemoveWebhook to return false for nonexistent webhook")
	}

	stats := m.GetStats()
	if stats.WebhookCount != 1 {
		t.Errorf("expected 1 webhook, got %d", stats.WebhookCount)
	}
}

func TestRemoveWebhook_Empty(t *testing.T) {
	m := NewManager([]WebhookTarget{})

	if m.RemoveWebhook("anything") {
		t.Error("expected RemoveWebhook to return false for empty manager")
	}
}

func TestAddEmailTarget(t *testing.T) {
	m := NewManager([]WebhookTarget{})

	m.AddEmailTarget(config.EmailConfig{
		Name:     "test-email",
		SMTPHost: "smtp.example.com",
		SMTPPort: 587,
		From:     "alerts@example.com",
		To:       []string{"admin@example.com"},
	})

	stats := m.GetStats()
	if stats.EmailCount != 1 {
		t.Errorf("expected 1 email target, got %d", stats.EmailCount)
	}
}

func TestAddEmailTarget_Invalid(t *testing.T) {
	m := NewManager([]WebhookTarget{})

	// Should not add - missing SMTPHost
	m.AddEmailTarget(config.EmailConfig{
		Name: "invalid",
		To:   []string{"admin@example.com"},
	})

	stats := m.GetStats()
	if stats.EmailCount != 0 {
		t.Errorf("expected 0 email targets for invalid config, got %d", stats.EmailCount)
	}

	// Should not add - missing To
	m.AddEmailTarget(config.EmailConfig{
		Name:     "invalid",
		SMTPHost: "smtp.example.com",
	})

	stats = m.GetStats()
	if stats.EmailCount != 0 {
		t.Errorf("expected 0 email targets for missing To, got %d", stats.EmailCount)
	}
}

func TestRemoveEmailTarget(t *testing.T) {
	m := NewManager([]WebhookTarget{})
	m.AddEmailTarget(config.EmailConfig{
		Name:     "to-remove",
		SMTPHost: "smtp.example.com",
		SMTPPort: 587,
		From:     "alerts@example.com",
		To:       []string{"admin@example.com"},
	})

	if !m.RemoveEmailTarget("to-remove") {
		t.Error("expected RemoveEmailTarget to return true")
	}

	stats := m.GetStats()
	if stats.EmailCount != 0 {
		t.Errorf("expected 0 email targets after removal, got %d", stats.EmailCount)
	}
}

func TestRemoveEmailTarget_NotFound(t *testing.T) {
	m := NewManager([]WebhookTarget{})
	m.AddEmailTarget(config.EmailConfig{
		Name:     "existing",
		SMTPHost: "smtp.example.com",
		SMTPPort: 587,
		From:     "alerts@example.com",
		To:       []string{"admin@example.com"},
	})

	if m.RemoveEmailTarget("nonexistent") {
		t.Error("expected RemoveEmailTarget to return false for nonexistent target")
	}

	stats := m.GetStats()
	if stats.EmailCount != 1 {
		t.Errorf("expected 1 email target, got %d", stats.EmailCount)
	}
}

func TestTestAlert_WebhookTarget(t *testing.T) {
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
		{Name: "test-target", URL: srv.URL, Type: "generic", Events: []string{"block"}},
	})

	err := m.TestAlert("test-target")
	if err != nil {
		t.Fatalf("TestAlert failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if receivedBody == nil {
		t.Fatal("expected webhook to receive test alert")
	}
	if receivedBody["action"] != "block" {
		t.Errorf("expected action=block, got %v", receivedBody["action"])
	}
}

func TestTestAlert_TargetNotFound(t *testing.T) {
	m := NewManager([]WebhookTarget{})

	err := m.TestAlert("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent target")
	}
	if err.Error() != "target nonexistent not found" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPagerDutyPayload(t *testing.T) {
	a := &Alert{
		Action:    "block",
		ClientIP:  "192.168.1.1",
		Method:    "POST",
		Path:      "/admin",
		Score:     95,
		Findings:  []string{"SQL injection"},
		Timestamp: "2025-01-15T10:30:00Z",
		EventID:   "evt-123",
		UserAgent: "TestAgent/1.0",
	}

	payload := pagerdutyPayload(a)

	if payload["event_action"] != "trigger" {
		t.Errorf("expected event_action=trigger, got %v", payload["event_action"])
	}

	p := payload["payload"].(map[string]any)
	if p["severity"] != "critical" {
		t.Errorf("expected severity=critical for block action, got %v", p["severity"])
	}
	if p["source"] != "192.168.1.1" {
		t.Errorf("expected source=192.168.1.1, got %v", p["source"])
	}
}

func TestPagerDutyPayload_Challenge(t *testing.T) {
	a := &Alert{
		Action:    "challenge",
		ClientIP:  "10.0.0.1",
		Method:    "GET",
		Path:      "/api",
		Score:     60,
		Timestamp: "2025-01-15T10:30:00Z",
	}

	payload := pagerdutyPayload(a)
	p := payload["payload"].(map[string]any)

	if p["severity"] != "warning" {
		t.Errorf("expected severity=warning for challenge action, got %v", p["severity"])
	}
}

func TestPagerDutyPayload_Log(t *testing.T) {
	a := &Alert{
		Action:    "log",
		ClientIP:  "10.0.0.1",
		Method:    "GET",
		Path:      "/health",
		Score:     30,
		Timestamp: "2025-01-15T10:30:00Z",
	}

	payload := pagerdutyPayload(a)
	p := payload["payload"].(map[string]any)

	if p["severity"] != "info" {
		t.Errorf("expected severity=info for log action, got %v", p["severity"])
	}
}

