package alerting

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	config := DefaultConfig()
	mgr := NewManager(config)

	if mgr == nil {
		t.Fatal("expected manager to be created")
	}

	if !mgr.config.Enabled {
		t.Error("expected alerting to be enabled by default")
	}
}

func TestAddWebhook(t *testing.T) {
	mgr := NewManager(DefaultConfig())

	tests := []struct {
		name    string
		webhook *WebhookTarget
		wantErr bool
	}{
		{
			name: "valid webhook",
			webhook: &WebhookTarget{
				Name:     "test-webhook",
				URL:      "https://example.com/webhook",
				Type:     "generic",
				Events:   []string{"block"},
				MinScore: 50,
				Cooldown: "30s",
			},
			wantErr: false,
		},
		{
			name: "missing name",
			webhook: &WebhookTarget{
				URL: "https://example.com/webhook",
			},
			wantErr: true,
		},
		{
			name: "missing url",
			webhook: &WebhookTarget{
				Name: "test-webhook",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.AddWebhook(tt.webhook)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddWebhook() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRemoveWebhook(t *testing.T) {
	mgr := NewManager(DefaultConfig())

	webhook := &WebhookTarget{
		Name: "test-webhook",
		URL:  "https://example.com/webhook",
	}

	mgr.AddWebhook(webhook)

	err := mgr.RemoveWebhook("test-webhook")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	// Try to remove again
	err = mgr.RemoveWebhook("test-webhook")
	if err == nil {
		t.Error("expected error when removing non-existent webhook")
	}
}

func TestGetWebhooks(t *testing.T) {
	mgr := NewManager(DefaultConfig())

	mgr.AddWebhook(&WebhookTarget{
		Name: "webhook-1",
		URL:  "https://example.com/1",
	})
	mgr.AddWebhook(&WebhookTarget{
		Name: "webhook-2",
		URL:  "https://example.com/2",
	})

	webhooks := mgr.GetWebhooks()
	if len(webhooks) != 2 {
		t.Errorf("expected 2 webhooks, got %d", len(webhooks))
	}
}

func TestAddEmail(t *testing.T) {
	mgr := NewManager(DefaultConfig())

	tests := []struct {
		name    string
		email   *EmailTarget
		wantErr bool
	}{
		{
			name: "valid email",
			email: &EmailTarget{
				Name:     "test-email",
				SMTPHost: "smtp.gmail.com",
				SMTPPort: 587,
				From:     "alerts@example.com",
				To:       []string{"admin@example.com"},
				Events:   []string{"block"},
				MinScore: 50,
				Cooldown: "5m",
			},
			wantErr: false,
		},
		{
			name: "missing name",
			email: &EmailTarget{
				SMTPHost: "smtp.gmail.com",
				From:     "alerts@example.com",
				To:       []string{"admin@example.com"},
			},
			wantErr: true,
		},
		{
			name: "missing smtp host",
			email: &EmailTarget{
				Name: "test-email",
				From: "alerts@example.com",
				To:   []string{"admin@example.com"},
			},
			wantErr: true,
		},
		{
			name: "missing to addresses",
			email: &EmailTarget{
				Name:     "test-email",
				SMTPHost: "smtp.gmail.com",
				From:     "alerts@example.com",
				To:       []string{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.AddEmail(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddEmail() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRemoveEmail(t *testing.T) {
	mgr := NewManager(DefaultConfig())

	email := &EmailTarget{
		Name:     "test-email",
		SMTPHost: "smtp.gmail.com",
		SMTPPort: 587,
		From:     "alerts@example.com",
		To:       []string{"admin@example.com"},
	}

	mgr.AddEmail(email)

	err := mgr.RemoveEmail("test-email")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	// Try to remove again
	err = mgr.RemoveEmail("test-email")
	if err == nil {
		t.Error("expected error when removing non-existent email")
	}
}

func TestGetEmails(t *testing.T) {
	mgr := NewManager(DefaultConfig())

	mgr.AddEmail(&EmailTarget{
		Name:     "email-1",
		SMTPHost: "smtp.gmail.com",
		From:     "a@example.com",
		To:       []string{"admin@example.com"},
	})
	mgr.AddEmail(&EmailTarget{
		Name:     "email-2",
		SMTPHost: "smtp.outlook.com",
		From:     "b@example.com",
		To:       []string{"admin@example.com"},
	})

	emails := mgr.GetEmails()
	if len(emails) != 2 {
		t.Errorf("expected 2 emails, got %d", len(emails))
	}
}

func TestShouldSend(t *testing.T) {
	mgr := NewManager(DefaultConfig())

	webhook := &WebhookTarget{
		Name:           "test",
		URL:            "https://example.com/webhook",
		Events:         []string{"block"},
		MinScore:       50,
		parsedCooldown: 1 * time.Hour,
	}

	tests := []struct {
		name     string
		event    *Event
		expected bool
	}{
		{
			name:     "score too low",
			event:    &Event{Type: "block", Score: 30},
			expected: false,
		},
		{
			name:     "wrong event type",
			event:    &Event{Type: "log", Score: 75},
			expected: false,
		},
		{
			name:     "should send",
			event:    &Event{Type: "block", Score: 75},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mgr.shouldSend(webhook, tt.event)
			if result != tt.expected {
				t.Errorf("shouldSend() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestCooldown(t *testing.T) {
	mgr := NewManager(DefaultConfig())

	// First call should pass
	if !mgr.checkCooldown("test-key", 1*time.Hour) {
		t.Error("first cooldown check should pass")
	}

	// Second call should fail (within cooldown)
	if mgr.checkCooldown("test-key", 1*time.Hour) {
		t.Error("second cooldown check should fail")
	}

	// Different key should pass
	if !mgr.checkCooldown("different-key", 1*time.Hour) {
		t.Error("different key should pass")
	}
}

func TestFormatSlackPayload(t *testing.T) {
	mgr := NewManager(DefaultConfig())

	event := &Event{
		Type:      "block",
		Score:     75,
		ClientIP:  "192.168.1.1",
		Method:    "GET",
		Path:      "/admin",
		Host:      "example.com",
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
	}

	payload := mgr.formatSlackPayload(event)

	var result map[string]any
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	attachments, ok := result["attachments"].([]any)
	if !ok || len(attachments) == 0 {
		t.Fatal("expected attachments in payload")
	}
}

func TestFormatDiscordPayload(t *testing.T) {
	mgr := NewManager(DefaultConfig())

	event := &Event{
		Type:      "block",
		Score:     75,
		ClientIP:  "192.168.1.1",
		Method:    "POST",
		Path:      "/api/login",
		Host:      "example.com",
		Timestamp: time.Now(),
	}

	payload := mgr.formatDiscordPayload(event)

	var result map[string]any
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	embeds, ok := result["embeds"].([]any)
	if !ok || len(embeds) == 0 {
		t.Fatal("expected embeds in payload")
	}
}

func TestFormatPagerDutyPayload(t *testing.T) {
	mgr := NewManager(DefaultConfig())

	event := &Event{
		ID:        "evt-123",
		Type:      "block",
		Score:     85,
		ClientIP:  "192.168.1.1",
		Method:    "GET",
		Path:      "/admin",
		Host:      "example.com",
		Timestamp: time.Now(),
	}

	payload := mgr.formatPagerDutyPayload(event)

	var result map[string]any
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	if _, ok := result["routing_key"]; !ok {
		t.Error("expected routing_key in payload")
	}
}

func TestSendWebhook(t *testing.T) {
	// Create test server
	received := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("expected Content-Type: application/json")
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		received <- body

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mgr := NewManager(DefaultConfig())
	webhook := &WebhookTarget{
		Name:     "test",
		URL:      server.URL,
		Type:     "generic",
		Events:   []string{"block"},
		MinScore: 50,
		Cooldown: "0s", // No cooldown for test
	}
	mgr.AddWebhook(webhook)

	event := &Event{
		Type:      "block",
		Score:     75,
		ClientIP:  "192.168.1.1",
		Method:    "GET",
		Path:      "/test",
		Host:      "example.com",
		Timestamp: time.Now(),
	}

	// Reset cooldown
	mgr.cooldownsMu.Lock()
	delete(mgr.cooldowns, "test")
	mgr.cooldownsMu.Unlock()

	mgr.sendWebhook(webhook, event)

	select {
	case payload := <-received:
		var receivedEvent Event
		if err := json.Unmarshal(payload, &receivedEvent); err != nil {
			t.Fatalf("failed to unmarshal received payload: %v", err)
		}
		if receivedEvent.ClientIP != "192.168.1.1" {
			t.Errorf("expected ClientIP 192.168.1.1, got %s", receivedEvent.ClientIP)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for webhook")
	}
}

func TestSendTestAlert(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mgr := NewManager(DefaultConfig())
	webhook := &WebhookTarget{
		Name:     "test-webhook",
		URL:      server.URL,
		Type:     "generic",
		Events:   []string{"block"},
		MinScore: 50,
		Cooldown: "0s",
	}
	mgr.AddWebhook(webhook)

	err := mgr.SendTestAlert("test-webhook")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	// Test non-existent target
	err = mgr.SendTestAlert("non-existent")
	if err == nil {
		t.Error("expected error for non-existent target")
	}
}

func TestGetHistory(t *testing.T) {
	mgr := NewManager(DefaultConfig())

	// Add some history
	for i := 0; i < 5; i++ {
		mgr.recordAlert("target-1", "webhook", &Event{Type: "block", Score: 50 + i}, true, "")
		mgr.recordAlert("target-2", "email", &Event{Type: "challenge", Score: 60 + i}, false, "error")
	}

	history := mgr.GetHistory(5)
	if len(history) != 5 {
		t.Errorf("expected 5 history entries, got %d", len(history))
	}

	// Check order (newest first) - last recorded was email with score 60+4=64
	if history[0].Score != 64 {
		t.Errorf("expected most recent score 64, got %d", history[0].Score)
	}

	// Test limit larger than history
	history = mgr.GetHistory(100)
	if len(history) != 10 {
		t.Errorf("expected 10 history entries, got %d", len(history))
	}
}

func TestGetStats(t *testing.T) {
	mgr := NewManager(DefaultConfig())

	// Add some history
	mgr.recordAlert("target-1", "webhook", &Event{Type: "block", Score: 50}, true, "")
	mgr.recordAlert("target-1", "webhook", &Event{Type: "block", Score: 60}, true, "")
	mgr.recordAlert("target-2", "email", &Event{Type: "block", Score: 70}, false, "error")

	sent, failed := mgr.GetStats()
	if sent != 2 {
		t.Errorf("expected 2 sent, got %d", sent)
	}
	if failed != 1 {
		t.Errorf("expected 1 failed, got %d", failed)
	}
}

func TestGetStatus(t *testing.T) {
	mgr := NewManager(DefaultConfig())

	mgr.AddWebhook(&WebhookTarget{Name: "webhook-1", URL: "https://example.com/1"})
	mgr.AddWebhook(&WebhookTarget{Name: "webhook-2", URL: "https://example.com/2"})
	mgr.AddEmail(&EmailTarget{Name: "email-1", SMTPHost: "smtp.example.com", From: "a@example.com", To: []string{"b@example.com"}})

	status := mgr.GetStatus()

	if status["webhook_count"] != 2 {
		t.Errorf("expected 2 webhooks, got %v", status["webhook_count"])
	}
	if status["email_count"] != 1 {
		t.Errorf("expected 1 email, got %v", status["email_count"])
	}
	if status["enabled"] != true {
		t.Error("expected alerting to be enabled")
	}
}

func TestContainsEvent(t *testing.T) {
	tests := []struct {
		events   []string
		event    string
		expected bool
	}{
		{[]string{"block", "challenge"}, "block", true},
		{[]string{"block", "challenge"}, "BLOCK", true}, // Case insensitive
		{[]string{"block", "challenge"}, "log", false},
		{[]string{"all"}, "block", true},
		{[]string{}, "block", false},
	}

	for _, tt := range tests {
		result := containsEvent(tt.events, tt.event)
		if result != tt.expected {
			t.Errorf("containsEvent(%v, %s) = %v, expected %v", tt.events, tt.event, result, tt.expected)
		}
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"30s", 30 * time.Second, false},
		{"5m", 5 * time.Minute, false},
		{"1h", 1 * time.Hour, false},
		{"", 0, true},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		duration, err := parseDuration(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseDuration(%s) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && duration != tt.expected {
			t.Errorf("parseDuration(%s) = %v, expected %v", tt.input, duration, tt.expected)
		}
	}
}

func TestFormatEmailBody(t *testing.T) {
	mgr := NewManager(DefaultConfig())
	target := &EmailTarget{
		Name: "test-email",
	}

	event := &Event{
		Type:      "block",
		Score:     75,
		ClientIP:  "192.168.1.1",
		Method:    "GET",
		Path:      "/admin",
		Host:      "example.com",
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
	}

	body := mgr.formatEmailBody(target, event)

	if !strings.Contains(body, "GuardianWAF") {
		t.Error("expected email body to contain 'GuardianWAF'")
	}
	if !strings.Contains(body, "192.168.1.1") {
		t.Error("expected email body to contain client IP")
	}
	if !strings.Contains(body, "75") {
		t.Error("expected email body to contain score")
	}
}

func BenchmarkSendAlert(b *testing.B) {
	mgr := NewManager(DefaultConfig())

	// Add webhook
	mgr.AddWebhook(&WebhookTarget{
		Name:     "bench-webhook",
		URL:      "http://localhost:9999/webhook",
		Type:     "generic",
		Events:   []string{"block"},
		MinScore: 50,
		Cooldown: "0s",
	})

	event := &Event{
		Type:      "block",
		Score:     75,
		ClientIP:  "192.168.1.1",
		Method:    "GET",
		Path:      "/test",
		Host:      "example.com",
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgr.SendAlert(event)
	}
}

func BenchmarkRecordAlert(b *testing.B) {
	mgr := NewManager(DefaultConfig())
	event := &Event{Type: "block", Score: 50}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgr.recordAlert("target", "webhook", event, true, "")
	}
}
