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
