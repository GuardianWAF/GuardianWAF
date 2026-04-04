package botdetect

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestBiometricCollector_HandleCollect(t *testing.T) {
	// Create enhanced layer
	cfg := DefaultEnhancedConfig()
	cfg.Biometric.Enabled = true
	layer := NewEnhancedLayer(&cfg)

	collector := NewBiometricCollector(layer)

	tests := []struct {
		name       string
		method     string
		headers    map[string]string
		body       any
		wantStatus int
	}{
		{
			name:       "valid request",
			method:     http.MethodPost,
			headers:    map[string]string{"X-Session-ID": "test-session-123"},
			body:       EventRequest{Events: []BiometricEvent{{Type: "mouse", Subtype: "move", X: 100, Y: 200, Timestamp: time.Now()}}},
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing session ID",
			method:     http.MethodPost,
			headers:    map[string]string{},
			body:       EventRequest{Events: []BiometricEvent{}},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "wrong method",
			method:     http.MethodGet,
			headers:    map[string]string{"X-Session-ID": "test"},
			body:       nil,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "invalid JSON",
			method:     http.MethodPost,
			headers:    map[string]string{"X-Session-ID": "test"},
			body:       "not json",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			if tt.body != nil {
				if s, ok := tt.body.(string); ok {
					body = []byte(s)
				} else {
					body, _ = json.Marshal(tt.body)
				}
			}

			req := httptest.NewRequest(tt.method, "/gwaf/biometric/collect", bytes.NewReader(body))
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			rr := httptest.NewRecorder()
			collector.HandleCollect(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
		})
	}
}

func TestBiometricCollector_processEvent(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Biometric.Enabled = true
	layer := NewEnhancedLayer(&cfg)
	collector := NewBiometricCollector(layer)

	now := time.Now()

	tests := []struct {
		name      string
		sessionID string
		event     BiometricEvent
	}{
		{
			name:      "mouse move",
			sessionID: "sess-1",
			event:     BiometricEvent{Type: "mouse", Subtype: "move", X: 10, Y: 20, Timestamp: now},
		},
		{
			name:      "mouse click",
			sessionID: "sess-1",
			event:     BiometricEvent{Type: "mouse", Subtype: "click", X: 10, Y: 20, Button: 0, Timestamp: now},
		},
		{
			name:      "keyboard press",
			sessionID: "sess-2",
			event:     BiometricEvent{Type: "keyboard", Subtype: "press", Key: "a", Code: "KeyA", Timestamp: now},
		},
		{
			name:      "scroll",
			sessionID: "sess-3",
			event:     BiometricEvent{Type: "scroll", DeltaY: 100, Timestamp: now},
		},
		{
			name:      "touch start",
			sessionID: "sess-4",
			event:     BiometricEvent{Type: "touch", Subtype: "start", X: 50, Y: 100, Timestamp: now},
		},
		{
			name:      "unknown type",
			sessionID: "sess-5",
			event:     BiometricEvent{Type: "unknown", Timestamp: now},
		},
		{
			name:      "invalid mouse subtype",
			sessionID: "sess-6",
			event:     BiometricEvent{Type: "mouse", Subtype: "invalid", Timestamp: now},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			collector.processEvent(tt.sessionID, tt.event)
		})
	}
}

func TestBiometricCollector_HandleChallengePage(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Challenge.Enabled = true
	cfg.Challenge.Provider = "hcaptcha"
	cfg.Challenge.SiteKey = "test-site-key"
	layer := NewEnhancedLayer(&cfg)
	collector := NewBiometricCollector(layer)

	tests := []struct {
		name       string
		method     string
		wantStatus int
		wantHTML   bool
	}{
		{
			name:       "GET request",
			method:     http.MethodGet,
			wantStatus: http.StatusOK,
			wantHTML:   true,
		},
		{
			name:       "POST request",
			method:     http.MethodPost,
			wantStatus: http.StatusMethodNotAllowed,
			wantHTML:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/gwaf/challenge", nil)
			rr := httptest.NewRecorder()
			collector.HandleChallengePage(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}

			if tt.wantHTML {
				contentType := rr.Header().Get("Content-Type")
				if contentType != "text/html" {
					t.Errorf("Content-Type = %s, want text/html", contentType)
				}
				body := rr.Body.String()
				if !contains(body, "test-site-key") {
					t.Error("expected site key in response")
				}
			}
		})
	}
}

func TestBiometricCollector_HandleChallengeVerify(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Challenge.Enabled = false // No provider configured
	layer := NewEnhancedLayer(&cfg)
	collector := NewBiometricCollector(layer)

	tests := []struct {
		name       string
		method     string
		formData   string
		wantStatus int
	}{
		{
			name:       "missing token",
			method:     http.MethodPost,
			formData:   "",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "GET request",
			method:     http.MethodGet,
			formData:   "",
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body *bytes.Buffer
			if tt.formData != "" {
				body = bytes.NewBufferString(tt.formData)
			} else {
				body = &bytes.Buffer{}
			}

			req := httptest.NewRequest(tt.method, "/gwaf/challenge/verify", body)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			collector.HandleChallengeVerify(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
		})
	}
}

func TestGenerateChallengePage(t *testing.T) {
	tests := []struct {
		name     string
		siteKey  string
		provider string
		want     []string
	}{
		{
			name:     "hcaptcha",
			siteKey:  "test-key-123",
			provider: "hcaptcha",
			want:     []string{"test-key-123", "js.hcaptcha.com", "h-captcha"},
		},
		{
			name:     "turnstile",
			siteKey:  "test-key-456",
			provider: "turnstile",
			want:     []string{"test-key-456", "cloudflare.com", "cf-turnstile"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			html := generateChallengePage(tt.siteKey, tt.provider)
			for _, want := range tt.want {
				if !contains(html, want) {
					t.Errorf("expected %q in HTML", want)
				}
			}
		})
	}
}

func TestNewBiometricCollector(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	layer := NewEnhancedLayer(&cfg)

	collector := NewBiometricCollector(layer)
	if collector == nil {
		t.Fatal("expected collector, got nil")
	}
	if collector.enhancedLayer != layer {
		t.Error("enhancedLayer not set correctly")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// MockRequestContext creates a mock request context for testing
func mockRequestContext() *engine.RequestContext {
	return &engine.RequestContext{
		StartTime: time.Now(),
		Headers:   make(map[string][]string),
	}
}
