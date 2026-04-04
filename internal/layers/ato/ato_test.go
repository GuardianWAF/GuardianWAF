package ato

import (
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestNewLayer(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login", "/api/auth"},
	}

	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	if layer.Name() != "ato_protection" {
		t.Errorf("Expected name 'ato_protection', got '%s'", layer.Name())
	}
}

func TestProcess_Disabled(t *testing.T) {
	cfg := Config{Enabled: false}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Path:    "/login",
		Method:  "POST",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected pass when disabled, got %v", result.Action)
	}
}

func TestProcess_NonLoginPath(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Path:    "/api/users",
		Method:  "POST",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected pass for non-login path, got %v", result.Action)
	}
}

func TestProcess_NonPostMethod(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Path:    "/login",
		Method:  "GET",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected pass for GET method, got %v", result.Action)
	}
}

func TestProcess_BruteForce(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		BruteForce: BruteForceConfig{
			Enabled:          true,
			Window:           15 * time.Minute,
			MaxAttemptsPerIP: 3,
			BlockDuration:    30 * time.Minute,
		},
	}
	layer, _ := NewLayer(&cfg)

	// Simulate multiple failed attempts
	for i := 0; i < 5; i++ {
		ctx := &engine.RequestContext{
			Path:       "/login",
			Method:     "POST",
			ClientIP:   net.ParseIP("192.0.2.1"),
			BodyString: `{"email":"test@example.com","password":"wrong"}`,
			Headers:    map[string][]string{},
		}

		result := layer.Process(ctx)
		if i >= 2 && result.Action != engine.ActionBlock {
			t.Errorf("Expected block after %d attempts, got %v (attempt %d)", 3, result.Action, i+1)
		}
	}
}

func TestProcess_CredentialStuffing(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		CredStuffing: CredentialStuffingConfig{
			Enabled:              true,
			DistributedThreshold: 3,
			Window:               time.Hour,
			BlockDuration:        time.Hour,
		},
	}
	layer, _ := NewLayer(&cfg)

	// Simulate same email from different IPs - need to exceed threshold
	ips := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}
	for i, ip := range ips {
		ctx := &engine.RequestContext{
			Path:       "/login",
			Method:     "POST",
			ClientIP:   net.ParseIP(ip),
			BodyString: `{"email":"target@example.com","password":"test"}`,
			Headers:    map[string][]string{},
		}

		result := layer.Process(ctx)
		// Only block after threshold is exceeded
		if i >= 3 && result.Action != engine.ActionBlock {
			t.Errorf("Expected block for credential stuffing after %d IPs", i+1)
		}
	}
}

func TestAttemptTracker(t *testing.T) {
	tracker := NewAttemptTracker()

	ip := net.ParseIP("192.0.2.1")
	email := "test@example.com"

	// Record attempts
	for i := 0; i < 5; i++ {
		tracker.RecordAttempt(&LoginAttempt{
			IP:    ip,
			Email: email,
			Time:  time.Now(),
		})
	}

	// Check counts
	count := tracker.GetIPAttempts(ip, time.Hour)
	if count != 5 {
		t.Errorf("Expected 5 IP attempts, got %d", count)
	}

	emailCount := tracker.GetEmailAttempts(email, time.Hour)
	if emailCount != 5 {
		t.Errorf("Expected 5 email attempts, got %d", emailCount)
	}

	// Test blocking
	tracker.BlockIP(ip, time.Now().Add(time.Hour), "test")
	blocked, reason := tracker.IsIPBlocked(ip)
	if !blocked {
		t.Error("Expected IP to be blocked")
	}
	if reason != "test" {
		t.Errorf("Expected reason 'test', got '%s'", reason)
	}

	// Test cleanup
	tracker.ClearAttempt(ip, email)
	count = tracker.GetIPAttempts(ip, time.Hour)
	if count != 0 {
		t.Errorf("Expected 0 attempts after clear, got %d", count)
	}
}

func TestExtractEmail(t *testing.T) {
	cfg := Config{Enabled: true, LoginPaths: []string{"/login"}}
	layer, _ := NewLayer(&cfg)

	tests := []struct {
		body     string
		expected string
	}{
		{`{"email":"test@example.com"}`, "test@example.com"},
		{`{"username":"user@example.org"}`, "user@example.org"},
		{`{"login":"admin@test.net"}`, "admin@test.net"},
		{`{"notemail":"value"}`, ""},
	}

	for _, tt := range tests {
		result := layer.extractEmail(tt.body)
		if result != tt.expected {
			t.Errorf("extractEmail(%q) = %q, want %q", tt.body, result, tt.expected)
		}
	}
}

func TestHaversineDistance(t *testing.T) {
	// Test distance between New York and London (~5570 km)
	nyc := &GeoLocation{Latitude: 40.7128, Longitude: -74.0060}
	london := &GeoLocation{Latitude: 51.5074, Longitude: -0.1278}

	distance := haversineDistance(nyc, london)

	// Allow 10% margin of error
	if distance < 5000 || distance > 6000 {
		t.Errorf("Expected ~5570 km, got %.0f km", distance)
	}

	// Test same location
	sameDistance := haversineDistance(nyc, nyc)
	if sameDistance > 1 {
		t.Errorf("Expected 0 km for same location, got %.0f km", sameDistance)
	}
}

func TestStats(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, _ := NewLayer(&cfg)

	stats := layer.Stats()
	if !stats["enabled"].(bool) {
		t.Error("Expected enabled=true")
	}
}

// Benchmark
func BenchmarkProcess(b *testing.B) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		BruteForce: BruteForceConfig{
			Enabled:          true,
			Window:           15 * time.Minute,
			MaxAttemptsPerIP: 10,
		},
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("10.0.0.1"),
		BodyString: `{"email":"test@example.com","password":"secret"}`,
		Headers:    map[string][]string{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		layer.Process(ctx)
	}
}
