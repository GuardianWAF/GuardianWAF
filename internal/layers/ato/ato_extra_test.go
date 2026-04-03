package ato

import (
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- PostProcess ---

func TestPostProcess_Success(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
	}
	layer, _ := NewLayer(cfg)
	layer.tracker.RecordAttempt(LoginAttempt{
		IP:    net.ParseIP("192.0.2.1"),
		Email: "test@example.com",
		Time:  time.Now(),
	})

	ctx := &engine.RequestContext{
		ClientIP:   net.ParseIP("192.0.2.1"),
		BodyString: `{"email":"test@example.com"}`,
	}

	layer.PostProcess(ctx, true)

	if layer.tracker.GetIPAttempts(net.ParseIP("192.0.2.1"), time.Hour) != 0 {
		t.Error("expected IP attempts to be cleared after successful login")
	}
}

func TestPostProcess_Failure(t *testing.T) {
	cfg := Config{Enabled: true, LoginPaths: []string{"/login"}}
	layer, _ := NewLayer(cfg)
	layer.tracker.RecordAttempt(LoginAttempt{
		IP:    net.ParseIP("192.0.2.1"),
		Email: "test@example.com",
		Time:  time.Now(),
	})

	ctx := &engine.RequestContext{
		ClientIP:   net.ParseIP("192.0.2.1"),
		BodyString: `{"email":"test@example.com"}`,
	}

	layer.PostProcess(ctx, false)

	if layer.tracker.GetIPAttempts(net.ParseIP("192.0.2.1"), time.Hour) != 1 {
		t.Error("expected IP attempts to remain after failed login")
	}
}

func TestPostProcess_Disabled(t *testing.T) {
	cfg := Config{Enabled: false}
	layer, _ := NewLayer(cfg)
	ctx := &engine.RequestContext{
		ClientIP:   net.ParseIP("192.0.2.1"),
		BodyString: `{"email":"test@example.com"}`,
	}
	layer.PostProcess(ctx, true) // should not panic
}

// --- extractPassword ---

func TestExtractPassword_JSON(t *testing.T) {
	cfg := Config{Enabled: true, LoginPaths: []string{"/login"}}
	layer, _ := NewLayer(cfg)

	tests := []struct {
		body     string
		expected string
	}{
		{`{"password":"secret123"}`, "secret123"},
		{`{"pass":"mypass"}`, "mypass"},
		{`{"email":"test@test.com"}`, ""},
	}

	for _, tt := range tests {
		result := layer.extractPassword(tt.body)
		if result != tt.expected {
			t.Errorf("extractPassword(%q) = %q, want %q", tt.body, result, tt.expected)
		}
	}
}

func TestExtractPassword_FormFormat(t *testing.T) {
	cfg := Config{Enabled: true, LoginPaths: []string{"/login"}}
	layer, _ := NewLayer(cfg)

	tests := []struct {
		body     string
		expected string
	}{
		{"password=formsecret", "formsecret"},
		{"pass=formpass", "formpass"},
		{"email=test@test.com", ""},
	}

	for _, tt := range tests {
		result := layer.extractPassword(tt.body)
		if result != tt.expected {
			t.Errorf("extractPassword(%q) = %q, want %q", tt.body, result, tt.expected)
		}
	}
}

// --- GetPasswordUseCount ---

func TestGetPasswordUseCount(t *testing.T) {
	tracker := NewAttemptTracker()

	tracker.RecordAttempt(LoginAttempt{
		IP:       net.ParseIP("10.0.0.1"),
		Email:    "a@test.com",
		Password: "common-password",
		Time:     time.Now(),
	})
	tracker.RecordAttempt(LoginAttempt{
		IP:       net.ParseIP("10.0.0.2"),
		Email:    "b@test.com",
		Password: "common-password",
		Time:     time.Now(),
	})

	count := tracker.GetPasswordUseCount("common-password")
	if count != 2 {
		t.Errorf("expected 2 uses of same password, got %d", count)
	}

	count = tracker.GetPasswordUseCount("unknown-password")
	if count != 0 {
		t.Errorf("expected 0 for unknown password, got %d", count)
	}
}

// --- hashPassword ---

func TestHashPassword(t *testing.T) {
	h1 := hashPassword("test")
	h2 := hashPassword("test")
	if h1 != h2 {
		t.Error("same password should produce same hash")
	}

	h3 := hashPassword("different")
	if h1 == h3 {
		t.Error("different passwords should produce different hashes")
	}
}

// --- Tracker Cleanup ---

func TestTracker_Cleanup(t *testing.T) {
	tracker := NewAttemptTracker()

	// Record old attempt
	tracker.RecordAttempt(LoginAttempt{
		IP:    net.ParseIP("192.0.2.1"),
		Email: "old@example.com",
		Time:  time.Now().Add(-48 * time.Hour),
	})
	// Record recent attempt
	tracker.RecordAttempt(LoginAttempt{
		IP:    net.ParseIP("10.0.0.1"),
		Email: "new@example.com",
		Time:  time.Now(),
	})

	tracker.Cleanup(24 * time.Hour)

	// Old should be gone
	if tracker.GetIPAttempts(net.ParseIP("192.0.2.1"), 72*time.Hour) != 0 {
		t.Error("old attempts should be cleaned up")
	}
	// Recent should remain
	if tracker.GetIPAttempts(net.ParseIP("10.0.0.1"), time.Hour) != 1 {
		t.Error("recent attempts should remain")
	}
}

// --- Tracker Stats with blocked entries ---

func TestTracker_Stats_Blocked(t *testing.T) {
	tracker := NewAttemptTracker()
	tracker.RecordAttempt(LoginAttempt{
		IP:    net.ParseIP("10.0.0.1"),
		Email: "test@example.com",
		Time:  time.Now(),
	})
	tracker.BlockIP(net.ParseIP("10.0.0.1"), time.Now().Add(time.Hour), "test")
	tracker.BlockEmail("test@example.com", time.Now().Add(time.Hour), "test")

	stats := tracker.Stats()
	if stats["blocked_ips"] != 1 {
		t.Errorf("expected 1 blocked IP, got %d", stats["blocked_ips"])
	}
	if stats["blocked_emails"] != 1 {
		t.Errorf("expected 1 blocked email, got %d", stats["blocked_emails"])
	}
}

// --- LocationDB ---

func TestLocationDB_Lookup_Exact(t *testing.T) {
	db := NewLocationDB()
	loc := &GeoLocation{Country: "US", City: "New York", Latitude: 40.71, Longitude: -74.00}
	db.Add("192.0.2.1", loc)

	result := db.Lookup(net.ParseIP("192.0.2.1"))
	if result == nil || result.City != "New York" {
		t.Errorf("expected New York, got %v", result)
	}
}

func TestLocationDB_Lookup_NotFound(t *testing.T) {
	db := NewLocationDB()
	result := db.Lookup(net.ParseIP("1.2.3.4"))
	if result != nil {
		t.Errorf("expected nil for unknown IP, got %v", result)
	}
}

// --- getLocation nil DB ---

func TestGetLocation_NilDB(t *testing.T) {
	cfg := Config{Enabled: true, LoginPaths: []string{"/login"}}
	layer, _ := NewLayer(cfg)
	loc := layer.getLocation(net.ParseIP("1.2.3.4"))
	if loc != nil {
		t.Error("expected nil when no location DB")
	}
}

// --- Layer Cleanup ---

func TestLayer_Cleanup(t *testing.T) {
	cfg := Config{Enabled: true, LoginPaths: []string{"/login"}}
	layer, _ := NewLayer(cfg)

	layer.tracker.RecordAttempt(LoginAttempt{
		IP:    net.ParseIP("192.0.2.1"),
		Email: "test@example.com",
		Time:  time.Now(),
	})

	layer.Cleanup()

	// After cleanup, should still have the attempt (it's recent)
	if layer.tracker.GetIPAttempts(net.ParseIP("192.0.2.1"), time.Hour) != 1 {
		t.Error("recent attempt should survive cleanup")
	}
}

// --- isLoginPath ---

func TestIsLoginPath(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login", "/api/auth"},
	}
	layer, _ := NewLayer(cfg)

	if !layer.isLoginPath("/login") {
		t.Error("/login should match")
	}
	if !layer.isLoginPath("/api/auth") {
		t.Error("/api/auth should match")
	}
	if layer.isLoginPath("/api/users") {
		t.Error("/api/users should not match")
	}
}

// --- ClearAttempt ---

func TestClearAttempt_IPOnly(t *testing.T) {
	tracker := NewAttemptTracker()
	tracker.RecordAttempt(LoginAttempt{IP: net.ParseIP("10.0.0.1"), Email: "test@example.com", Time: time.Now()})

	tracker.ClearAttempt(net.ParseIP("10.0.0.1"), "")
	if tracker.GetIPAttempts(net.ParseIP("10.0.0.1"), time.Hour) != 0 {
		t.Error("IP attempts should be cleared")
	}
}

func TestClearAttempt_NilIP(t *testing.T) {
	tracker := NewAttemptTracker()
	tracker.RecordAttempt(LoginAttempt{IP: net.ParseIP("10.0.0.1"), Email: "test@example.com", Time: time.Now()})

	tracker.ClearAttempt(nil, "test@example.com")
	if tracker.GetEmailAttempts("test@example.com", time.Hour) != 0 {
		t.Error("email attempts should be cleared")
	}
}

// --- BlockIP expired ---

func TestIsIPBlocked_Expired(t *testing.T) {
	tracker := NewAttemptTracker()
	tracker.BlockIP(net.ParseIP("10.0.0.1"), time.Now().Add(-time.Hour), "expired")

	blocked, _ := tracker.IsIPBlocked(net.ParseIP("10.0.0.1"))
	if blocked {
		t.Error("expired block should not be active")
	}
}

// --- IsEmailBlocked expired ---

func TestIsEmailBlocked_Expired(t *testing.T) {
	tracker := NewAttemptTracker()
	tracker.BlockEmail("test@example.com", time.Now().Add(-time.Hour), "expired")

	blocked, _ := tracker.IsEmailBlocked("test@example.com")
	if blocked {
		t.Error("expired email block should not be active")
	}
}

// --- RecordAttempt zero time ---

func TestRecordAttempt_ZeroTime(t *testing.T) {
	tracker := NewAttemptTracker()
	tracker.RecordAttempt(LoginAttempt{
		IP:    net.ParseIP("10.0.0.1"),
		Email: "test@example.com",
		Time:  time.Time{},
	})

	count := tracker.GetIPAttempts(net.ParseIP("10.0.0.1"), time.Hour)
	if count != 1 {
		t.Errorf("expected 1 attempt with zero time, got %d", count)
	}
}

// --- Process with password spray ---

func TestProcess_PasswordSpray(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		PasswordSpray: PasswordSprayConfig{
			Enabled:       true,
			Threshold:     3,
			Window:        time.Hour,
			BlockDuration: time.Hour,
		},
	}
	layer, _ := NewLayer(cfg)

	// Record 3 password uses first via tracker directly
	for i := 0; i < 3; i++ {
		layer.tracker.RecordAttempt(LoginAttempt{
			IP:       net.ParseIP("10.0.0." + string(rune('1'+i))),
			Email:    string(rune('a'+i)) + "@test.com",
			Password: "common123",
			Time:     time.Now(),
		})
	}

	// Now the 4th attempt with same password should trigger spray detection
	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("10.0.0.9"),
		BodyString: `{"email":"d@test.com","password":"common123"}`,
		Headers:    map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for password spray, got %v", result.Action)
	}
}

// --- Process: no email in body ---

func TestProcess_NoEmail(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		BruteForce: BruteForceConfig{Enabled: true, Window: time.Hour, MaxAttemptsPerIP: 3},
	}
	layer, _ := NewLayer(cfg)

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("192.0.2.1"),
		BodyString: `{"notemail":"value"}`,
		Headers:    map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass when no email extracted, got %v", result.Action)
	}
}
