package ato

import (
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// ---------------------------------------------------------------------------
// NewLayer — with all sub-configs enabled and geo provider
// ---------------------------------------------------------------------------

func TestNewLayer_AllSubConfigsEnabled(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login", "/api/auth", "/signin"},
		BruteForce: BruteForceConfig{
			Enabled:             true,
			Window:              15 * time.Minute,
			MaxAttemptsPerIP:    5,
			MaxAttemptsPerEmail: 10,
			BlockDuration:       30 * time.Minute,
		},
		CredStuffing: CredentialStuffingConfig{
			Enabled:              true,
			DistributedThreshold: 3,
			Window:               time.Hour,
			BlockDuration:        time.Hour,
		},
		PasswordSpray: PasswordSprayConfig{
			Enabled:       true,
			Threshold:     5,
			Window:        time.Hour,
			BlockDuration: time.Hour,
		},
		Travel: ImpossibleTravelConfig{
			Enabled:       true,
			MaxDistanceKm: 500,
			MaxTimeHours:  2,
			BlockDuration: time.Hour,
		},
	}

	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer with all configs: %v", err)
	}
	if layer.Name() != "ato_protection" {
		t.Errorf("expected name 'ato_protection', got %q", layer.Name())
	}
	if len(layer.loginPathRe) != 3 {
		t.Errorf("expected 3 login path regexes, got %d", len(layer.loginPathRe))
	}
}

func TestNewLayer_WithGeoDBPath(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		Travel: ImpossibleTravelConfig{
			Enabled:       true,
			MaxDistanceKm: 500,
			MaxTimeHours:  2,
			BlockDuration: time.Hour,
		},
		GeoDBPath: "/fake/path/to/geodb.mmdb",
	}

	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer with GeoDBPath: %v", err)
	}
	if layer.locationDB == nil {
		t.Error("expected locationDB to be initialized when Travel enabled and GeoDBPath set")
	}
}

func TestNewLayer_TravelEnabled_NoGeoDBPath(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		Travel: ImpossibleTravelConfig{
			Enabled:       true,
			MaxDistanceKm: 500,
			MaxTimeHours:  2,
			BlockDuration: time.Hour,
		},
		// GeoDBPath intentionally empty
	}

	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	if layer.locationDB != nil {
		t.Error("expected locationDB to be nil when GeoDBPath is empty")
	}
}

// ---------------------------------------------------------------------------
// checkImpossibleTravel — covering getLocation, getLastLoginLocation,
// getLastLoginTime through the method
// ---------------------------------------------------------------------------

func TestCheckImpossibleTravel_NoLocationDB(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		Travel: ImpossibleTravelConfig{
			Enabled:       true,
			MaxDistanceKm: 500,
			MaxTimeHours:  2,
			BlockDuration: time.Hour,
		},
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("1.2.3.4"),
		BodyString: `{"email":"test@example.com"}`,
		Headers:    map[string][]string{},
	}

	result := layer.checkImpossibleTravel(ctx, "test@example.com")
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass with no locationDB, got %v", result.Action)
	}
}

func TestCheckImpossibleTravel_WithLocationDB_NoLastLocation(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		Travel: ImpossibleTravelConfig{
			Enabled:       true,
			MaxDistanceKm: 500,
			MaxTimeHours:  2,
			BlockDuration: time.Hour,
		},
		GeoDBPath: "/fake/geodb",
	}
	layer, _ := NewLayer(&cfg)

	// Add current IP location to DB
	layer.locationDB.Add("1.2.3.4", &GeoLocation{
		Country:   "US",
		City:      "New York",
		Latitude:  40.7128,
		Longitude: -74.0060,
	})

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("1.2.3.4"),
		BodyString: `{"email":"test@example.com"}`,
		Headers:    map[string][]string{},
	}

	// getLastLoginLocation always returns nil -> pass
	result := layer.checkImpossibleTravel(ctx, "test@example.com")
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass when no last login location, got %v", result.Action)
	}
}

func TestCheckImpossibleTravel_CurrentIPLocationNotFound(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		Travel: ImpossibleTravelConfig{
			Enabled:       true,
			MaxDistanceKm: 500,
			MaxTimeHours:  2,
			BlockDuration: time.Hour,
		},
		GeoDBPath: "/fake/geodb",
	}
	layer, _ := NewLayer(&cfg)

	// Don't add current IP to DB -> getLocation returns nil
	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("9.8.7.6"),
		BodyString: `{"email":"test@example.com"}`,
		Headers:    map[string][]string{},
	}

	result := layer.checkImpossibleTravel(ctx, "test@example.com")
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass when current IP not in locationDB, got %v", result.Action)
	}
}

func TestCheckImpossibleTravel_LocationDBExactMatch(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		Travel: ImpossibleTravelConfig{
			Enabled:       true,
			MaxDistanceKm: 500,
			MaxTimeHours:  2,
			BlockDuration: time.Hour,
		},
		GeoDBPath: "/fake/geodb",
	}
	layer, _ := NewLayer(&cfg)

	// Add an exact IP entry
	layer.locationDB.Add("10.0.0.5", &GeoLocation{
		Country:   "DE",
		City:      "Berlin",
		Latitude:  52.52,
		Longitude: 13.405,
	})

	loc := layer.getLocation(net.ParseIP("10.0.0.5"))
	if loc == nil {
		t.Fatal("expected exact match for 10.0.0.5")
	}
	if loc.City != "Berlin" {
		t.Errorf("expected Berlin, got %s", loc.City)
	}
}

func TestCheckImpossibleTravel_LocationDBNoMatch(t *testing.T) {
	db := NewLocationDB()

	db.Add("1.2.3.4", &GeoLocation{Country: "US", City: "Test", Latitude: 40, Longitude: -74})

	loc := db.Lookup(net.ParseIP("1.2.3.4"))
	if loc == nil || loc.City != "Test" {
		t.Errorf("expected exact match, got %v", loc)
	}

	// Different IP not in DB
	loc = db.Lookup(net.ParseIP("1.2.3.5"))
	if loc != nil {
		t.Error("expected nil for non-matching IP")
	}
}

// ---------------------------------------------------------------------------
// getLastLoginLocation / getLastLoginTime — direct calls for coverage
// ---------------------------------------------------------------------------

func TestGetLastLoginLocation_ReturnsNil(t *testing.T) {
	cfg := Config{Enabled: true, LoginPaths: []string{"/login"}}
	layer, _ := NewLayer(&cfg)

	loc := layer.getLastLoginLocation("anyone@example.com")
	if loc != nil {
		t.Error("expected nil (not implemented)")
	}
}

func TestGetLastLoginTime_ReturnsZero(t *testing.T) {
	cfg := Config{Enabled: true, LoginPaths: []string{"/login"}}
	layer, _ := NewLayer(&cfg)

	tm := layer.getLastLoginTime("anyone@example.com")
	if !tm.IsZero() {
		t.Error("expected zero time (not implemented)")
	}
}

func TestCheckImpossibleTravel_Block(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		Travel: ImpossibleTravelConfig{
			Enabled:       true,
			MaxDistanceKm: 500,
			MaxTimeHours:  2,
			BlockDuration: time.Hour,
		},
		GeoDBPath: "/fake/geodb",
	}
	layer, _ := NewLayer(&cfg)

	layer.locationDB.Add("1.2.3.4", &GeoLocation{Latitude: 40.7128, Longitude: -74.0060})
	layer.lastLogin["traveler@example.com"] = &GeoLocation{Latitude: 51.5074, Longitude: -0.1278}
	layer.lastTime["traveler@example.com"] = time.Now().Add(-30 * time.Minute)

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("1.2.3.4"),
		BodyString: `{"email":"traveler@example.com"}`,
		Headers:    map[string][]string{},
	}

	result := layer.checkImpossibleTravel(ctx, "traveler@example.com")
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for impossible travel, got %v", result.Action)
	}
}

func TestCheckImpossibleTravel_Possible(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		Travel: ImpossibleTravelConfig{
			Enabled:       true,
			MaxDistanceKm: 500,
			MaxTimeHours:  2,
			BlockDuration: time.Hour,
		},
		GeoDBPath: "/fake/geodb",
	}
	layer, _ := NewLayer(&cfg)

	layer.locationDB.Add("1.2.3.4", &GeoLocation{Latitude: 40.7128, Longitude: -74.0060})
	layer.lastLogin["traveler@example.com"] = &GeoLocation{Latitude: 40.7300, Longitude: -73.9900}
	layer.lastTime["traveler@example.com"] = time.Now().Add(-30 * time.Minute)

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("1.2.3.4"),
		BodyString: `{"email":"traveler@example.com"}`,
		Headers:    map[string][]string{},
	}

	result := layer.checkImpossibleTravel(ctx, "traveler@example.com")
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for possible travel, got %v", result.Action)
	}
}

// ---------------------------------------------------------------------------
// checkBruteForce — per-email path and threshold boundary
// ---------------------------------------------------------------------------

func TestCheckBruteForce_ExactThreshold(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		BruteForce: BruteForceConfig{
			Enabled:             true,
			Window:              time.Hour,
			MaxAttemptsPerIP:    3,
			MaxAttemptsPerEmail: 100,
			BlockDuration:       time.Hour,
		},
	}
	layer, _ := NewLayer(&cfg)

	ip := net.ParseIP("192.0.2.1")
	email := "victim@example.com"

	// Record exactly MaxAttemptsPerIP attempts
	for i := 0; i < 3; i++ {
		layer.tracker.RecordAttempt(&LoginAttempt{
			IP:    ip,
			Email: email,
			Time:  time.Now(),
		})
	}

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   ip,
		BodyString: `{"email":"victim@example.com"}`,
		Headers:    map[string][]string{},
	}

	result := layer.checkBruteForce(ctx, email)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block at exact threshold, got %v", result.Action)
	}
}

func TestCheckBruteForce_BelowThreshold(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		BruteForce: BruteForceConfig{
			Enabled:             true,
			Window:              time.Hour,
			MaxAttemptsPerIP:    5,
			MaxAttemptsPerEmail: 100,
			BlockDuration:       time.Hour,
		},
	}
	layer, _ := NewLayer(&cfg)

	ip := net.ParseIP("192.0.2.2")
	email := "safe@example.com"

	// Record fewer than threshold
	for i := 0; i < 4; i++ {
		layer.tracker.RecordAttempt(&LoginAttempt{
			IP:    ip,
			Email: email,
			Time:  time.Now(),
		})
	}

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   ip,
		BodyString: `{"email":"safe@example.com"}`,
		Headers:    map[string][]string{},
	}

	result := layer.checkBruteForce(ctx, email)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass below threshold, got %v", result.Action)
	}
}

func TestCheckBruteForce_PerEmailThreshold(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		BruteForce: BruteForceConfig{
			Enabled:             true,
			Window:              time.Hour,
			MaxAttemptsPerIP:    100,
			MaxAttemptsPerEmail: 3,
			BlockDuration:       time.Hour,
		},
	}
	layer, _ := NewLayer(&cfg)

	email := "target@example.com"

	// Record attempts from different IPs for same email
	for i := 0; i < 3; i++ {
		layer.tracker.RecordAttempt(&LoginAttempt{
			IP:    net.ParseIP("10.0.0." + string(rune('1'+i))),
			Email: email,
			Time:  time.Now(),
		})
	}

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("10.0.0.9"),
		BodyString: `{"email":"target@example.com"}`,
		Headers:    map[string][]string{},
	}

	result := layer.checkBruteForce(ctx, email)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for per-email brute force, got %v", result.Action)
	}
	if result.Score != 80 {
		t.Errorf("expected score 80, got %d", result.Score)
	}
}

func TestCheckBruteForce_ExpiredEntriesNotCounted(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		BruteForce: BruteForceConfig{
			Enabled:             true,
			Window:              5 * time.Minute,
			MaxAttemptsPerIP:    3,
			MaxAttemptsPerEmail: 100,
			BlockDuration:       time.Hour,
		},
	}
	layer, _ := NewLayer(&cfg)

	ip := net.ParseIP("192.0.2.50")
	email := "expired@example.com"

	// Record old attempts outside the window
	for i := 0; i < 5; i++ {
		layer.tracker.RecordAttempt(&LoginAttempt{
			IP:    ip,
			Email: email,
			Time:  time.Now().Add(-10 * time.Minute),
		})
	}

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   ip,
		BodyString: `{"email":"expired@example.com"}`,
		Headers:    map[string][]string{},
	}

	result := layer.checkBruteForce(ctx, email)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for expired entries, got %v", result.Action)
	}
}

func TestCheckBruteForce_DifferentEmailsSeparate(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		BruteForce: BruteForceConfig{
			Enabled:             true,
			Window:              time.Hour,
			MaxAttemptsPerIP:    3,
			MaxAttemptsPerEmail: 100,
			BlockDuration:       time.Hour,
		},
	}
	layer, _ := NewLayer(&cfg)

	ip := net.ParseIP("192.0.2.10")

	// 3 attempts for email-a -> triggers per-IP block
	for i := 0; i < 3; i++ {
		layer.tracker.RecordAttempt(&LoginAttempt{
			IP:    ip,
			Email: "a@example.com",
			Time:  time.Now(),
		})
	}

	// Now use a different email with a different IP
	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("192.0.2.99"),
		BodyString: `{"email":"b@example.com"}`,
		Headers:    map[string][]string{},
	}

	result := layer.checkBruteForce(ctx, "b@example.com")
	if result.Action != engine.ActionPass {
		t.Errorf("different IP/email should not be blocked, got %v", result.Action)
	}
}

// ---------------------------------------------------------------------------
// checkPasswordSpray — threshold boundary
// ---------------------------------------------------------------------------

func TestCheckPasswordSpray_BelowThreshold(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		PasswordSpray: PasswordSprayConfig{
			Enabled:       true,
			Threshold:     5,
			Window:        time.Hour,
			BlockDuration: time.Hour,
		},
	}
	layer, _ := NewLayer(&cfg)

	// Record 4 uses (below threshold of 5)
	for i := 0; i < 4; i++ {
		layer.tracker.RecordAttempt(&LoginAttempt{
			IP:       net.ParseIP("10.0.0." + string(rune('1'+i))),
			Email:    string(rune('a'+i)) + "@test.com",
			Password: "sharedpwd",
			Time:     time.Now(),
		})
	}

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("10.0.0.9"),
		BodyString: `{"email":"e@test.com","password":"sharedpwd"}`,
		Headers:    map[string][]string{},
	}

	result := layer.checkPasswordSpray(ctx, "sharedpwd")
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass below threshold, got %v", result.Action)
	}
}

func TestCheckPasswordSpray_ExactThreshold(t *testing.T) {
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
	layer, _ := NewLayer(&cfg)

	// Record exactly 3 uses -> at threshold
	for i := 0; i < 3; i++ {
		layer.tracker.RecordAttempt(&LoginAttempt{
			IP:       net.ParseIP("10.0.1." + string(rune('1'+i))),
			Email:    string(rune('a'+i)) + "@spray.com",
			Password: "spraypass",
			Time:     time.Now(),
		})
	}

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("10.0.1.9"),
		BodyString: `{"email":"d@spray.com","password":"spraypass"}`,
		Headers:    map[string][]string{},
	}

	result := layer.checkPasswordSpray(ctx, "spraypass")
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block at exact threshold, got %v", result.Action)
	}
	if result.Score != 75 {
		t.Errorf("expected score 75, got %d", result.Score)
	}
}

func TestCheckPasswordSpray_MultipleEmailsFromSameIP(t *testing.T) {
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
	layer, _ := NewLayer(&cfg)

	attackerIP := net.ParseIP("10.0.2.1")

	// Same IP tries different emails with the same password
	for i := 0; i < 3; i++ {
		layer.tracker.RecordAttempt(&LoginAttempt{
			IP:       attackerIP,
			Email:    string(rune('a'+i)) + "@target.com",
			Password: "guessedpwd",
			Time:     time.Now(),
		})
	}

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   attackerIP,
		BodyString: `{"email":"d@target.com","password":"guessedpwd"}`,
		Headers:    map[string][]string{},
	}

	result := layer.checkPasswordSpray(ctx, "guessedpwd")
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for spray from same IP, got %v", result.Action)
	}
}

// ---------------------------------------------------------------------------
// extractEmail — form-encoded and edge cases
// ---------------------------------------------------------------------------

func TestExtractEmail_FormEncoded(t *testing.T) {
	cfg := Config{Enabled: true, LoginPaths: []string{"/login"}}
	layer, _ := NewLayer(&cfg)

	tests := []struct {
		body     string
		expected string
	}{
		// URL-encoded @ (%40) does not match the email regex which requires literal @
		{"email=user%40example.com", ""},
		{"username=alice%40test.org", ""},
		{"login=bob%40mail.net", ""},
		{"email=alice@example.com&password=x", "alice@example.com"},
		{"username=alice@example.com", "alice@example.com"},
		{"login=bob@example.com", "bob@example.com"},
		{"password=secret&email=charlie@example.com", "charlie@example.com"},
	}

	for _, tt := range tests {
		result := layer.extractEmail(tt.body)
		if result != tt.expected {
			t.Errorf("extractEmail(%q) = %q, want %q", tt.body, result, tt.expected)
		}
	}
}

func TestExtractEmail_EmptyBody(t *testing.T) {
	cfg := Config{Enabled: true, LoginPaths: []string{"/login"}}
	layer, _ := NewLayer(&cfg)

	result := layer.extractEmail("")
	if result != "" {
		t.Errorf("expected empty string for empty body, got %q", result)
	}
}

func TestExtractEmail_NoEmailPresent(t *testing.T) {
	cfg := Config{Enabled: true, LoginPaths: []string{"/login"}}
	layer, _ := NewLayer(&cfg)

	tests := []struct {
		body     string
		expected string
	}{
		{`{"password":"secret"}`, ""},
		{`{"name":"john"}`, ""},
		{"password=secret&token=abc", ""},
		{"just some random text", ""},
		{"not=json&not=email", ""},
	}

	for _, tt := range tests {
		result := layer.extractEmail(tt.body)
		if result != tt.expected {
			t.Errorf("extractEmail(%q) = %q, want %q", tt.body, result, tt.expected)
		}
	}
}

func TestExtractEmail_JSON_FallbackFields(t *testing.T) {
	cfg := Config{Enabled: true, LoginPaths: []string{"/login"}}
	layer, _ := NewLayer(&cfg)

	// Email field takes priority
	result := layer.extractEmail(`{"email":"primary@example.com","username":"secondary@example.com"}`)
	if result != "primary@example.com" {
		t.Errorf("expected email field to take priority, got %q", result)
	}

	// Falls back to username when email is empty
	result = layer.extractEmail(`{"username":"fallback@example.com"}`)
	if result != "fallback@example.com" {
		t.Errorf("expected username fallback, got %q", result)
	}

	// Falls back to login when email and username are empty
	result = layer.extractEmail(`{"login":"loginfield@example.com"}`)
	if result != "loginfield@example.com" {
		t.Errorf("expected login fallback, got %q", result)
	}

	// JSON field has non-email value -> not matched
	result = layer.extractEmail(`{"email":"not-an-email"}`)
	if result != "" {
		t.Errorf("expected empty for non-email value in JSON, got %q", result)
	}
}

func TestExtractEmail_FormEncoded_MultiplePairs(t *testing.T) {
	cfg := Config{Enabled: true, LoginPaths: []string{"/login"}}
	layer, _ := NewLayer(&cfg)

	result := layer.extractEmail("password=secret&email=form@example.com&remember=true")
	if result != "form@example.com" {
		t.Errorf("expected form@example.com, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// Process — login path for various methods, blocked IP/email, credential stuffing
// ---------------------------------------------------------------------------

func TestProcess_LoginPath_VariousMethods(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		BruteForce: BruteForceConfig{
			Enabled:             true,
			Window:              time.Hour,
			MaxAttemptsPerIP:    10,
			MaxAttemptsPerEmail: 10,
			BlockDuration:       time.Hour,
		},
	}
	layer, _ := NewLayer(&cfg)

	methods := []string{"GET", "PUT", "DELETE", "PATCH"}
	for _, method := range methods {
		ctx := &engine.RequestContext{
			Path:       "/login",
			Method:     method,
			ClientIP:   net.ParseIP("10.0.0.1"),
			BodyString: `{"email":"test@example.com","password":"secret"}`,
			Headers:    map[string][]string{},
		}
		result := layer.Process(ctx)
		if result.Action != engine.ActionPass {
			t.Errorf("expected pass for %s on login path, got %v", method, result.Action)
		}
	}
}

func TestProcess_NonLoginPath_PassThrough(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		BruteForce: BruteForceConfig{
			Enabled:             true,
			Window:              time.Hour,
			MaxAttemptsPerIP:    1,
			MaxAttemptsPerEmail: 1,
		},
	}
	layer, _ := NewLayer(&cfg)

	paths := []string{"/api/users", "/dashboard", "/healthz", "/v1/data"}
	for _, path := range paths {
		ctx := &engine.RequestContext{
			Path:       path,
			Method:     "POST",
			ClientIP:   net.ParseIP("10.0.0.1"),
			BodyString: `{"email":"test@example.com","password":"secret"}`,
			Headers:    map[string][]string{},
		}
		result := layer.Process(ctx)
		if result.Action != engine.ActionPass {
			t.Errorf("expected pass for non-login path %s, got %v", path, result.Action)
		}
	}
}

func TestProcess_IPAlreadyBlocked(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
	}
	layer, _ := NewLayer(&cfg)

	ip := net.ParseIP("192.0.2.100")
	layer.tracker.BlockIP(ip, time.Now().Add(time.Hour), "previous_violation")

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   ip,
		BodyString: `{"email":"blocked@example.com","password":"secret"}`,
		Headers:    map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for blocked IP, got %v", result.Action)
	}
	if result.Score != 100 {
		t.Errorf("expected score 100 for blocked IP, got %d", result.Score)
	}
}

func TestProcess_EmailAlreadyBlocked(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
	}
	layer, _ := NewLayer(&cfg)

	email := "blocked@example.com"
	layer.tracker.BlockEmail(email, time.Now().Add(time.Hour), "credential_stuffing")

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("10.0.0.1"),
		BodyString: `{"email":"blocked@example.com","password":"secret"}`,
		Headers:    map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for blocked email, got %v", result.Action)
	}
	if result.Score != 100 {
		t.Errorf("expected score 100 for blocked email, got %d", result.Score)
	}
}

func TestProcess_CredentialStuffingThroughProcess(t *testing.T) {
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

	email := "shared@example.com"
	ips := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}

	// Record attempts from 3 different IPs for same email
	for _, ip := range ips {
		layer.tracker.RecordAttempt(&LoginAttempt{
			IP:    net.ParseIP(ip),
			Email: email,
			Time:  time.Now(),
		})
	}

	// 4th IP should trigger credential stuffing
	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("192.168.1.4"),
		BodyString: `{"email":"shared@example.com","password":"guess"}`,
		Headers:    map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for credential stuffing, got %v", result.Action)
	}
	if result.Score != 85 {
		t.Errorf("expected score 85, got %d", result.Score)
	}
}

func TestProcess_RecordsAttemptOnPass(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		BruteForce: BruteForceConfig{
			Enabled:             false,
			MaxAttemptsPerEmail: 100,
		},
	}
	layer, _ := NewLayer(&cfg)

	ip := net.ParseIP("10.0.0.50")
	email := "record@example.com"

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   ip,
		BodyString: `{"email":"record@example.com","password":"test"}`,
		Headers:    map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected pass, got %v", result.Action)
	}

	// Verify attempt was recorded
	count := layer.tracker.GetIPAttempts(ip, time.Hour)
	if count != 1 {
		t.Errorf("expected 1 recorded attempt, got %d", count)
	}
	emailCount := layer.tracker.GetEmailAttempts(email, time.Hour)
	if emailCount != 1 {
		t.Errorf("expected 1 recorded email attempt, got %d", emailCount)
	}
}

// ---------------------------------------------------------------------------
// Process — full integration: all checks enabled
// ---------------------------------------------------------------------------

func TestProcess_AllChecksEnabled_FirstAttemptPasses(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login", "/api/auth"},
		BruteForce: BruteForceConfig{
			Enabled:             true,
			Window:              time.Hour,
			MaxAttemptsPerIP:    5,
			MaxAttemptsPerEmail: 5,
			BlockDuration:       time.Hour,
		},
		CredStuffing: CredentialStuffingConfig{
			Enabled:              true,
			DistributedThreshold: 5,
			Window:               time.Hour,
			BlockDuration:        time.Hour,
		},
		PasswordSpray: PasswordSprayConfig{
			Enabled:       true,
			Threshold:     10,
			Window:        time.Hour,
			BlockDuration: time.Hour,
		},
		Travel: ImpossibleTravelConfig{
			Enabled:       true,
			MaxDistanceKm: 500,
			MaxTimeHours:  2,
			BlockDuration: time.Hour,
		},
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Path:       "/api/auth",
		Method:     "POST",
		ClientIP:   net.ParseIP("10.0.0.1"),
		BodyString: `{"email":"user@example.com","password":"secret"}`,
		Headers:    map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("first attempt should pass, got %v", result.Action)
	}
}

// ---------------------------------------------------------------------------
// LocationDB — exact match and not-found cases
// ---------------------------------------------------------------------------

func TestLocationDB_IPv4ExactMatchOnly(t *testing.T) {
	db := NewLocationDB()

	// Add an exact IP entry
	db.Add("192.168.1.50", &GeoLocation{Country: "US", City: "LA", Latitude: 34.05, Longitude: -118.24})

	loc := db.Lookup(net.ParseIP("192.168.1.50"))
	if loc == nil {
		t.Fatal("expected exact match for 192.168.1.50")
	}
	if loc.City != "LA" {
		t.Errorf("expected LA, got %s", loc.City)
	}

	// Different IP not in DB
	loc = db.Lookup(net.ParseIP("192.168.2.1"))
	if loc != nil {
		t.Error("expected nil for IP not in DB")
	}
}

func TestLocationDB_IPv4PrefixLookup(t *testing.T) {
	db := NewLocationDB()

	// The Lookup method builds prefix as string(ip[:3])+".0/24" using raw bytes.
	// To test the /24 prefix code path, we must add an entry with the raw-byte key format.
	ip := net.ParseIP("10.0.0.5").To4()
	prefix := string(ip[:3]) + ".0/24"
	db.Add(prefix, &GeoLocation{Country: "DE", City: "Berlin", Latitude: 52.5, Longitude: 13.4})

	// 10.0.0.99 should match via /24 prefix since exact match fails first
	loc := db.Lookup(net.ParseIP("10.0.0.99"))
	if loc == nil {
		t.Fatal("expected /24 prefix match for 10.0.0.99")
	}
	if loc.City != "Berlin" {
		t.Errorf("expected Berlin, got %s", loc.City)
	}

	// 10.0.1.1 should not match (different /24)
	loc = db.Lookup(net.ParseIP("10.0.1.1"))
	if loc != nil {
		t.Error("expected nil for IP in different /24")
	}
}

func TestLocationDB_ExactMatchSameIP(t *testing.T) {
	db := NewLocationDB()

	db.Add("10.0.0.1", &GeoLocation{Country: "UK", City: "London", Latitude: 51.5, Longitude: -0.1})

	loc := db.Lookup(net.ParseIP("10.0.0.1"))
	if loc == nil || loc.City != "London" {
		t.Errorf("expected exact match London, got %v", loc)
	}

	loc = db.Lookup(net.ParseIP("10.0.0.2"))
	if loc != nil {
		t.Errorf("expected nil for non-matching IP, got %v", loc)
	}
}

// ---------------------------------------------------------------------------
// blockResult — verify finding fields
// ---------------------------------------------------------------------------

func TestBlockResult_FindingFields(t *testing.T) {
	cfg := Config{Enabled: true, LoginPaths: []string{"/login"}}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("1.2.3.4"),
		BodyString: `{}`,
		Headers:    map[string][]string{},
	}

	result := layer.blockResult(ctx, "test_attack", "test reason", 42)
	if result.Action != engine.ActionBlock {
		t.Error("expected block action")
	}
	if result.Score != 42 {
		t.Errorf("expected score 42, got %d", result.Score)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.DetectorName != "ato_protection" {
		t.Errorf("expected detector 'ato_protection', got %q", f.DetectorName)
	}
	if f.Category != "account_takeover" {
		t.Errorf("expected category 'account_takeover', got %q", f.Category)
	}
	if f.Score != 42 {
		t.Errorf("expected finding score 42, got %d", f.Score)
	}
	if f.MatchedValue != "1.2.3.4" {
		t.Errorf("expected matched value '1.2.3.4', got %q", f.MatchedValue)
	}
	if f.Location != "ip" {
		t.Errorf("expected location 'ip', got %q", f.Location)
	}
}

// ---------------------------------------------------------------------------
// Tracker — email/IP not blocked (no record)
// ---------------------------------------------------------------------------

func TestIsEmailBlocked_NoRecord(t *testing.T) {
	tracker := NewAttemptTracker()
	blocked, reason := tracker.IsEmailBlocked("nonexistent@example.com")
	if blocked {
		t.Error("expected not blocked for nonexistent email")
	}
	if reason != "" {
		t.Errorf("expected empty reason, got %q", reason)
	}
}

func TestIsIPBlocked_NoRecord(t *testing.T) {
	tracker := NewAttemptTracker()
	blocked, reason := tracker.IsIPBlocked(net.ParseIP("10.99.99.99"))
	if blocked {
		t.Error("expected not blocked for nonexistent IP")
	}
	if reason != "" {
		t.Errorf("expected empty reason, got %q", reason)
	}
}

// ---------------------------------------------------------------------------
// Tracker Cleanup — password hash cleanup path
// ---------------------------------------------------------------------------

func TestTracker_Cleanup_PasswordHashes(t *testing.T) {
	tracker := NewAttemptTracker()

	// Record an old password attempt
	tracker.RecordAttempt(&LoginAttempt{
		IP:       net.ParseIP("10.0.0.1"),
		Email:    "old@test.com",
		Password: "old-password",
		Time:     time.Now().Add(-48 * time.Hour),
	})

	// Record a recent password attempt
	tracker.RecordAttempt(&LoginAttempt{
		IP:       net.ParseIP("10.0.0.2"),
		Email:    "new@test.com",
		Password: "new-password",
		Time:     time.Now(),
	})

	// Verify both are tracked before cleanup
	if tracker.GetPasswordUseCount("old-password") != 1 {
		t.Error("expected old password to be tracked before cleanup")
	}
	if tracker.GetPasswordUseCount("new-password") != 1 {
		t.Error("expected new password to be tracked before cleanup")
	}

	tracker.Cleanup(24 * time.Hour)

	// Old password hash should be cleaned up
	if tracker.GetPasswordUseCount("old-password") != 0 {
		t.Error("expected old password hash to be cleaned up")
	}
	// Recent password hash should remain
	if tracker.GetPasswordUseCount("new-password") != 1 {
		t.Error("expected recent password hash to remain after cleanup")
	}
}
