package ato

import (
	"fmt"
	"math"
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestLayerOrder(t *testing.T) {
	layer, err := NewLayer(&Config{Enabled: true, LoginPaths: []string{"/login"}})
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}
	if got := layer.Order(); got != engine.OrderATO {
		t.Fatalf("Order() = %d, want %d", got, engine.OrderATO)
	}
}

func TestProcess_TenantDisabledOverride(t *testing.T) {
	layer, err := NewLayer(&Config{Enabled: true, LoginPaths: []string{"/login"}})
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	ctx := &engine.RequestContext{
		Path:      "/login",
		Method:    "POST",
		ClientIP:  net.ParseIP("192.0.2.10"),
		BodyString: `{"email":"tenant@example.com","password":"secret"}`,
		Headers:   map[string][]string{},
		TenantWAFConfig: &config.WAFConfig{
			ATOProtection: config.ATOProtectionConfig{Enabled: false},
		},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected pass when tenant disables ATO, got %v", result.Action)
	}
	if got := layer.tracker.GetIPAttempts(ctx.ClientIP, time.Hour); got != 0 {
		t.Fatalf("expected no tracking when tenant disables layer, got %d attempts", got)
	}
}

func TestCheckImpossibleTravel_EarlyReturnBranches(t *testing.T) {
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
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	email := "traveler@example.com"
	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("203.0.113.10"),
		BodyString: `{"email":"traveler@example.com"}`,
		Headers:    map[string][]string{},
	}
	layer.locationDB.Add("203.0.113.10", &GeoLocation{Latitude: 40.7128, Longitude: -74.0060})
	layer.lastLogin[email] = &GeoLocation{Latitude: 51.5074, Longitude: -0.1278}

	layer.lastTime[email] = time.Time{}
	if result := layer.checkImpossibleTravel(ctx, email); result.Action != engine.ActionPass {
		t.Fatalf("expected pass when last login time is zero, got %v", result.Action)
	}

	layer.lastTime[email] = time.Now().Add(-30 * time.Second)
	if result := layer.checkImpossibleTravel(ctx, email); result.Action != engine.ActionPass {
		t.Fatalf("expected pass for sub-minute travel window, got %v", result.Action)
	}

	layer.lastTime[email] = time.Now().Add(-3 * time.Hour)
	if result := layer.checkImpossibleTravel(ctx, email); result.Action != engine.ActionPass {
		t.Fatalf("expected pass when time diff exceeds configured window, got %v", result.Action)
	}
}

func TestProcess_ImpossibleTravelBlocks(t *testing.T) {
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
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	email := "process-traveler@example.com"
	layer.locationDB.Add("198.51.100.25", &GeoLocation{Latitude: 40.7128, Longitude: -74.0060})
	layer.lastLogin[email] = &GeoLocation{Latitude: 51.5074, Longitude: -0.1278}
	layer.lastTime[email] = time.Now().Add(-30 * time.Minute)

	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("198.51.100.25"),
		BodyString: `{"email":"process-traveler@example.com","password":"secret"}`,
		Headers:    map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Fatalf("expected impossible travel to block through Process, got %v", result.Action)
	}
}

func TestLayerCleanup_RemovesStaleAndAggressiveEntries(t *testing.T) {
	layer, err := NewLayer(&Config{Enabled: true, LoginPaths: []string{"/login"}})
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	staleEmail := "stale@example.com"
	layer.lastTime[staleEmail] = time.Now().Add(-49 * time.Hour)
	layer.lastLogin[staleEmail] = &GeoLocation{Latitude: 1, Longitude: 1}

	for i := 0; i < 100001; i++ {
		email := fmt.Sprintf("old-%d@example.com", i)
		layer.lastTime[email] = time.Now().Add(-2 * time.Hour)
		layer.lastLogin[email] = &GeoLocation{Latitude: 10, Longitude: 10}
	}
	freshEmail := "fresh@example.com"
	layer.lastTime[freshEmail] = time.Now().Add(-30 * time.Minute)
	layer.lastLogin[freshEmail] = &GeoLocation{Latitude: 20, Longitude: 20}

	layer.Cleanup()

	if _, ok := layer.lastTime[staleEmail]; ok {
		t.Fatal("expected stale travel timestamp to be removed")
	}
	if _, ok := layer.lastLogin[staleEmail]; ok {
		t.Fatal("expected stale travel location to be removed")
	}
	if _, ok := layer.lastTime[freshEmail]; !ok {
		t.Fatal("expected fresh travel timestamp to remain")
	}
	if _, ok := layer.lastLogin[freshEmail]; !ok {
		t.Fatal("expected fresh travel location to remain")
	}
	for email, ts := range layer.lastTime {
		if email != freshEmail && time.Since(ts) > time.Hour {
			t.Fatalf("expected aggressive cleanup to remove old over-cap entry %q", email)
		}
	}
}

func TestHaversineDistance_InvalidCoordinatesReturnZero(t *testing.T) {
	loc1 := &GeoLocation{Latitude: math.NaN(), Longitude: 0}
	loc2 := &GeoLocation{Latitude: 0, Longitude: 0}
	if got := haversineDistance(loc1, loc2); got != 0 {
		t.Fatalf("expected 0 for NaN coordinates, got %v", got)
	}

	loc3 := &GeoLocation{Latitude: 91, Longitude: 0}
	if got := haversineDistance(loc3, loc2); got != 0 {
		t.Fatalf("expected 0 for out-of-range coordinates, got %v", got)
	}
}

func TestAttemptTrackerRecordAttempt_DropsNewIPWhenCapReached(t *testing.T) {
	tracker := NewAttemptTracker()
	tracker.maxEntries = 1
	now := time.Now()

	tracker.RecordAttempt(&LoginAttempt{IP: net.ParseIP("192.0.2.1"), Email: "first@example.com", Time: now})
	tracker.RecordAttempt(&LoginAttempt{IP: net.ParseIP("192.0.2.2"), Email: "second@example.com", Time: now})

	if got := tracker.GetIPAttempts(net.ParseIP("192.0.2.1"), time.Hour); got != 1 {
		t.Fatalf("expected first IP to remain tracked, got %d", got)
	}
	if got := tracker.GetIPAttempts(net.ParseIP("192.0.2.2"), time.Hour); got != 0 {
		t.Fatalf("expected second IP to be dropped when cap reached, got %d", got)
	}
}
