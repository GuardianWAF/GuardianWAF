package ato

import (
	"net"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: PostProcess never wrote the impossible-travel state maps, so
// checkImpossibleTravel's getLastLoginLocation/Time always returned empty and
// the feature was inert regardless of configuration. A successful login must
// record the login location and timestamp; failed logins must not.

func loginCtx(ip net.IP, body string) *engine.RequestContext {
	return &engine.RequestContext{
		Method:     "POST",
		Path:       "/login",
		ClientIP:   ip,
		BodyString: body,
	}
}

func TestPostProcessRecordsTravelState(t *testing.T) {
	l, err := NewLayer(&Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		Travel:     ImpossibleTravelConfig{Enabled: true},
		GeoDBPath:  "stub",
	})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	// Seed the location DB so getLocation resolves for the login IP.
	l.locationDB.Add("10.0.0.5", &GeoLocation{Latitude: 40.7128, Longitude: -74.006})

	body := `{"email":"user@example.com","password":"secret"}`
	l.PostProcess(loginCtx(net.ParseIP("10.0.0.5"), body), true)

	if l.getLastLoginLocation("user@example.com") == nil {
		t.Fatalf("FAIL: successful login recorded no travel location — impossible-travel detection can never trigger because state is never written")
	}
	if l.getLastLoginTime("user@example.com").IsZero() {
		t.Fatalf("FAIL: successful login recorded no travel timestamp")
	}
}

func TestPostProcessFailedLoginDoesNotRecordTravelState(t *testing.T) {
	l, err := NewLayer(&Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		Travel:     ImpossibleTravelConfig{Enabled: true},
		GeoDBPath:  "stub",
	})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	l.locationDB.Add("10.0.0.6", &GeoLocation{Latitude: 51.5074, Longitude: -0.1278})

	body := `{"email":"victim@example.com","password":"wrong"}`
	l.PostProcess(loginCtx(net.ParseIP("10.0.0.6"), body), false)

	if l.getLastLoginLocation("victim@example.com") != nil {
		t.Fatalf("FAIL: failed login recorded travel state — only successful logins establish a travel baseline")
	}
}
