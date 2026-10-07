package ato

import (
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: the IP-block verdict must not depend on the request body.
//
// Process used to extract the email first and return ActionPass when the body
// carried no credentials — before it ever consulted the IP block list. A banned
// IP could therefore slip a request through a login path just by sending a body
// the parser could not read, or by omitting credentials entirely, which makes
// the IP ban a body-dependent control that the caller chooses.
//
// The IP check now runs first, so a banned IP is blocked regardless of the body.
// Email extraction and the empty-email pass-through still apply to every other
// IP, and an unbanned IP sending an unparseable body still passes.

const (
	atoBannedIP = "203.0.113.7"  // TEST-NET-3, reserved for documentation
	atoCleanIP  = "198.51.100.9" // TEST-NET-2, reserved for documentation
)

func TestBannedIPIsBlockedEvenWhenTheBodyHasNoCredentials(t *testing.T) {
	l, err := NewLayer(&Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		BruteForce: BruteForceConfig{
			Enabled:             true,
			Window:              time.Hour,
			MaxAttemptsPerIP:    3,
			MaxAttemptsPerEmail: 10,
			BlockDuration:       time.Minute,
		},
	})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}

	banned := net.ParseIP(atoBannedIP)
	clean := net.ParseIP(atoCleanIP)

	l.tracker.BlockIP(banned, time.Now().Add(time.Hour), "prior ban")

	// HARNESS: the ban really is in place, so a pass below would be the
	// ordering under test rather than a setup that failed to block anything.
	if blocked, _ := l.tracker.IsIPBlocked(banned); !blocked {
		t.Fatalf("HARNESS FAIL: %s is not banned, so this test cannot observe the check order", atoBannedIP)
	}

	const unreadableBody = "this is not a login payload"

	// The behaviour under test: a banned IP is blocked even though the body
	// carries no credentials for the parser to find.
	if res := l.Process(loginCtx(banned, unreadableBody)); res.Action != engine.ActionBlock {
		t.Fatalf("banned IP %s sent a body with no credentials and was answered %s; "+
			"the IP block must not depend on whether the body parses", atoBannedIP, res.Action)
	}

	// Control 1: the same body from an unbanned IP still passes — the layer
	// is not simply blocking every login-path request.
	if res := l.Process(loginCtx(clean, unreadableBody)); res.Action != engine.ActionPass {
		t.Fatalf("unbanned IP %s sending a body with no credentials must pass through, got %s",
			atoCleanIP, res.Action)
	}

	// Control 2: a banned IP sending real credentials is still blocked, so the
	// reorder left the ordinary banned-IP path intact.
	if res := l.Process(loginCtx(banned, "email=user%40example.com&password=hunter2")); res.Action != engine.ActionBlock {
		t.Fatalf("banned IP %s with valid credentials must be blocked, got %s", atoBannedIP, res.Action)
	}
}
