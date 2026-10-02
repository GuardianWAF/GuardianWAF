package ato

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (hunt round 2026-10-02-ato-password-not-recorded): password-spray
// detection was dead in serve mode. Layer.Process extracts the password and
// calls checkPasswordSpray, which counts uses out of the tracker's
// passwordHashes map — and that map is only written by RecordAttempt when
// LoginAttempt.Password is non-empty. The RecordAttempt call at the end of
// Process built &LoginAttempt{IP, Email, Time} and omitted Password, so the
// map stayed empty, the windowed count was always 0, and no configured
// threshold could ever be reached.
//
// These tests drive the real Layer.Process path (the existing spray-window
// regression tests call checkPasswordSpray / RecordAttempt directly, which
// bypassed exactly the wiring that was broken).

func sprayProcessCtx(ip, email, password string) *engine.RequestContext {
	return &engine.RequestContext{
		Method:     "POST",
		Path:       "/login",
		ClientIP:   net.ParseIP(ip),
		BodyString: fmt.Sprintf(`{"email":%q,"password":%q}`, email, password),
		Headers:    map[string][]string{},
	}
}

func newSprayProcessLayer(t *testing.T, threshold int) *Layer {
	t.Helper()
	layer, err := NewLayer(&Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		PasswordSpray: PasswordSprayConfig{
			Enabled:       true,
			Threshold:     threshold,
			Window:        time.Hour,
			BlockDuration: time.Hour,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return layer
}

// The same password sprayed from distinct source IPs must be caught. This is
// the classic spray shape: one password, many IPs, one target account each.
func TestSprayBlocksThroughProcessPath(t *testing.T) {
	layer := newSprayProcessLayer(t, 3)

	blockedAt := -1
	for i := range 6 {
		res := layer.Process(sprayProcessCtx(
			fmt.Sprintf("203.0.113.%d", i+1),
			fmt.Sprintf("victim%d@test.local", i),
			"Summer2024!"))
		if res.Action == engine.ActionBlock {
			blockedAt = i + 1
			break
		}
	}
	if blockedAt < 0 {
		t.Fatalf("password spray through Layer.Process never blocked at threshold 3: " +
			"Process omits LoginAttempt.Password at RecordAttempt, so tracker.passwordHashes stays empty")
	}
}

// Boundary: the threshold-th request must still pass and the one after it
// blocks. Pins that the count accumulates exactly once per request rather than
// double-counting or skipping the boundary.
func TestSprayThresholdBoundaryThroughProcess(t *testing.T) {
	layer := newSprayProcessLayer(t, 3)

	// Uses 1..3 are below the threshold: each is checked against what is
	// already on record, then recorded.
	for i := range 3 {
		res := layer.Process(sprayProcessCtx(
			fmt.Sprintf("198.51.100.%d", i+1),
			fmt.Sprintf("b%d@test.local", i),
			"Boundary-Pw-1"))
		if res.Action == engine.ActionBlock {
			t.Fatalf("blocked at use #%d, before the threshold of 3 was reached", i+1)
		}
	}
	// The check runs BEFORE the record, so the fourth request is the first one
	// that sees three uses of the password on record.
	res := layer.Process(sprayProcessCtx("198.51.100.4", "b4@test.local", "Boundary-Pw-1"))
	if res.Action != engine.ActionBlock {
		t.Fatal("expected a block once three uses of the same password were on record")
	}
}

// Control (must hold before and after the fix): distinct passwords from the
// same IP are NOT a spray. Guards against the fix over-matching.
func TestSprayDistinctPasswordesNotBlocked(t *testing.T) {
	layer := newSprayProcessLayer(t, 3)

	for i := range 8 {
		res := layer.Process(sprayProcessCtx(
			"192.0.2.50",
			fmt.Sprintf("d%d@test.local", i),
			fmt.Sprintf("Unique-Pw-%d", i)))
		if res.Action == engine.ActionBlock {
			t.Fatalf("distinct passwords were flagged as a spray at request %d", i+1)
		}
	}
}

// Control (must hold before and after the fix): brute-force per-IP shares the
// same RecordAttempt sink through the same Process path, so it must keep
// tripping. A regression here would mean the fix disturbed shared tracking.
func TestBruteForcePerIPStillBlocksThroughProcess(t *testing.T) {
	layer, err := NewLayer(&Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		BruteForce: BruteForceConfig{
			Enabled:             true,
			Window:              time.Hour,
			MaxAttemptsPerIP:    3,
			MaxAttemptsPerEmail: 1000,
			BlockDuration:       time.Hour,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	blockedAt := -1
	for i := range 6 {
		res := layer.Process(sprayProcessCtx(
			"198.51.100.7", fmt.Sprintf("c%d@test.local", i), fmt.Sprintf("pw-%d", i)))
		if res.Action == engine.ActionBlock {
			blockedAt = i + 1
			break
		}
	}
	if blockedAt < 0 {
		t.Fatal("brute force per-IP stopped blocking through Process — the shared tracker path regressed")
	}
}

// The tracker must hold the password record after a Process-driven attempt,
// and must not retain the plaintext password.
func TestSprayRecordsPasswordHashNotPlaintext(t *testing.T) {
	layer := newSprayProcessLayer(t, 5)
	const pw = "Plaintext-Canary-9f3a"

	layer.Process(sprayProcessCtx("192.0.2.77", "hash@test.local", pw))

	if got := layer.tracker.GetPasswordUseCount(pw); got != 1 {
		t.Fatalf("expected 1 recorded use of the sprayed password, got %d", got)
	}
	raw, err := layer.tracker.passwordHashes[hashPassword(pw)], error(nil)
	if err != nil || raw == nil {
		t.Fatalf("no password record under the hashed key")
	}
	raw.mu.RLock()
	defer raw.mu.RUnlock()
	if raw.Count != 1 || len(raw.Uses) != 1 {
		t.Fatalf("password record not populated: Count=%d Uses=%d", raw.Count, len(raw.Uses))
	}
	// The record is keyed by the sha256 digest, so the plaintext is never a map key.
	if hashPassword(pw) == pw {
		t.Fatal("hashPassword is not hashing — plaintext would be retained")
	}
}
