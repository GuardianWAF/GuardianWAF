package ato

// Regression (round 2026-10-20-r7): the password-spray threshold counted raw
// password USES instead of distinct ACCOUNTS.
//
// ADR 0030 (Status: Implemented) defines a spray as "the same password hash
// seen against threshold+ different accounts" / "one common password across
// many accounts (defeating per-account brute force limits)", and the alert
// reason is "Many accounts targeted". The check compared the number of
// submissions of a password against the threshold, so a single account
// submitting the same password repeatedly — a user fumbling their own
// password — tripped the threshold and the WAF answered 403 with a "common
// password attack" verdict, although no second account was ever targeted.
// The per-account brute-force detector owns that case.
//
// These tests drive the real Layer.Process path.

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// sprayAcctSecret is a fixed test credential used only by these tests.
const sprayAcctSecret = "SprayAcct-Pw-7c1e"

func sprayAcctCtx(ip, email string) *engine.RequestContext {
	return &engine.RequestContext{
		Method:     "POST",
		Path:       "/login",
		ClientIP:   net.ParseIP(ip),
		BodyString: fmt.Sprintf(`{"email":%q,"password":%q}`, email, sprayAcctSecret),
		Headers:    map[string][]string{},
	}
}

func newSprayAcctLayer(t *testing.T, threshold int) *Layer {
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

// A single account repeating one password is NOT a spray: the account is the
// unit of the detection (ADR 0030). Before the fix the use count reached the
// threshold and the request was blocked.
func TestSprayCountsDistinctAccountsNotUses(t *testing.T) {
	layer := newSprayAcctLayer(t, 3)

	for i := 1; i <= 4; i++ {
		res := layer.Process(sprayAcctCtx("198.51.100.5", "one-account@example.test"))
		if res.Action == engine.ActionBlock {
			t.Fatalf("attempt #%d against a SINGLE account was blocked: %+v — password_spray "+
				"must count distinct accounts (ADR 0030: \"the same password hash seen against "+
				"threshold+ different accounts\"), not raw submissions", i, res.Findings)
		}
	}
}

// Control: the same password against DISTINCT accounts IS a spray and must
// still be blocked. Guards against the fix disabling the detector.
func TestSprayStillBlocksDistinctAccounts(t *testing.T) {
	layer := newSprayAcctLayer(t, 3)

	blocked := false
	for i := 1; i <= 6; i++ {
		res := layer.Process(sprayAcctCtx(
			fmt.Sprintf("203.0.113.%d", i),
			fmt.Sprintf("victim%d@example.test", i),
		))
		if res.Action == engine.ActionBlock {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Fatal("the same password against distinct accounts was never blocked — spray " +
			"detection itself is broken")
	}
}

// Boundary: threshold-1 distinct accounts pass, the threshold-th one blocks.
func TestSprayDistinctAccountThresholdBoundary(t *testing.T) {
	layer := newSprayAcctLayer(t, 3)

	for i := 1; i <= 3; i++ {
		res := layer.Process(sprayAcctCtx(
			fmt.Sprintf("198.51.100.%d", i),
			fmt.Sprintf("acct%d@example.test", i),
		))
		if res.Action == engine.ActionBlock {
			t.Fatalf("blocked at account #%d, before the threshold of 3 was reached", i)
		}
	}
	res := layer.Process(sprayAcctCtx("198.51.100.9", "acct4@example.test"))
	if res.Action != engine.ActionBlock {
		t.Fatal("expected a block once three distinct accounts used the same password")
	}
}

// The tracker counts DISTINCT accounts per password, and the windowed count
// ignores accounts whose last use fell outside the operator's window.
func TestTrackerCountsDistinctAccountsPerPassword(t *testing.T) {
	tracker := NewAttemptTracker()

	// One account, three uses: one account.
	for range 3 {
		tracker.RecordAttempt(&LoginAttempt{
			IP:       net.ParseIP("10.9.0.1"),
			Email:    "repeat@example.test",
			Password: sprayAcctSecret,
			Time:     time.Now(),
		})
	}
	if got := tracker.GetPasswordAccountCount(sprayAcctSecret, time.Hour); got != 1 {
		t.Fatalf("distinct accounts = %d, want 1 (three uses of one account)", got)
	}
	if got := tracker.GetPasswordUseCount(sprayAcctSecret); got != 3 {
		t.Fatalf("recorded uses = %d, want 3", got)
	}

	// Two more accounts: three distinct accounts.
	for _, email := range []string{"b@example.test", "c@example.test"} {
		tracker.RecordAttempt(&LoginAttempt{
			IP:       net.ParseIP("10.9.0.2"),
			Email:    email,
			Password: sprayAcctSecret,
			Time:     time.Now(),
		})
	}
	if got := tracker.GetPasswordAccountCount(sprayAcctSecret, time.Hour); got != 3 {
		t.Fatalf("distinct accounts = %d, want 3", got)
	}

	// An account whose last use is outside the window must not count.
	tracker.RecordAttempt(&LoginAttempt{
		IP:       net.ParseIP("10.9.0.3"),
		Email:    "stale@example.test",
		Password: sprayAcctSecret,
		Time:     time.Now().Add(-5 * time.Minute),
	})
	if got := tracker.GetPasswordAccountCount(sprayAcctSecret, time.Minute); got != 3 {
		t.Fatalf("in-window distinct accounts = %d, want 3 (the stale account must not count)", got)
	}
	// An unset window keeps the all-time behavior.
	if got := tracker.GetPasswordAccountCount(sprayAcctSecret, 0); got != 4 {
		t.Fatalf("all-time distinct accounts = %d, want 4", got)
	}
}
