package clustersync

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Regression tests: negative ban durations are out-of-domain input and must be
// rejected at both seams. NewBanCommand (the constructor behind
// API.ProposeBan, driven by dashboard operator input) used to accept them, and
// applyBanIP only sets ExpiresAt for positive durations — so a request for a
// FINITE ban silently escalated to a PERMANENT ban (ExpiresAt never set).
// Documented semantics: 0 = permanent, > 0 = finite.

func TestNewBanCommandRejectsNegativeDuration(t *testing.T) {
	cases := []time.Duration{-time.Hour, -time.Minute, -time.Nanosecond}
	for _, d := range cases {
		_, err := NewBanCommand("10.0.0.1", d)
		if err == nil {
			t.Fatalf("FAIL: NewBanCommand accepted negative duration %v", d)
		}
		if !strings.Contains(err.Error(), "invalid ban duration") {
			t.Fatalf("unexpected error for %v: %v", d, err)
		}
	}

	// Legitimate semantics unchanged: 0 = permanent, positive = finite.
	for _, d := range []time.Duration{0, time.Hour, time.Nanosecond} {
		if _, err := NewBanCommand("10.0.0.1", d); err != nil {
			t.Fatalf("NewBanCommand rejected legitimate duration %v: %v", d, err)
		}
	}
}

// Raft-replay hardening: a hand-built negative-duration command (as a buggy
// or hostile authenticated peer could put in the log) must be rejected by
// Apply and must not create a ban entry.
func TestApplyRejectsNegativeDurationBan(t *testing.T) {
	s := NewReplicatedStore()

	payload, err := json.Marshal(BanIPPayload{IP: "10.0.0.7", Duration: -time.Hour})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if err := s.Apply(Command{Type: CmdBanIP, Payload: payload}); err == nil {
		t.Fatal("FAIL: Apply accepted a negative-duration ban command")
	}
	if s.IsBanned("10.0.0.7") {
		t.Fatal("FAIL: negative-duration command created a ban entry")
	}

	// The store is undamaged: a legitimate ban still applies.
	ok, err := NewBanCommand("10.0.0.8", time.Hour)
	if err != nil {
		t.Fatalf("NewBanCommand: %v", err)
	}
	if err := s.Apply(ok); err != nil {
		t.Fatalf("Apply legitimate ban after rejection: %v", err)
	}
	if !s.IsBanned("10.0.0.8") {
		t.Fatal("legitimate ban not applied after a rejection")
	}
}
