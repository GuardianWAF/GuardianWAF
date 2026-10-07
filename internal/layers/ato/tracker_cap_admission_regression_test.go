package ato

// Regression: the outer-map cap must never cost the tracker attempt evidence.
//
// RecordAttempt enforced maxEntries inconsistently across its sibling branches.
// The IP branch evicted and then inserted unconditionally, so a new IP kept its
// record even when eviction could free nothing. The email and password branches
// instead re-checked the cap and silently discarded a BRAND-NEW key's first
// attempt whenever the map was full and every stored record was still blocked:
//
//	if emailRec != nil || t.maxEntries <= 0 || len(t.emailAttempts) < t.maxEntries {
//	    ...insert...
//	}
//
// Consequences of the drop, both security-relevant:
//
//   - GetEmailAttempts returns 0 for that email, so the per-email brute-force
//     counter never starts. A correct password following a mistyped one is
//     answered as a fresh attempt instead of one that counts.
//   - The asymmetry made the two detectors behave differently under identical
//     pressure: the same attacker is throttled by IP but not by email, so
//     per-IP brute force kept working while per-email silently stopped.
//
// maxEntries is a best-effort memory guard, not an admission limit. The tracker
// evicts the oldest non-blocked record and, when none is available, grows past
// the cap rather than dropping security evidence — the same principle
// TestAttemptTrackerBlockListsAlreadyRecorded applies to explicit blocks.
//
// Memory stays bounded in practice: Cleanup removes records with no attempts
// inside maxAge that are not blocked, and blocks expire on their own.

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// recordEmailAttempt records one attempt for ip/email/password.
func recordEmailAttempt(tr *AttemptTracker, ip, email, password string) {
	tr.RecordAttempt(&LoginAttempt{
		IP:       net.ParseIP(ip),
		Email:    email,
		Password: password,
		Time:     time.Now(),
	})
}

// saturatedTracker returns a tracker whose emailAttempts and passwordHashes maps
// are full and whose every stored record is blocked, so evictOldestAttempt frees
// nothing on either map.
func saturatedTracker(t *testing.T) *AttemptTracker {
	t.Helper()
	tr := NewAttemptTracker()
	tr.maxEntries = 2

	for i := 0; i < 2; i++ {
		email := fmt.Sprintf("filler-%d@example.com", i)
		recordEmailAttempt(tr, fmt.Sprintf("10.1.0.%d", i+1), email, fmt.Sprintf("filler-pw-%d", i))
		tr.BlockEmail(email, time.Now().Add(time.Hour), "saturating the map")
	}
	return tr
}

func TestSaturationDoesNotDiscardAttemptEvidence(t *testing.T) {
	tr := saturatedTracker(t)

	// HARNESS: both maps are full and fully blocked, so eviction cannot free a
	// slot. Without this the test could pass for the wrong reason.
	if got := tr.Stats()["tracked_emails"]; got != tr.maxEntries {
		t.Fatalf("HARNESS FAIL: tracked_emails = %d, want the map saturated at %d", got, tr.maxEntries)
	}
	if n, _ := blockedEmailCountForSaturationTest(tr); n != tr.maxEntries {
		t.Fatalf("HARNESS FAIL: expected %d blocked email records, got %d", tr.maxEntries, n)
	}

	recordEmailAttempt(tr, "10.1.0.99", "fresh@example.com", "fresh-password")

	// The email branch: a new email's first attempt must not be discarded.
	if got := tr.GetEmailAttempts("fresh@example.com", time.Hour); got != 1 {
		t.Fatalf("email evidence discarded under saturation: GetEmailAttempts(fresh) = %d, want 1 — "+
			"maxEntries must not silently drop a new key's first attempt", got)
	}

	// The password branch: same contract, same reasoning.
	if got := tr.GetPasswordUseCount("fresh-password"); got != 1 {
		t.Fatalf("password evidence discarded under saturation: GetPasswordUseCount = %d, want 1 — "+
			"maxEntries must not silently drop a new key's first attempt", got)
	}

	// The IP branch already behaved this way; assert it so the three sibling
	// branches cannot drift apart again.
	if got := tr.GetIPAttempts(net.ParseIP("10.1.0.99"), time.Hour); got != 1 {
		t.Fatalf("IP evidence discarded under saturation: GetIPAttempts = %d, want 1", got)
	}
}

// Control: with nothing blocked, eviction succeeds and the cap still holds, so
// admitting new keys does not turn the guard off in the ordinary case.
func TestSaturationGuardStillBoundsMapsWhenEvictionCanHelp(t *testing.T) {
	tr := NewAttemptTracker()
	tr.maxEntries = 2
	now := time.Now()

	for i := 0; i < 5; i++ {
		tr.RecordAttempt(&LoginAttempt{
			IP:       net.ParseIP(fmt.Sprintf("10.2.0.%d", i+1)),
			Email:    fmt.Sprintf("user-%d@example.com", i),
			Password: fmt.Sprintf("password-%d", i),
			Time:     now,
		})
	}

	stats := tr.Stats()
	for _, key := range []string{"tracked_ips", "tracked_emails", "tracked_passwords"} {
		if stats[key] > tr.maxEntries {
			t.Fatalf("%s = %d, want <= %d when eviction is able to free a slot", key, stats[key], tr.maxEntries)
		}
	}
}

func blockedEmailCountForSaturationTest(tr *AttemptTracker) (int, string) {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	now := time.Now()
	n := 0
	for _, rec := range tr.emailAttempts {
		rec.mu.RLock()
		if now.Before(rec.BlockedUntil) {
			n++
		}
		rec.mu.RUnlock()
	}
	return n, ""
}
