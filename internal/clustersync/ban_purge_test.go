package clustersync

import (
	"encoding/json"
	"testing"
	"time"
)

// Regression tests: applying a ban command must opportunistically reclaim
// already-expired ban entries. PurgeExpiredBans — the bans janitor — has no
// production caller, so expired bans used to linger forever: IsBanned/BannedIPs
// filter them on read (behavior was correct) but the map itself only ever
// grew, unless an operator issued an explicit CmdUnbanIP per IP. The sweep now
// runs in applyBanIP (ban commands are rare, so O(n) is free), mirroring
// sweepStaleCounters for the counters map. Permanent bans (zero ExpiresAt) and
// live bans are preserved.

func TestApplyBanIPReclaimsExpiredBans(t *testing.T) {
	s := NewReplicatedStore()
	now := time.Now()

	seed := func(ip string, expires time.Time) {
		t.Helper()
		s.mu.Lock()
		s.bans[ip] = BanEntry{IP: ip, BannedAt: now.Add(-2 * time.Hour), ExpiresAt: expires}
		s.mu.Unlock()
	}
	// Expired, live, and permanent (Duration 0 => zero ExpiresAt) entries.
	seed("expired-1", now.Add(-time.Hour))
	seed("expired-2", now.Add(-time.Minute))
	seed("live", now.Add(time.Hour))
	seed("permanent", time.Time{})

	applyBan := func(ip string, duration time.Duration) {
		t.Helper()
		payload, err := json.Marshal(BanIPPayload{IP: ip, Duration: duration})
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		if err := s.Apply(Command{Type: CmdBanIP, Payload: payload}); err != nil {
			t.Fatalf("Apply ban %s: %v", ip, err)
		}
	}
	applyBan("fresh", time.Hour)

	// Expired entries reclaimed; live, permanent, and the new entry kept.
	if got := s.Stats().Bans; got != 3 {
		t.Fatalf("FAIL: %d ban entries retained after reclamation (want 3: fresh+live+permanent) — expired bans leak", got)
	}
	if s.IsBanned("expired-1") || s.IsBanned("expired-2") {
		t.Fatal("expired IPs report banned after reclamation")
	}
	if !s.IsBanned("fresh") || !s.IsBanned("live") || !s.IsBanned("permanent") {
		t.Fatal("live/permanent bans lost during reclamation")
	}
	if bans := s.BannedIPs(); len(bans) != 3 {
		t.Fatalf("BannedIPs returned %d entries, want 3", len(bans))
	}

	// The sweep is repeatable: a second ban command keeps the map bounded.
	applyBan("fresh-2", time.Hour)
	if got := s.Stats().Bans; got != 4 {
		t.Fatalf("second ban command changed retention (got %d, want 4)", got)
	}
}

// Control: Apply(CmdUnbanIP) must still remove exactly its own entry.
func TestApplyUnbanIPRemovesEntry(t *testing.T) {
	s := NewReplicatedStore()
	now := time.Now()

	s.mu.Lock()
	s.bans["target"] = BanEntry{IP: "target", BannedAt: now, ExpiresAt: now.Add(time.Hour)}
	s.bans["keep"] = BanEntry{IP: "keep", BannedAt: now, ExpiresAt: now.Add(time.Hour)}
	s.mu.Unlock()

	payload, err := json.Marshal(UnbanIPPayload{IP: "target"})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if err := s.Apply(Command{Type: CmdUnbanIP, Payload: payload}); err != nil {
		t.Fatalf("Apply unban: %v", err)
	}

	if s.IsBanned("target") {
		t.Fatal("unbanned IP still reports banned")
	}
	if !s.IsBanned("keep") {
		t.Fatal("unban removed an unrelated entry")
	}
}
