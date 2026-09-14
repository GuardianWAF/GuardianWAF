package ratelimit

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (hunt round 7/25): CleanupExpired's violation-counter sweep
// probed the bucket map with the exact "violation:"-stripped key
// (<ruleID>:<tenantID>:<ip>). For "ip+path"-scoped rules the actual bucket
// key carries a fourth ":<path>" segment, so the probe never matched and the
// sweep deleted the violation counter WHILE the bucket still existed —
// resetting the auto-ban accumulator on every cleanup run. An attacker
// violating at a rate below AutoBanAfter-per-cleanup-interval was never
// auto-banned, defeating the cumulative escalation for every ip+path rule.

func newIPPathAutoBanLayer() *Layer {
	return NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Scope: "ip+path", Limit: 1, Window: time.Minute,
			Burst: 1, Action: "block", AutoBanAfter: 3,
		}},
	})
}

func TestCleanupExpiredKeepsIPPathViolationCounters(t *testing.T) {
	l := newIPPathAutoBanLayer()
	var bans int
	l.OnAutoBan = func(ip, reason string) { bans++ }

	violate := func() {
		l.Process(&engine.RequestContext{
			ClientIP: net.ParseIP("203.0.113.7"),
			Path:     "/api/login",
		})
	}

	violate() // consumes the single token (no violation)
	violate() // violation 1
	violate() // violation 2

	// The bucket was just accessed, so the bucket-eviction loop keeps it;
	// the violation sweep is the only thing that can reset the counter here.
	l.CleanupExpired(time.Minute)

	violate() // violation 3 -> the auto-ban must fire
	if bans != 1 {
		t.Fatalf("FAIL: auto-ban never fired after 3 violations across a CleanupExpired run (bans=%d) — the ip+path violation counter is reset while its bucket still exists", bans)
	}
}

// Control pinning the original cleanup intent: an "ip"-scoped rule's
// violation counter is keyed exactly like its bucket, so when the bucket is
// genuinely evicted (stale), the counter must go with it.
func TestCleanupExpiredStillRemovesStaleIPScopeCounters(t *testing.T) {
	l := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r2", Scope: "ip", Limit: 1, Window: time.Minute,
			Burst: 1, Action: "block", AutoBanAfter: 100,
		}},
	})
	l.OnAutoBan = func(ip, reason string) {}

	violate := func() {
		l.Process(&engine.RequestContext{
			ClientIP: net.ParseIP("203.0.113.7"),
			Path:     "/api/login",
		})
	}
	violate()
	violate() // counter = 1, bucket freshly accessed

	// Negative staleDuration puts the cutoff in the future: the just-used
	// bucket is evicted as stale and the violation counter must follow.
	l.CleanupExpired(-time.Minute)

	if n := countMapEntries(&l.violations); n != 0 {
		t.Fatalf("FAIL: stale ip-scope violation counter survived cleanup (counters=%d)", n)
	}
	if n := countMapEntries(&l.buckets); n != 0 {
		t.Fatalf("FAIL: expected the stale bucket to be evicted, got %d", n)
	}
}

func countMapEntries(m *sync.Map) int {
	n := 0
	m.Range(func(any, any) bool { n++; return true })
	return n
}
