package ato

import (
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (round 2026-09-25-credstuffing-window): checkCredentialStuffing
// compared the ALL-TIME emailToIPs unique-IP set against DistributedThreshold
// and never consulted CredentialStuffingConfig.Window, although the field is
// plumbed from YAML through config and the layer registry. The set never
// decays (ClearAttempt does not touch it; Cleanup only removes whole emails
// evicted from emailAttempts), so an email tried from DistributedThreshold
// distinct IPs at any point in the process lifetime kept blocking every later
// login attempt from any IP — and the operator's window knob was a silent
// no-op. Stuffing detection now counts only IPs whose last attempt falls
// inside the configured window; an unset window (<= 0) keeps the legacy
// all-time behavior so deployments that never configured one do not silently
// lose the check.

func newStuffingLayer(window time.Duration, threshold int) *Layer {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		CredStuffing: CredentialStuffingConfig{
			Enabled:              true,
			DistributedThreshold: threshold,
			Window:               window,
			BlockDuration:        time.Hour,
		},
	}
	layer, _ := NewLayer(&cfg)
	return layer
}

func recordStuffingUse(l *Layer, ip, email string, at time.Time) {
	l.tracker.RecordAttempt(&LoginAttempt{
		IP:    net.ParseIP(ip),
		Email: email,
		Time:  at,
	})
}

// Distinct source IPs entirely outside the configured window must not trip
// the distributed threshold.
func TestStuffingWindowExcludesOldIPs(t *testing.T) {
	layer := newStuffingLayer(time.Minute, 3)
	for i := 0; i < 3; i++ {
		recordStuffingUse(layer, "10.6.0."+string(rune('1'+i)), "victim@old.test", time.Now().Add(-5*time.Minute))
	}
	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("10.6.0.9"),
		BodyString: `{"email":"victim@old.test"}`,
		Headers:    map[string][]string{},
	}
	if res := layer.checkCredentialStuffing(ctx, "victim@old.test"); res.Action == engine.ActionBlock {
		t.Fatalf("blocked although zero source IPs fall within the configured 1-minute window (all-time count leak)")
	}
}

// Distinct source IPs inside the window still block at the threshold
// (control: the windowed fix must keep detecting real distributed attacks).
func TestStuffingWindowIncludesRecentIPs(t *testing.T) {
	layer := newStuffingLayer(time.Minute, 3)
	for i := 0; i < 3; i++ {
		recordStuffingUse(layer, "10.6.1."+string(rune('1'+i)), "victim@new.test", time.Now())
	}
	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("10.6.1.9"),
		BodyString: `{"email":"victim@new.test"}`,
		Headers:    map[string][]string{},
	}
	res := layer.checkCredentialStuffing(ctx, "victim@new.test")
	if res.Action != engine.ActionBlock {
		t.Fatalf("in-window distributed spread at threshold did not block (Action=%v)", res.Action)
	}
	if res.Score != 85 {
		t.Fatalf("stuffing block score = %d, want 85", res.Score)
	}
}

// An unset window (<= 0) keeps the legacy all-time behavior: old IPs still
// count, so deployments that never configured a window do not silently lose
// stuffing detection.
func TestStuffingZeroWindowKeepsLegacyAllTimeCount(t *testing.T) {
	layer := newStuffingLayer(0, 3)
	for i := 0; i < 3; i++ {
		recordStuffingUse(layer, "10.6.2."+string(rune('1'+i)), "victim@legacy.test", time.Now().Add(-5*time.Minute))
	}
	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("10.6.2.9"),
		BodyString: `{"email":"victim@legacy.test"}`,
		Headers:    map[string][]string{},
	}
	if res := layer.checkCredentialStuffing(ctx, "victim@legacy.test"); res.Action != engine.ActionBlock {
		t.Fatalf("window<=0 must keep the legacy all-time count (Action=%v)", res.Action)
	}
}

// A repeat attempt from a KNOWN source IP inside the window refreshes its
// last-seen timestamp and still counts once (not twice) toward the threshold.
func TestStuffingWindowRepeatIPCountsOnce(t *testing.T) {
	layer := newStuffingLayer(time.Minute, 3)
	now := time.Now()
	recordStuffingUse(layer, "10.6.3.1", "repeat@probe.test", now.Add(-30*time.Second))
	recordStuffingUse(layer, "10.6.3.1", "repeat@probe.test", now)
	recordStuffingUse(layer, "10.6.3.2", "repeat@probe.test", now)
	recordStuffingUse(layer, "10.6.3.3", "repeat@probe.test", now)
	if got := layer.tracker.GetUniqueIPsForEmail("repeat@probe.test", time.Minute); got != 3 {
		t.Fatalf("windowed unique-IP count = %d, want 3 (repeat IP must refresh, not duplicate)", got)
	}
}
