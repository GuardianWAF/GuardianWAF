package ato

import (
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (round 2026-09-18): checkPasswordSpray compared the ALL-TIME
// PasswordRecord.Count against the threshold and never consulted
// PasswordSprayConfig.Window, although the field is plumbed from YAML through
// config and the layer registry. A password whose Count crossed the threshold
// at any point in the past kept blocking every later source IP that submitted
// it — hours or days after any actual spray — and the operator's window knob
// was a silent no-op. Spray detection now counts uses inside the configured
// window; an unset window (<= 0) keeps the legacy all-time behavior so
// deployments that never configured one do not silently lose the check.

func newSprayLayer(window time.Duration, threshold int) *Layer {
	cfg := Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		PasswordSpray: PasswordSprayConfig{
			Enabled:       true,
			Threshold:     threshold,
			Window:        window,
			BlockDuration: time.Hour,
		},
	}
	layer, _ := NewLayer(&cfg)
	return layer
}

func recordSprayUse(l *Layer, ip, email, password string, at time.Time) {
	l.tracker.RecordAttempt(&LoginAttempt{
		IP:       net.ParseIP(ip),
		Email:    email,
		Password: password,
		Time:     at,
	})
}

// Uses entirely outside the configured window must not trip the threshold.
func TestSprayWindowExcludesOldUses(t *testing.T) {
	layer := newSprayLayer(time.Minute, 3)
	for i := 0; i < 3; i++ {
		recordSprayUse(layer, "10.5.0."+string(rune('1'+i)), string(rune('a'+i))+"@old.test", "gw-oldpwd-probe", time.Now().Add(-5*time.Minute))
	}
	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("10.5.0.9"),
		BodyString: `{"email":"old@probe.test"}`,
		Headers:    map[string][]string{},
	}
	if res := layer.checkPasswordSpray(ctx, "gw-oldpwd-probe"); res.Action == engine.ActionBlock {
		t.Fatalf("blocked although zero uses fall within the configured 1-minute window")
	}
}

// Uses inside the window still block at the threshold.
func TestSprayWindowIncludesRecentUses(t *testing.T) {
	layer := newSprayLayer(time.Minute, 3)
	for i := 0; i < 3; i++ {
		recordSprayUse(layer, "10.5.1."+string(rune('1'+i)), string(rune('a'+i))+"@new.test", "gw-newpwd-probe", time.Now())
	}
	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("10.5.1.9"),
		BodyString: `{"email":"new@probe.test"}`,
		Headers:    map[string][]string{},
	}
	res := layer.checkPasswordSpray(ctx, "gw-newpwd-probe")
	if res.Action != engine.ActionBlock {
		t.Fatalf("in-window uses at threshold did not block (Action=%v)", res.Action)
	}
	if res.Score != 75 {
		t.Fatalf("spray block score = %d, want 75", res.Score)
	}
}

// An unset window (<= 0) keeps the legacy all-time behavior: old uses still
// count, so deployments that never configured a window do not silently lose
// spray detection.
func TestSprayZeroWindowKeepsLegacyAllTimeCount(t *testing.T) {
	layer := newSprayLayer(0, 3)
	for i := 0; i < 3; i++ {
		recordSprayUse(layer, "10.5.2."+string(rune('1'+i)), string(rune('a'+i))+"@legacy.test", "gw-legacypwd-probe", time.Now().Add(-5*time.Minute))
	}
	ctx := &engine.RequestContext{
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("10.5.2.9"),
		BodyString: `{"email":"legacy@probe.test"}`,
		Headers:    map[string][]string{},
	}
	if res := layer.checkPasswordSpray(ctx, "gw-legacypwd-probe"); res.Action != engine.ActionBlock {
		t.Fatalf("window<=0 must keep the legacy all-time count (Action=%v)", res.Action)
	}
}
