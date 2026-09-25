package rules

// Regression (round 2026-09-25-round11-regex-timeout-direction): the regex
// evaluator's failure value was unconditional true (fail-closed) — deny-safe
// for block/log/challenge rules, but FAIL-OPEN for pass-rules: when a regex
// could not be evaluated (per-request budget exhausted, semaphore overload,
// or the per-regex ceiling timeout fired), a whitelist rule's matches
// condition counted as MATCHED, so the whitelist fired and the request
// bypassed the WAF entirely. Deterministic proof: regexTimeoutAfter and
// regexSem are package vars — these tests force the timeout branch by firing
// the timer immediately while holding every semaphore slot (no goroutine
// races). Fixed direction-aware: deny actions fail closed (true — the rule
// still enforces), pass actions fail safe (false — a whitelist that could
// not be evaluated must never fire). Normal matching is untouched, and the
// deny-side fail-closed guarantee from the C1+C2 concurrency fix is
// preserved and pinned here.

import (
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func whitelistProbeLayer(passAction string) *Layer {
	return NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID: "probe-whitelist", Name: "whitelist", Enabled: true, Priority: 1,
				Action:     passAction,
				Conditions: []Condition{{Field: "header:X-Probe", Op: "matches", Value: "."}},
			},
			{
				ID: "probe-block", Name: "blocker", Enabled: true, Priority: 2,
				Action:     "block",
				Conditions: []Condition{{Field: "path", Op: "equals", Value: "/probe"}},
			},
		},
	}, nil)
}

// forceRegexFailure makes the regex evaluator's failure branches fire
// deterministically: the timeout timer is always ready and every semaphore
// slot is held, so the wait branch can only take the failure path.
func forceRegexFailure(t *testing.T) {
	t.Helper()
	origTimer := regexTimeoutAfter
	regexTimeoutAfter = func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}
	for i := 0; i < maxConcurrentRegex; i++ {
		regexSem <- struct{}{}
	}
	t.Cleanup(func() {
		regexTimeoutAfter = origTimer
		for i := 0; i < maxConcurrentRegex; i++ {
			<-regexSem
		}
	})
}

func probeCtx() *engine.RequestContext {
	return &engine.RequestContext{
		Path:     "/probe",
		Method:   "GET",
		ClientIP: net.ParseIP("192.0.2.7"),
		Headers:  map[string][]string{"X-Probe": {"probe-value"}},
		// Accumulator is needed because the block rule adds a finding.
		Accumulator: engine.NewScoreAccumulator(2),
	}
}

// A pass whitelist must NOT fire while regex evaluation could not complete
// (fail-safe direction); the block rule underneath must still be evaluated.
func TestRegexTimeoutFailsSafeForPassRules(t *testing.T) {
	layer := whitelistProbeLayer("pass")
	forceRegexFailure(t)
	res := layer.Process(probeCtx())
	if res.Action == engine.ActionPass {
		t.Fatalf("whitelist fired while regex evaluation could not complete — WAF bypassed for the request (Action=Pass)")
	}
	if res.Action != engine.ActionBlock {
		t.Fatalf("expected the underlying block rule to fire, got Action=%v", res.Action)
	}
}

// Deny rules keep the fail-closed direction under the same failure: the
// C1+C2 concurrency guarantee (an unevaluable regex still enforces) is
// preserved for block/log/challenge rules.
func TestRegexTimeoutStaysFailClosedForDenyRules(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID: "probe-deny", Name: "deny", Enabled: true, Priority: 1,
				Action:     "block",
				Conditions: []Condition{{Field: "header:X-Probe", Op: "matches", Value: "."}},
			},
		},
	}, nil)
	forceRegexFailure(t)
	if res := layer.Process(probeCtx()); res.Action != engine.ActionBlock {
		t.Fatalf("deny rule must stay fail-closed under regex timeout (Action=%v)", res.Action)
	}
}

// Normal (non-failed) matching is untouched: the whitelist still fires.
func TestRegexNormalMatchingUnaffected(t *testing.T) {
	layer := whitelistProbeLayer("pass")
	res := layer.Process(probeCtx())
	if res.Action != engine.ActionPass {
		t.Fatalf("normal whitelist match must still pass (Action=%v)", res.Action)
	}
}
