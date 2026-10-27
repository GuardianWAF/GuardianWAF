package ai

import (
	"sync/atomic"
	"testing"
)

func TestVerdictsRespectCurrentEnforcementMode(t *testing.T) {
	var enforcing atomic.Bool
	enforcing.Store(true)
	a := NewAnalyzer(AnalyzerConfig{
		Enabled: true, AutoBlockEnabled: true,
		EnforcementAllowed: enforcing.Load,
	}, NewStore(t.TempDir()), "")
	var blocker mockBlocker
	a.SetBlocker(&blocker)
	verdicts := []Verdict{{IP: "203.0.113.7", Action: "block", Confidence: 0.9}}
	batch := map[string]bool{"203.0.113.7": true}
	a.applyVerdicts(verdicts, batch)
	if len(blocker.calls) != 1 {
		t.Fatal("enforcing control did not ban")
	}

	// Gate a completed analysis at the exact point before applying its result.
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-release
		a.applyVerdicts(verdicts, batch)
	}()
	enforcing.Store(false)
	close(release)
	<-done
	if len(blocker.calls) != 1 {
		t.Fatal("a verdict completed after monitoring was enabled created a ban")
	}

	a.applyVerdicts(nil, batch)
	a.applyVerdicts(verdicts, nil)
	if len(blocker.calls) != 1 {
		t.Fatal("empty/monitor verdicts created bans")
	}
	enforcing.Store(true)
	a.applyVerdicts(verdicts, batch)
	if len(blocker.calls) != 2 {
		t.Fatal("returning to enforcement did not restore auto-blocking")
	}
	t.Log("FIX VERIFIED")
}
