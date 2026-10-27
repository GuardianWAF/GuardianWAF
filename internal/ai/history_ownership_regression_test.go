package ai

import (
	"reflect"
	"testing"
)

func TestStoreHistorySnapshotOwnership(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if len(s.GetHistory(0)) != 0 {
		t.Fatal("empty history")
	}
	want := AnalysisResult{ID: "one", Verdicts: []Verdict{{Reason: "original", Action: "monitor"}}, ThreatsDetected: []string{"original"}, TokensUsed: 5}
	input := want
	input.Verdicts = append([]Verdict(nil), want.Verdicts...)
	input.ThreatsDetected = append([]string(nil), want.ThreatsDetected...)
	if err := s.AddResult(input); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		<-release
		input.Verdicts[0].Reason = "caller"
		input.ThreatsDetected[0] = "caller"
		close(done)
	}()
	close(release)
	<-done
	h := s.GetHistory(1)
	if !reflect.DeepEqual(h[0], want) {
		t.Fatalf("input alias: %+v", h[0])
	}
	h[0].Verdicts[0].Reason = "reader"
	h[0].ThreatsDetected[0] = "reader"
	if !reflect.DeepEqual(s.GetHistory(1)[0], want) {
		t.Fatal("snapshot alias")
	}
	for _, r := range []AnalysisResult{{ID: "nil"}, {ID: "empty", Verdicts: []Verdict{}, ThreatsDetected: []string{}}} {
		if err := s.AddResult(r); err != nil {
			t.Fatal(err)
		}
	}
	history := s.GetHistory(0)
	if len(history) != 3 || history[0].ID != "empty" || history[1].Verdicts != nil || history[0].Verdicts == nil || !reflect.DeepEqual(history[2], want) {
		t.Fatal("retention/nil/empty")
	}
	if !reflect.DeepEqual(NewStore(dir).GetHistory(0), history) {
		t.Fatal("disk history divergence")
	}
	if s.GetUsage().MonitorsTriggered != 1 {
		t.Fatal("usage changed")
	}
	t.Log("FIX VERIFIED")
}
