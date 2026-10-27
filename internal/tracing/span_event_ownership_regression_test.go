package tracing

import (
	"reflect"
	"testing"
)

func TestSpanEventAttributesAreSnapshots(t *testing.T) {
	s := &Span{}
	attrs := map[string]string{"state": "first", "keep": "yes"}
	s.AddEvent("first", attrs)
	release := make(chan struct{})
	done := make(chan struct{})
	go func() { <-release; attrs["state"] = "second"; delete(attrs, "keep"); attrs["new"] = "yes"; close(done) }()
	close(release)
	<-done
	s.AddEvent("second", attrs)
	attrs["state"] = "third"
	s.AddEvent("nil", nil)
	s.AddEvent("empty", map[string]string{})
	if !reflect.DeepEqual(s.Events[0].Attributes, map[string]string{"state": "first", "keep": "yes"}) || !reflect.DeepEqual(s.Events[1].Attributes, map[string]string{"state": "second", "new": "yes"}) {
		t.Fatal("map reuse changed earlier events")
	}
	if s.Events[2].Attributes != nil || s.Events[3].Attributes == nil || len(s.Events) != 4 {
		t.Fatal("nil/empty/order")
	}
	s.End()
	end := s.EndTime
	s.End()
	if s.EndTime != end || s.IsRecording() {
		t.Fatal("End semantics")
	}
	t.Log("FIX VERIFIED")
}
