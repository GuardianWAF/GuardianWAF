package tracing

import (
	"maps"
	"testing"
)

type completedSpanRecordingExporter struct {
	span  *Span
	calls int
}

func (e *completedSpanRecordingExporter) Export(s *Span) { e.span = s; e.calls++ }
func (e *completedSpanRecordingExporter) Shutdown()      {}

func TestCompletedSpanIgnoresLateMutations(t *testing.T) {
	for _, empty := range []bool{true, false} {
		tr, err := NewTracer(Config{Enabled: true, SamplingRate: 1})
		if err != nil {
			t.Fatal(err)
		}
		exported := &completedSpanRecordingExporter{}
		tr.SetExporter(exported)
		s := tr.StartSpan("example", SpanKindInternal)
		if !empty {
			s.SetAttribute("state", "active")
			s.AddEvent("before", map[string]string{"value": "original"})
		}
		initialAttributes := maps.Clone(s.Attributes)
		s.End()
		end := s.EndTime
		duration := s.Duration()
		release, done := make(chan struct{}), make(chan struct{})
		go func() {
			<-release
			for range 3 {
				s.SetAttribute("state", "late")
				s.SetAttribute("new", "late")
				s.AddEvent("late", nil)
			}
			close(done)
		}()
		close(release)
		<-done
		s.End()
		s.End()
		if exported.calls != 1 || s.IsRecording() || !s.EndTime.Equal(end) || s.Duration() != duration {
			t.Fatal("completion changed")
		}
		if empty {
			if !maps.Equal(s.Attributes, initialAttributes) || s.Events != nil {
				t.Fatal("late mutation allocated completed span state")
			}
		} else {
			if s.Attributes["state"] != "active" || s.Attributes["new"] != "" || len(s.Events) != 1 || s.Events[0].Name != "before" {
				t.Fatal("late mutation changed completed span")
			}
		}
		_, created, count := tr.Stats()
		if created != 1 || count != 1 {
			t.Fatalf("counts created=%d exported=%d", created, count)
		}
		tr.Shutdown()
	}
	s := &Span{}
	s.SetAttribute("state", "one")
	s.SetAttribute("state", "two")
	s.AddEvent("nil", nil)
	s.AddEvent("empty", map[string]string{})
	if s.Attributes["state"] != "two" || len(s.Events) != 2 || s.Events[0].Attributes != nil || s.Events[1].Attributes == nil {
		t.Fatal("active control changed")
	}
	s.End()
	emptySpan := &Span{}
	emptySpan.End()
	emptySpan.SetAttribute("late", "value")
	emptySpan.AddEvent("late", nil)
	if emptySpan.Attributes != nil || emptySpan.Events != nil {
		t.Fatal("late mutation allocated zero span state")
	}
}
