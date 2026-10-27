package events

import (
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"testing"
)

func TestEventBusGivesEachSubscriberIndependentFindings(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()
	first := make(chan engine.Event, 1)
	second := make(chan engine.Event, 1)
	bus.Subscribe(first)
	bus.Subscribe(second)
	input := engine.Event{ID: "original", Findings: []engine.Finding{{Description: "accepted"}}}
	bus.Publish(input)
	mutated := make(chan struct{})
	go func() {
		ev := <-first
		ev.ID = "local"
		ev.Findings[0].Description = "subscriber changed"
		close(mutated)
	}()
	<-mutated // Gate the second observation on completion of the first mutation.
	got := <-second
	if got.ID != "original" {
		t.Fatal("unaffected scalar control failed", got.ID)
	}
	t.Log("CONTROL: scalar value isolation passed")
	t.Logf("EXPECTED: second=accepted caller=accepted; ACTUAL: second=%s caller=%s", got.Findings[0].Description, input.Findings[0].Description)
	if got.Findings[0].Description != "accepted" || input.Findings[0].Description != "accepted" {
		t.Fatal("PROBLEM CONFIRMED")
	}
	t.Log("FIX VERIFIED")
}

func TestEventBusGivesEachSubscriberIndependentFindingsEdges(t *testing.T) {
	for _, findings := range [][]engine.Finding{nil, {}, {{Description: "one"}, {Description: "two"}}} {
		bus := NewEventBus()
		ch := make(chan engine.Event, 1)
		bus.Subscribe(ch)
		input := engine.Event{Findings: findings}
		bus.Publish(input)
		for i := range input.Findings {
			input.Findings[i].Description = "changed"
		}
		got := <-ch
		if len(got.Findings) != len(findings) {
			t.Fatal("length changed")
		}
		for _, f := range got.Findings {
			if f.Description == "changed" {
				t.Fatal("publisher mutation affected delivery")
			}
		}
		bus.Close()
		bus.Publish(input)
	}
}
