package events

import (
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"testing"
)

func TestEventBusDuplicateSubscriptionIsIdempotent(t *testing.T) {
	for _, cap := range []int{1, 2, 4} {
		b := NewEventBusWithMaxSubscribers(cap)
		ch := make(chan engine.Event, 8)
		for range 3 {
			b.Subscribe(ch)
		}
		if s := b.Stats(); s.Subscribers != 1 || s.RejectedSubscriptions != 0 {
			t.Fatalf("duplicate registration stats: %+v", s)
		}
		b.Publish(engine.Event{ID: "first"})
		if len(ch) != 1 {
			t.Fatalf("deliveries=%d want 1", len(ch))
		}
		<-ch
		b.Unsubscribe(ch)
		b.Publish(engine.Event{ID: "unsubscribed"})
		if len(ch) != 0 {
			t.Fatal("unsubscribed delivery")
		}
		b.Subscribe(ch)
		b.Subscribe(ch)
		b.Publish(engine.Event{ID: "second"})
		if len(ch) != 1 {
			t.Fatal("resubscribe duplicated delivery")
		}
		<-ch
		b.Close()
		b.Close()
		if _, open := <-ch; open {
			t.Fatal("channel not closed")
		}
	}
	b := NewEventBus()
	b.Close()
	b.Close()
	t.Log("FIX VERIFIED")
}
