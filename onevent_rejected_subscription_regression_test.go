package guardianwaf

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/events"
)

const onEventPumpFrame = "guardianwaf.(*Engine).OnEvent.func1"

func countOnEventPumps(t *testing.T) int {
	t.Helper()
	var stacks bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&stacks, 1); err != nil {
		t.Fatalf("capture goroutine stacks: %v", err)
	}
	count := 0
	label := fmt.Sprintf("\"guardianwaf-event-test\":%q", t.Name())
	for _, block := range strings.Split(stacks.String(), "\n\n") {
		if !strings.Contains(block, label) || !strings.Contains(block, onEventPumpFrame) {
			continue
		}
		for _, line := range strings.Split(block, "\n") {
			if strings.Contains(line, " @ ") {
				var n int
				if _, err := fmt.Sscanf(line, "%d @", &n); err != nil {
					t.Fatal(err)
				}
				count += n
				break
			}
		}
	}
	return count
}

func TestOnEventRejectedSubscriptionDoesNotLeakPump(t *testing.T) {
	baseline := countOnEventPumps(t)
	register := func(waf *Engine, callback func(Event)) {
		pprof.Do(context.Background(), pprof.Labels("guardianwaf-event-test", t.Name()), func(context.Context) {
			waf.OnEvent(callback)
		})
	}
	waitCount := func(want int) {
		t.Helper()
		for range 1000 {
			if countOnEventPumps(t) == want {
				return
			}
			runtime.Gosched()
		}
		t.Fatalf("pump count did not converge: got=%d want=%d", countOnEventPumps(t), want)
	}

	// Control: an admitted callback pump is owned by the event bus and exits
	// when Engine.Close closes its subscribed channel.
	control, err := New(Config{})
	if err != nil {
		t.Fatalf("New control engine: %v", err)
	}
	t.Cleanup(func() { _ = control.Close() })
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	register(control, func(Event) {
		close(started)
		<-release
		close(finished)
	})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	control.internal.EventBus().Publish(Event{})
	<-started
	if got := countOnEventPumps(t); got != baseline+1 {
		t.Fatalf("control pump did not start: baseline=%d got=%d", baseline, got)
	}
	if err := control.Close(); err != nil {
		t.Fatalf("close control engine: %v", err)
	}
	close(release)
	<-finished
	waitCount(baseline)

	waf, err := New(Config{})
	if err != nil {
		t.Fatalf("New saturated engine: %v", err)
	}
	t.Cleanup(func() { _ = waf.Close() })
	bus, ok := waf.internal.EventBus().(*events.EventBus)
	if !ok {
		t.Fatalf("proof setup: event bus type = %T, want *events.EventBus", waf.internal.EventBus())
	}
	maxSubscribers := bus.Stats().MaxSubscribers
	holders := make([]chan Event, maxSubscribers)
	for i := range maxSubscribers {
		holders[i] = make(chan Event, 1)
		bus.Subscribe(holders[i])
	}
	if stats := bus.Stats(); stats.Subscribers != maxSubscribers {
		t.Fatalf("proof setup did not fill subscriber cap: %+v", stats)
	}

	register(waf, func(Event) {})
	if stats := bus.Stats(); stats.RejectedSubscriptions != 1 {
		t.Fatalf("proof setup did not trigger one rejected subscription: %+v", stats)
	}

	if err := waf.Close(); err != nil {
		t.Fatalf("close saturated engine: %v", err)
	}
	waitCount(baseline)
	runtime.KeepAlive(holders)
}
