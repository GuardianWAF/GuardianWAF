package engine

import (
	"context"
	"runtime"
	"time"
)

// Large bodies dominate inspection cost: every text detector scans every view
// of the body, roughly 50 ms per MB of JSON and 75 ms per MB of text on one
// core. Without a bound, a few concurrent multi-megabyte POSTs could occupy
// every core and stall the small requests that make up normal traffic. Bodies
// above largeBodyBytes therefore take one of a fixed number of inspection
// slots (half the CPUs), so large-body inspection never uses more than half
// the machine. Small requests never wait.
const largeBodyBytes = 256 << 10

// largeBodySlotTimeout is how long a large body waits for a slot. A variable
// so tests need not wait it out.
var largeBodySlotTimeout = 5 * time.Second

func newLargeBodySlots() chan struct{} {
	return make(chan struct{}, max(1, runtime.GOMAXPROCS(0)/2))
}

// acquireInspectionSlot returns a release func and true when the body may be
// inspected now. Small bodies pass without a slot. A large body waits up to
// largeBodySlotTimeout (or until the client goes away) and is refused
// otherwise; it is never forwarded uninspected.
func (e *Engine) acquireInspectionSlot(ctx context.Context, bodyLen int) (func(), bool) {
	if bodyLen <= largeBodyBytes || e.largeBodySlots == nil {
		return func() {}, true
	}
	release := func() { <-e.largeBodySlots }
	select {
	case e.largeBodySlots <- struct{}{}:
		return release, true
	default:
	}
	timer := time.NewTimer(largeBodySlotTimeout)
	defer timer.Stop()
	select {
	case e.largeBodySlots <- struct{}{}:
		return release, true
	case <-timer.C:
	case <-ctx.Done():
	}
	e.largeBodyRejected.Add(1)
	return nil, false
}
