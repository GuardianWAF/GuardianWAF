package clientside

import (
	"sync"
	"testing"
	"time"
)

// Regression: isKnownSkimmingDomain must take l.mu.RLock.
//
// It runs on the per-response Magecart scan (processResponse ->
// analyzeResponseBody), which executes concurrently for every in-flight
// request, while AddSkimmingDomain writes the same
// patterns.KnownSkimmingDomains map from the dashboard and MCP handlers.
// The getter GetSkimmingDomains already took the read lock; the detection
// path did not, so two accesses to one map were unsynchronised. A concurrent
// map read and map write is not merely a torn value — the Go runtime throws
// the fatal, unrecoverable "concurrent map read and map write", killing the
// whole WAF process rather than just the request.
//
// This test is a race-detector test: it fails under `go test -race` when the
// read lock is missing, and passes with it.
func TestKnownSkimmingDomainConcurrentScanAndAdd(t *testing.T) {
	// The body matches the built-in SkimmingPatterns
	// (?i)https?://[^/"'\s]*(?:skim|track|...)[^/"'\s]* so the scan actually
	// reaches isKnownSkimmingDomain. Without a pattern hit the reader never
	// touches the map and the race window would be vacuous.
	body := []byte(`<script src="https://track-skimmer.example/collect.js"></script>`)

	layer := NewLayer(&Config{
		Enabled: true,
		MagecartDetection: MagecartConfig{
			Enabled:                 true,
			DetectSuspiciousDomains: true,
		},
	})

	// Control: the scan reaches the map, so a clean race run below means the
	// read is locked — not that the reader never executed.
	layer.AddSkimmingDomain("track-skimmer.example")
	if res := layer.analyzeResponseBody(body); len(res.Matches) == 0 {
		t.Fatal("control FAIL: scan matched nothing — the fixture does not reach SkimmingPatterns")
	}

	const readers = 4
	started := make(chan struct{}, readers)
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer: the dashboard / MCP runtime path.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			layer.AddSkimmingDomain("skimmer-" + string(rune('a'+i%26)) + ".evil")
		}
	}()

	// Readers: the per-response Magecart scan (the production hot path).
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started <- struct{}{} // signal this goroutine is on the CPU
			for {
				select {
				case <-stop:
					return
				default:
				}
				layer.analyzeResponseBody(body)
			}
		}()
	}

	// Wait for every reader to be scheduled, so the overlap window is real.
	for range readers {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			close(stop)
			wg.Wait()
			t.Fatal("setup error: reader goroutines never started")
		}
	}

	// Bounded window with the readers confirmed running.
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}
