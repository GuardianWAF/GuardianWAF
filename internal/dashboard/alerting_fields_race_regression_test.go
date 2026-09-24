package dashboard

// Regression (round 2026-09-24-r7-alerting-fields-race): production wires
// the alerting dependencies via SetAlertingStatsFn / SetAlertingTestFn AFTER
// startDashboard has launched srv.Serve in a goroutine (setupAlertingRuntime),
// so request goroutines read the plain fields concurrently with the setters
// — the same post-start publication race proven for metricsHandler (round 4),
// the cluster providers (round 5), and the late-wired routing/rules/AI fields
// (round 6). The fields are now atomic.Pointer; this test keeps the race
// pinned by driving the real production handlers (handleGetStats /
// handleTestAlert) from several goroutines while the setters publish
// mid-flight — under -race any regression to a plain field is reported.
// (The HTTP-level harness is throttled by authWrap's per-IP /api/v1/ rate
// limiter — the direct invocation removes that confound; authenticated
// production requests demonstrably reach these handlers through the full
// chain.)

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAlertingFields_PublishAtomicallyWhileServing(t *testing.T) {
	d := newTestDashboard(t, "dash-key")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	hammer := func(handler func(http.ResponseWriter, *http.Request), makeReq func() *http.Request) {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			rr := httptest.NewRecorder()
			handler(rr, makeReq())
		}
	}
	statsReq := func() *http.Request {
		return httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	}
	testAlertReq := func() *http.Request {
		return httptest.NewRequest(http.MethodPost, "/api/v1/alerts/test", strings.NewReader(`{"target":"webhook-1"}`))
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go hammer(d.handleGetStats, statsReq)
		wg.Add(1)
		go hammer(d.handleTestAlert, testAlertReq)
	}
	// The exact production ordering: serving live, then wire the fields.
	time.Sleep(20 * time.Millisecond)
	d.SetAlertingStatsFn(func() any { return map[string]any{"sent": 1, "failed": 0} })
	d.SetAlertingTestFn(func(targetName string) error { return nil })
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()
}
