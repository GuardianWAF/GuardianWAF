package dashboard

// Regression (round 2026-09-24-r6-late-wired-fields-race): production wires
// the remaining late-wired Dashboard dependencies via SetCertFn /
// SetUpstreamsFn AFTER startDashboard has launched srv.Serve in a goroutine,
// so request goroutines read the plain interface fields concurrently with
// the setters — the same post-start publication race proven for metricsHandler
// (round 4) and the cluster providers (round 5). The fields are now
// atomic.Pointer; this test keeps the race pinned by driving the real
// production handlers (handleGetUpstreams / handleGetCerts) from several
// goroutines while the setters publish mid-flight — under -race any
// regression to a plain field is reported. (The HTTP-level harness is
// throttled by authWrap's per-IP /api/v1/ rate limiter, which suppresses
// handler reads during the write window — the direct invocation removes that
// confound; authenticated production requests demonstrably reach these
// handlers through the full chain.)

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestLateWiredFields_PublishAtomicallyWhileServing(t *testing.T) {
	d := newTestDashboard(t, "dash-key")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	hammer := func(handler func(http.ResponseWriter, *http.Request), path string) {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			handler(rr, req)
		}
	}
	wg.Add(2)
	go hammer(d.handleGetUpstreams, "/api/v1/upstreams")
	go hammer(d.handleGetUpstreams, "/api/v1/upstreams")
	wg.Add(2)
	go hammer(d.handleGetCerts, "/api/v1/ssl")
	go hammer(d.handleGetCerts, "/api/v1/ssl")
	// The exact production ordering: serving live, then wire the fields.
	time.Sleep(20 * time.Millisecond)
	d.SetUpstreamsFn(func() any { return []any{map[string]any{"id": "up1"}} })
	d.SetCertFn(func() any { return map[string]any{"enabled": true} })
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()
}
