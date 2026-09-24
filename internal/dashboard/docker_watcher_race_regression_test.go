package dashboard

// Regression (round 2026-09-24-r8-docker-watcher-race): production wires the
// Docker watcher via SetDockerWatcher AFTER startDashboard has launched
// srv.Serve in a goroutine (setupDockerRuntime runs at main.go:390,
// startDashboard at :335), so request goroutines read the plain field
// concurrently with the setter — the same post-start publication race proven
// for metricsHandler (round 4), the cluster providers (round 5), the
// late-wired routing/rules/AI fields (round 6), and the alerting fields
// (round 7). The field is now atomic.Pointer; this test keeps the race pinned
// by driving the real production handlers (handleDockerServices /
// handleDockerContainers / handleDockerEvents) from several goroutines while
// the setter publishes mid-flight — under -race any regression to a plain
// field is reported. (The HTTP-level harness is throttled by authWrap's
// per-IP /api/v1/ rate limiter — the direct invocation removes that
// confound; the handlers are mounted behind authWrap at
// misc_handlers.go:59-61.)

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/docker"
)

type regDockerWatcherStub struct{}

func (s *regDockerWatcherStub) Services() []docker.DiscoveredService { return nil }
func (s *regDockerWatcherStub) ServiceCount() int                    { return 0 }

func TestDockerWatcher_PublishAtomicallyWhileServing(t *testing.T) {
	d := newTestDashboard(t, "dash-key")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	hammer := func(handler func(http.ResponseWriter, *http.Request)) {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			rr := httptest.NewRecorder()
			handler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/docker/services", nil))
		}
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go hammer(d.handleDockerServices)
		wg.Add(1)
		go hammer(d.handleDockerContainers)
		wg.Add(1)
		go hammer(d.handleDockerEvents)
	}
	// The exact production ordering: serving live, then wire the field.
	time.Sleep(20 * time.Millisecond)
	d.SetDockerWatcher(&regDockerWatcherStub{})
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()
}
