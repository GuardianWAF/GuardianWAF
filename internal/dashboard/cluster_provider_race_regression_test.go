package dashboard

// Regression (round 2026-09-24-r5-cluster-provider-startup-race): production
// wires the cluster dependencies via SetClusterStatusProvider /
// SetClusterIsolationChecker AFTER startDashboard has launched srv.Serve in a
// goroutine, so request goroutines read the plain interface fields
// concurrently with the setters — a formal data race whose torn interface
// read can yield an inconsistent (type, data) pair (crash class). The fields
// are now atomic.Pointer; this test keeps the race pinned by serving a real
// Dashboard, hammering /readyz (isolationChecker read) and an authenticated
// cluster route (clusterStatus read) from several goroutines, and calling
// both setters mid-flight — under -race any regression to a plain field is
// reported.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// stubIsolationChecker implements ClusterIsolationChecker for the race test.
type stubIsolationChecker struct{}

func (stubIsolationChecker) IsIsolated() bool { return false }
func (stubIsolationChecker) MemberCount() int { return 1 }

func TestSetClusterProviders_PublishAtomicallyWhileServing(t *testing.T) {
	d := newTestDashboard(t, "dash-key")
	server := httptest.NewServer(d.Handler())
	defer server.Close()

	client := &http.Client{Timeout: 2 * time.Second}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	hammer := func(path, key string) {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
			if err != nil {
				return
			}
			if key != "" {
				req.Header.Set("X-API-Key", key)
			}
			resp, err := client.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
	}
	targets := []struct{ path, key string }{
		{"/readyz", ""},
		{"/readyz", ""},
		{"/api/v1/cluster/status", "dash-key"},
		{"/api/v1/cluster/status", "dash-key"},
	}
	for _, tc := range targets {
		wg.Add(1)
		go hammer(tc.path, tc.key)
	}
	// Publish while reads are in flight — the exact production ordering
	// (Serve live, then the setters).
	time.Sleep(50 * time.Millisecond)
	d.SetClusterStatusProvider(&mockClusterProvider{})
	d.SetClusterIsolationChecker(stubIsolationChecker{})
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}
