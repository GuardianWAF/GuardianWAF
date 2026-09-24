package dashboard

// Regression (round 2026-09-24-r4-metrics-handler-startup-race): production
// wires the metrics exposition via SetMetricsHandler AFTER startDashboard has
// launched srv.Serve in a goroutine, so request goroutines read the handler
// field concurrently with the setter. The field was a plain
// http.HandlerFunc — a formal data race between SetMetricsHandler and
// handleMetricsRoute on the admin-authenticated /metrics dispatch path
// (race-detector proven: write dashboard.go SetMetricsHandler vs read
// stats_handlers.go handleMetricsRoute). The field is now an
// atomic.Pointer[http.HandlerFunc]; this test keeps the race pinned by
// serving a real Dashboard, hammering /metrics from several goroutines, and
// publishing the handler mid-flight — under -race any regression to a plain
// field is reported.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestSetMetricsHandler_PublishesAtomicallyWhileServing(t *testing.T) {
	d := newTestDashboard(t, "dash-key")
	d.SetAdminKey("admin-key")
	server := httptest.NewServer(d.Handler())
	defer server.Close()

	client := &http.Client{Timeout: 2 * time.Second}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	hammer := func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			req, err := http.NewRequest(http.MethodGet, server.URL+"/metrics", nil)
			if err != nil {
				return
			}
			req.Header.Set("X-API-Key", "admin-key")
			resp, err := client.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go hammer()
	}
	// Publish while reads are in flight — the exact production ordering
	// (Serve live, then SetMetricsHandler).
	time.Sleep(50 * time.Millisecond)
	d.SetMetricsHandler(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}
