package proxy

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// HealthChecker performs periodic health checks against backends.
type HealthChecker struct {
	backends          []*Backend
	interval          time.Duration
	timeout           time.Duration
	path              string
	client            *http.Client
	stopCh            chan struct{}
	mu                sync.Mutex
	consecutiveFails  map[*Backend]int
	failureThreshold  int
	successThreshold  int
}

// NewHealthChecker creates a new health checker.
// It checks each backend by sending HTTP GET to the given path at the given interval.
// A backend is marked unhealthy after 3 consecutive failures and healthy after 1 success.
func NewHealthChecker(backends []*Backend, interval, timeout time.Duration, path string) *HealthChecker {
	if path == "" {
		path = "/health"
	}
	if interval == 0 {
		interval = 10 * time.Second
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	return &HealthChecker{
		backends: backends,
		interval: interval,
		timeout:  timeout,
		path:     path,
		client: &http.Client{
			Timeout: timeout,
		},
		stopCh:           make(chan struct{}),
		consecutiveFails: make(map[*Backend]int),
		failureThreshold: 3,
		successThreshold: 1,
	}
}

// Start begins background health checking.
func (hc *HealthChecker) Start() {
	go hc.run()
}

// Stop stops the background health checker.
func (hc *HealthChecker) Stop() {
	close(hc.stopCh)
}

func (hc *HealthChecker) run() {
	// Run an initial check immediately
	hc.checkAll()

	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hc.checkAll()
		case <-hc.stopCh:
			return
		}
	}
}

func (hc *HealthChecker) checkAll() {
	var wg sync.WaitGroup
	for _, b := range hc.backends {
		wg.Add(1)
		go func(backend *Backend) {
			defer wg.Done()
			healthy := hc.check(backend)
			hc.updateHealth(backend, healthy)
		}(b)
	}
	wg.Wait()
}

// check performs a single health check against the backend.
func (hc *HealthChecker) check(backend *Backend) bool {
	checkURL := fmt.Sprintf("%s%s", backend.URL.String(), hc.path)

	resp, err := hc.client.Get(checkURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Consider 2xx status codes as healthy
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// updateHealth updates the health status based on check results.
// Mark unhealthy after failureThreshold consecutive failures.
// Mark healthy after successThreshold consecutive successes (default 1).
func (hc *HealthChecker) updateHealth(backend *Backend, healthy bool) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if healthy {
		// Reset failure count on success
		hc.consecutiveFails[backend] = 0
		backend.SetHealthy(true)
	} else {
		hc.consecutiveFails[backend]++
		if hc.consecutiveFails[backend] >= hc.failureThreshold {
			backend.SetHealthy(false)
		}
	}
}

// CheckNow performs an immediate health check on all backends (useful for testing).
func (hc *HealthChecker) CheckNow() {
	hc.checkAll()
}
