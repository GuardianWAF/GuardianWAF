package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// HealthChecker periodically checks the health of all targets in a balancer.
type HealthChecker struct {
	balancer *Balancer
	interval time.Duration
	timeout  time.Duration
	path     string
	client   *http.Client
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// HealthConfig configures health checking.
type HealthConfig struct {
	Enabled  bool
	Interval time.Duration
	Timeout  time.Duration
	Path     string
}

// NewHealthChecker creates a new health checker for the given balancer.
func NewHealthChecker(b *Balancer, cfg HealthConfig) *HealthChecker {
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.Path == "" {
		cfg.Path = "/"
	}

	return &HealthChecker{
		balancer: b,
		interval: cfg.Interval,
		timeout:  cfg.Timeout,
		path:     cfg.Path,
		client:   &http.Client{Timeout: cfg.Timeout},
		stopCh:   make(chan struct{}),
	}
}

// Start begins periodic health checking in a background goroutine.
func (hc *HealthChecker) Start() {
	hc.wg.Add(1)
	go func() {
		defer hc.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				// Health checker panic recovery — prevent silent failure
				fmt.Printf("[ERROR] health checker panic: %v\n", r)
			}
		}()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Initial check
		hc.checkAll(ctx)

		ticker := time.NewTicker(hc.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				hc.checkAll(ctx)
			case <-hc.stopCh:
				return
			}
		}
	}()
}

// Stop stops the health checker and waits for it to finish.
func (hc *HealthChecker) Stop() {
	close(hc.stopCh)
	hc.wg.Wait()
}

// checkAll checks all targets in the balancer.
func (hc *HealthChecker) checkAll(ctx context.Context) {
	targets := hc.balancer.Targets()
	for _, t := range targets {
		// SSRF TOCTOU mitigation: re-check DNS on each health check to detect
		// DNS rebinding attacks that change a public IP to a private one.
		if !allowPrivateTargets {
			if err := isPrivateOrReservedIP(t.URL.Host); err != nil {
				t.SetHealthy(false)
				t.lastCheck.Store(time.Now())
				continue
			}
		}
		healthy := hc.check(ctx, t)
		t.SetHealthy(healthy)
		t.lastCheck.Store(time.Now())
	}
}

// check performs a single health check against a target.
func (hc *HealthChecker) check(ctx context.Context, t *Target) bool {
	checkURL := fmt.Sprintf("%s://%s%s", t.URL.Scheme, t.URL.Host, hc.path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, http.NoBody)
	if err != nil {
		return false
	}
	// Set Host header so backends with virtual hosting respond correctly
	req.Host = t.URL.Host
	resp, err := hc.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// Drain up to 64KB so the connection can be reused by the pool,
	// but don't read unlimited data from a compromised backend.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}
