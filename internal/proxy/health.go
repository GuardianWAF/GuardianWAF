package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

var healthLog = slog.Default().With(slog.String("component", "proxy/health"))

// HealthChecker periodically checks the health of all targets in a balancer.
type HealthChecker struct {
	balancer *Balancer
	interval time.Duration
	timeout  time.Duration
	path     string
	client   *http.Client
	stopCh   chan struct{}
	stopOnce sync.Once
	mu       sync.Mutex
	cancel   context.CancelFunc
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
		client:   newHealthCheckHTTPClient(cfg.Timeout, healthCheckPolicy(b)),
		stopCh:   make(chan struct{}),
	}
}

func healthCheckPolicy(b *Balancer) TargetPolicy {
	if b == nil {
		return TargetPolicy{}
	}
	targets := b.Targets()
	if len(targets) == 0 || targets[0] == nil {
		return TargetPolicy{}
	}
	return targets[0].policy
}

func newHealthCheckHTTPClient(timeout time.Duration, policy TargetPolicy) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           SSRFDialContextWithPolicy(policy),
			TLSHandshakeTimeout:   minHealthCheckDuration(timeout, 10*time.Second),
			ResponseHeaderTimeout: minHealthCheckDuration(timeout, 10*time.Second),
			ExpectContinueTimeout: 1 * time.Second,
			IdleConnTimeout:       30 * time.Second,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func minHealthCheckDuration(a, b time.Duration) time.Duration {
	if a <= 0 || a > b {
		return b
	}
	return a
}

// Start begins periodic health checking in a background goroutine.
func (hc *HealthChecker) Start() {
	hc.wg.Add(1)
	go func() {
		defer hc.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				// Health checker panic recovery — prevent silent failure
				healthLog.Error("health checker panic recovered", "panic", r)
			}
		}()

		ctx, cancel := context.WithCancel(context.Background())
		hc.mu.Lock()
		hc.cancel = cancel
		hc.mu.Unlock()
		defer func() {
			cancel()
			hc.mu.Lock()
			hc.cancel = nil
			hc.mu.Unlock()
		}()

		select {
		case <-hc.stopCh:
			return
		default:
		}

		// Initial check
		hc.checkAll(ctx)

		tickerInterval := hc.interval
		if tickerInterval <= 0 {
			tickerInterval = 30 * time.Second
		}
		ticker := time.NewTicker(tickerInterval)
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
	_ = hc.StopWithContext(context.Background())
}

// StopWithContext stops the health checker and waits within ctx for in-flight
// probes to observe cancellation and exit.
func (hc *HealthChecker) StopWithContext(ctx context.Context) error {
	hc.mu.Lock()
	cancel := hc.cancel
	hc.mu.Unlock()
	if cancel != nil {
		cancel()
	}

	hc.stopOnce.Do(func() {
		close(hc.stopCh)
	})
	return waitForHealthChecker(ctx, &hc.wg)
}

func waitForHealthChecker(ctx context.Context, wg *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// checkAll checks all targets in the balancer.
func (hc *HealthChecker) checkAll(ctx context.Context) {
	targets := hc.balancer.Targets()
	for _, t := range targets {
		// SSRF TOCTOU mitigation: re-check DNS on each health check to detect
		// DNS rebinding attacks that change a public IP to a private one.
		if !t.policy.AllowPrivateTargets {
			if err := IsPrivateOrReservedIPWithPolicy(t.URL.Host, t.policy); err != nil {
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
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024)) // nolint:errcheck // response body drain; error ignored
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}
