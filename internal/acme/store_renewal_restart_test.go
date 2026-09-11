package acme

// Regression test for the renewal-loop restart contract (round
// round7-acme-renewal-restart). StartRenewal's loop must survive a panicking
// renewal attempt: a panic is recovered and the loop restarts after a short
// backoff (unless shutting down). Before the fix the goroutine recovered the
// panic and exited — one panic permanently disabled certificate renewal for
// the process lifetime, so every ACME-managed certificate ran to expiry
// (fleet-wide TLS outage). Same restart pattern as
// internal/docker/watcher.go. Resolves the adjacent defect parked by the
// round-19/25 early-renewal fix.

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestRenewalLoopRestartsAfterPanic(t *testing.T) {
	s := NewCertDiskStore(t.TempDir(), NewClient(LetsEncryptStaging), NewHTTP01Handler())
	s.AddDomains([]string{"example.com"})

	// The renewal path is reachable without any network: the cert file for
	// the domain does not exist, so renewIfNeeded -> loadOrObtain calls the
	// obtainCertificate seam. Every attempt panics.
	var calls atomic.Int64
	orig := obtainCertificate
	obtainCertificate = func(c *Client, domains []string, h *HTTP01Handler) ([]byte, []byte, error) {
		calls.Add(1)
		panic("renewal boom")
	}
	defer func() { obtainCertificate = orig }()

	s.StartRenewal(50 * time.Millisecond)
	defer s.StopRenewal()

	// The loop must restart after the panic and retry on subsequent ticks.
	deadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if calls.Load() >= 3 {
			return // restarted and retrying — contract holds
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("renewal panicked once and was never restarted — only %d attempt(s) in 2.5s; certificate renewal must restart after a panic instead of being permanently disabled", calls.Load())
}
