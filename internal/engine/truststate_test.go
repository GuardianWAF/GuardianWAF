package engine

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// Regression (the catalog-closure weak note): NewEngine and Reload called
// SetTrustedProxies(cfg.TrustedProxies), clobbering the package-global
// trust state their own instance-local copy exists to protect — and the
// per-request AcquireContext path (context.go:275) reads exactly that
// global, so in a multi-engine deployment every request's client-IP trust
// model was the LAST-CONSTRUCTED engine's, not the serving engine's.
// Construction now touches only the instance copy; the package-global is
// mutated solely by the explicit SetTrustedProxies embedder API.
func TestNewEngineDoesNotMutatePackageTrustState(t *testing.T) {
	SetTrustedProxies(nil) // start from a clean package state

	cfg := config.DefaultConfig()
	cfg.TrustedProxies = []string{"10.0.0.0/8"}
	if _, err := NewEngine(cfg, newMockEventStore(), newMockEventBus()); err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	trustedProxyMu.RLock()
	n := len(trustedProxyCIDRs)
	trustedProxyMu.RUnlock()

	if n != 0 {
		t.Fatalf("FAIL: engine construction wrote %d CIDRs into the package-global trust state — per-request AcquireContext would inherit the last-constructed engine's trust model", n)
	}
}
