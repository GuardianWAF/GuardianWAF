package websocket

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Round proof: handleWebSocket hijacks the upgrade and dialBackend dials the
// CLIENT-SUPPLIED Host header. An attacker can therefore make the WAF open a
// bidirectional tunnel to arbitrary internal host:port targets (websocket
// SSRF): the client's request is forwarded verbatim to the dialed host and
// the response is tunneled back.

func newSSRFTestLayer(t *testing.T, allowed []string, idle time.Duration) *Layer {
	t.Helper()
	return NewLayer(&Config{
		Enabled:             true,
		ScanPayloads:        true,
		IdleTimeout:         idle,
		AllowedBackendHosts: allowed,
	})
}

func upgradeRequest(targetHost string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://waf.internal/api/ws", nil)
	req.Host = targetHost // attacker-controlled Host header
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.RequestURI = "" // client requests must not carry the server-side field
	return req
}

func TestUpgradeRequestMustNotDialUnallowlistedHost(t *testing.T) {
	// The "internal service" an attacker wants to reach. It records every hit.
	var internalHits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()
	internalHost := internal.Listener.Addr().String()

	// The WAF-fronting server wrapping the (un-hijacked) proxy path. `next`
	// must receive upgrades when the layer declines to hijack.
	var nextHits atomic.Int32
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextHits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	srv := httptest.NewServer(newSSRFTestLayer(t, nil, 50*time.Millisecond).Wrap(next))
	defer srv.Close()
	srvHost := srv.Listener.Addr().String()

	client := &http.Client{Timeout: 2 * time.Second}
	req := upgradeRequest(internalHost)
	req.URL = httptest.NewRequest(http.MethodGet, "http://"+srvHost+"/api/ws", nil).URL
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if got := internalHits.Load(); got != 0 {
		t.Fatalf("FAIL: internal service was dialed %d time(s) — the WAF tunneled to the client-supplied Host %q (websocket SSRF)", got, internalHost)
	}
	if nextHits.Load() == 0 {
		t.Fatalf("FAIL: the upgrade never reached the proxy path after the layer declined to hijack")
	}
}

func TestUpgradeRequestInspectsAllowlistedBackend(t *testing.T) {
	var backendHits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	backendHost := backend.Listener.Addr().String()

	srv := httptest.NewServer(newSSRFTestLayer(t, []string{backendHost}, 50*time.Millisecond).Wrap(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		})))
	defer srv.Close()
	srvHost := srv.Listener.Addr().String()

	client := &http.Client{Timeout: 2 * time.Second}
	req := upgradeRequest(backendHost)
	req.URL = httptest.NewRequest(http.MethodGet, "http://"+srvHost+"/api/ws", nil).URL
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if got := backendHits.Load(); got != 1 {
		t.Fatalf("FAIL: allowlisted backend not dialed exactly once (hits=%d) — inspection must still work for configured hosts", got)
	}
}
