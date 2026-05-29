package clustersync

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewClusterHTTPClient_DoesNotFollowRedirects(t *testing.T) {
	targetHits := atomic.Int64{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/cluster/sync", http.StatusFound)
	}))
	defer redirector.Close()

	cfg := DefaultConfig()
	cfg.NodeID = "node-1"
	cfg.SharedSecret = "cluster-secret"
	m := NewManager(cfg)

	err := m.sendEventToNode(&Node{ID: "node-2", Address: redirector.URL}, &SyncEvent{
		ID:         "evt-redirect",
		EntityType: "rule",
		EntityID:   "rule-1",
		Action:     "create",
		Timestamp:  time.Now().UnixNano(),
	})
	if err == nil {
		t.Fatal("expected redirect response to fail replication")
	}
	if !strings.Contains(err.Error(), "sync failed: 302") {
		t.Fatalf("expected 302 sync failure, got %v", err)
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("cluster client followed redirect to target server %d times", got)
	}
}

func TestNewClusterHTTPClient_HasTransportTimeouts(t *testing.T) {
	client := newClusterHTTPClient()
	if client.Timeout != 30*time.Second {
		t.Fatalf("client timeout = %v, want 30s", client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.ResponseHeaderTimeout != 30*time.Second {
		t.Fatalf("response header timeout = %v, want 30s", transport.ResponseHeaderTimeout)
	}
	if transport.TLSHandshakeTimeout != 10*time.Second {
		t.Fatalf("TLS handshake timeout = %v, want 10s", transport.TLSHandshakeTimeout)
	}
	if client.CheckRedirect == nil {
		t.Fatal("expected CheckRedirect to be configured")
	}
}
