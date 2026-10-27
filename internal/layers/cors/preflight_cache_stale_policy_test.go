package cors

import (
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression for F167: a preflight that snapshotted the old policy and
// finished after UpdateConfig cleared the cache re-populated it with an
// old-policy verdict, which then served X-CORS-Cache hits under the new policy
// for the whole TTL — bypassing strict-mode method validation and re-granting
// credentials. The interleaving is forced explicitly (snapshot → update →
// stale completion), no sleeps.

func stalePreflightReq(origin, method string) *engine.RequestContext {
	return &engine.RequestContext{Method: "OPTIONS", Headers: map[string][]string{
		"Origin": {origin}, "Access-Control-Request-Method": {method}}}
}

const staleOrigin = "https://app.example.com"

func staleOldPolicy() Config {
	return Config{Enabled: true, AllowOrigins: []string{staleOrigin}, AllowMethods: []string{"GET", "DELETE"},
		AllowCredentials: true, StrictMode: true, PreflightCacheSeconds: 600}
}

// runStale snapshots oldCfg, applies newCfg, then completes the stale preflight.
func runStale(t *testing.T, oldCfg, newCfg Config, method string) *Layer {
	t.Helper()
	l, err := NewLayer(&oldCfg)
	if err != nil {
		t.Fatal(err)
	}
	req := stalePreflightReq(staleOrigin, method)
	snap, allowed := l.snapshotConfig(staleOrigin)
	if !allowed {
		t.Fatal("origin must be allowed under the old policy")
	}
	if err := l.UpdateConfig(newCfg); err != nil {
		t.Fatal(err)
	}
	l.handlePreflight(req, staleOrigin, &snap, time.Now())
	return l
}

func TestPreflightCache_StaleVerdictAfterUpdate_StrictMethod(t *testing.T) {
	newCfg := staleOldPolicy()
	newCfg.AllowMethods = []string{"GET"}
	l := runStale(t, staleOldPolicy(), newCfg, "DELETE")

	fresh := stalePreflightReq(staleOrigin, "DELETE")
	if res := l.Process(fresh); res.Action != engine.ActionBlock {
		t.Fatalf("DELETE removed under strict mode: want block, got %v (cache=%q)",
			res.Action, fresh.CORSPreflightHeaders["X-CORS-Cache"])
	}
}

func TestPreflightCache_StaleVerdictAfterUpdate_Credentials(t *testing.T) {
	newCfg := staleOldPolicy()
	newCfg.AllowCredentials = false
	newCfg.StrictMode = false
	l := runStale(t, staleOldPolicy(), newCfg, "GET")

	fresh := stalePreflightReq(staleOrigin, "GET")
	l.Process(fresh)
	if got := fresh.CORSPreflightHeaders["Access-Control-Allow-Credentials"]; got != "false" {
		t.Fatalf("credentials disabled by update: want ACAC=false, got %q (cache=%q)",
			got, fresh.CORSPreflightHeaders["X-CORS-Cache"])
	}
}

func TestPreflightCache_SamePolicyUpdateStillCaches(t *testing.T) {
	// An update to an identical policy leaves the stale verdict valid, so it
	// may be cached; the normal miss → hit cycle must keep working.
	l := runStale(t, staleOldPolicy(), staleOldPolicy(), "GET")
	fresh := stalePreflightReq(staleOrigin, "GET")
	l.Process(fresh)
	if fresh.CORSPreflightHeaders["X-CORS-Cache"] != "hit" {
		t.Fatal("identical-policy verdict should be served from cache")
	}
}

func TestPreflightCache_ConcurrentUpdateNoStaleHit(t *testing.T) {
	oldCfg := staleOldPolicy()
	newCfg := staleOldPolicy()
	newCfg.AllowMethods = []string{"GET"}
	l, err := NewLayer(&oldCfg)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 200 {
				l.Process(stalePreflightReq(staleOrigin, "DELETE"))
			}
		}()
	}
	close(start)
	for range 50 {
		_ = l.UpdateConfig(oldCfg)
		_ = l.UpdateConfig(newCfg)
	}
	wg.Wait()
	if res := l.Process(stalePreflightReq(staleOrigin, "DELETE")); res.Action != engine.ActionBlock {
		t.Fatalf("after final update to the strict GET-only policy, DELETE must block; got %v", res.Action)
	}
}
