package tenant

// Regression tests: GetTenantByAPIKey's API-key cache fast path must take and
// release m.apiKeyCacheMu exactly once on every path.
//
// The fast path released the lock inside the cache-hit branch and then fell
// through to a second, unconditional Unlock at the end of the block. A cache
// entry naming a tenant that is no longer in m.tenants — the
// "deleted without a cache clear" case the code itself anticipates — therefore
// released the mutex twice. On a sync.Mutex that is
// `fatal error: sync: unlock of unlocked mutex`: a runtime throw, NOT a
// recoverable panic, so a single unauthenticated request carrying the affected
// key aborted the entire process. The key arrives pre-authentication on
// X-GuardianWAF-Tenant-Key (ResolveTenant, manager.go:491), which makes this a
// remote denial of service on the tenant auth path.
//
// cachedTenantID now scopes the read so the single release is structural rather
// than something each branch has to remember.

import (
	"path/filepath"
	"testing"
)

// newIsolatedManager returns a Manager whose tenant store is a fresh temp dir.
// The package default (data/tenants) persists across runs, so a leftover store
// would preload tenants and make these tests depend on unrelated state.
func newIsolatedManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManagerWithStore(10, filepath.Join(t.TempDir(), "tenants"))
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(m.Close)
	if got := len(m.ListTenants()); got != 0 {
		t.Fatalf("expected an empty manager, got %d tenants", got)
	}
	return m
}

// A cache entry that still names a deleted tenant must not abort the process:
// the lookup falls through to the slow path and returns nil.
func TestGetTenantByAPIKeyStaleCacheEntryDoesNotAbort(t *testing.T) {
	m := newIsolatedManager(t)

	tenant, err := m.CreateTenant("acme", "victim", []string{"acme.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	key, err := m.RegenerateAPIKey(tenant.ID)
	if err != nil {
		t.Fatalf("RegenerateAPIKey: %v", err)
	}
	if got := m.GetTenantByAPIKey(key); got == nil {
		t.Fatalf("HARNESS FAIL: a valid API key must resolve to its tenant")
	}

	// Reproduce the documented stale-entry state: the cache still names a
	// tenant that has been removed from m.tenants. DeleteTenant invalidates
	// the cache, so the surviving entry is re-established the same way the
	// production slow path does — via cacheAPIKeyResult, called at
	// manager.go after a concurrent invalidation.
	m.invalidateAPIKeyCache()
	if err := m.DeleteTenant(tenant.ID); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	m.cacheAPIKeyResult(fastKeyHash(key), &Tenant{ID: tenant.ID})

	if _, live := m.tenants[tenant.ID]; live {
		t.Fatalf("HARNESS FAIL: tenant %s still present; the vanished branch was not exercised", tenant.ID)
	}

	// Before the fix this call unlocked m.apiKeyCacheMu twice and the runtime
	// aborted the process with "sync: unlock of unlocked mutex".
	if got := m.GetTenantByAPIKey(key); got != nil {
		t.Fatalf("a deleted tenant's cached key must not resolve (got tenant %s)", got.ID)
	}
}

// The ordinary fast path must still resolve from cache — the lock refactor
// must not turn every lookup into the PBKDF2 slow path.
func TestGetTenantByAPIKeyCachedHitStillResolves(t *testing.T) {
	m := newIsolatedManager(t)

	tenant, err := m.CreateTenant("acme", "cached", []string{"cached.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	key, err := m.RegenerateAPIKey(tenant.ID)
	if err != nil {
		t.Fatalf("RegenerateAPIKey: %v", err)
	}

	// First lookup populates the cache; the second is served from it.
	if got := m.GetTenantByAPIKey(key); got == nil || got.ID != tenant.ID {
		t.Fatalf("cold lookup must resolve the tenant (got %v)", got)
	}
	if got := m.GetTenantByAPIKey(key); got == nil || got.ID != tenant.ID {
		t.Fatalf("warm-cache lookup must resolve the tenant (got %v)", got)
	}

	// The entry really is cached (this is the branch that used to
	// double-unlock), so the fix cannot have silently bypassed it.
	m.apiKeyCacheMu.Lock()
	cachedID, ok := m.apiKeyCache[fastKeyHash(key)]
	m.apiKeyCacheMu.Unlock()
	if !ok || cachedID != tenant.ID {
		t.Fatalf("expected a cached entry for the tenant, got ok=%v id=%q", ok, cachedID)
	}
}

// A cached NEGATIVE result (an unknown key remembered as "") must still short
// circuit to nil without touching the tenant map or the slow path.
func TestGetTenantByAPIKeyCachedNegativeStillShortCircuits(t *testing.T) {
	m := newIsolatedManager(t)

	if got := m.GetTenantByAPIKey("gwaf_not_a_real_key"); got != nil {
		t.Fatalf("an unknown key must not resolve a tenant (got %v)", got)
	}

	m.apiKeyCacheMu.Lock()
	cachedID, ok := m.apiKeyCache[fastKeyHash("gwaf_not_a_real_key")]
	m.apiKeyCacheMu.Unlock()
	if !ok || cachedID != "" {
		t.Fatalf("expected a cached negative entry, got ok=%v id=%q", ok, cachedID)
	}

	// Repeat lookup: served by the cached negative result.
	if got := m.GetTenantByAPIKey("gwaf_not_a_real_key"); got != nil {
		t.Fatalf("cached negative result must stay nil (got %v)", got)
	}
}

// Every exit path must leave the cache mutex balanced, including repeated
// lookups that hit each branch. A leaked or double release shows up here as a
// fatal rather than a failed assertion, which is exactly the regression.
func TestGetTenantByAPIKeyLeavesCacheMutexBalanced(t *testing.T) {
	m := newIsolatedManager(t)

	tenant, err := m.CreateTenant("acme", "balanced", []string{"balanced.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	key, err := m.RegenerateAPIKey(tenant.ID)
	if err != nil {
		t.Fatalf("RegenerateAPIKey: %v", err)
	}

	for i := range 3 {
		m.GetTenantByAPIKey(key)                               // miss then hit
		m.GetTenantByAPIKey("gwaf_bad_" + string(rune('a'+i))) // negative
	}

	// The mutex must still be acquirable: the process reaching this line at
	// all proves no prior call double-released it.
	if !m.apiKeyCacheMu.TryLock() {
		t.Fatal("API key cache mutex remains locked after lookups")
	}
	m.apiKeyCacheMu.Unlock()
}
