package tenant

import (
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
)

func TestTenantCredentialCacheCannotPublishAcrossRevocation(t *testing.T) {
	m := newIsolatedManager(t)
	m.store = nil
	// Use a cheap self-describing test hash: this checks publication ordering,
	// not password derivation strength. Production key generation is unchanged.
	salt := []byte("cache-revocation-test")
	hash := func(key string) string {
		return "v3$1$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(deriveKey([]byte(key), salt, 1))
	}
	tn := &Tenant{ID: "concurrent-key", Active: true}
	m.tenants[tn.ID] = tn
	for round := range 32 {
		oldKey, newKey := fmt.Sprintf("old-%d", round), fmt.Sprintf("new-%d", round)
		m.mu.Lock()
		tn.APIKeyHash = hash(oldKey)
		m.invalidateAPIKeyCache()
		m.mu.Unlock()
		if m.GetTenantByAPIKey(oldKey) != tn {
			t.Fatal("control: original key did not resolve")
		}

		// Gate lookups against an in-progress rotation. A lookup may have
		// verified the old key before rotation, but must never cache that result
		// after the rotation invalidates it.
		m.mu.Lock()
		started := make(chan struct{}, 16)
		var workers sync.WaitGroup
		for range 16 {
			workers.Go(func() {
				started <- struct{}{}
				m.GetTenantByAPIKey(oldKey)
			})
		}
		for range 16 {
			<-started
		}
		tn.APIKeyHash = hash(newKey)
		m.invalidateAPIKeyCache()
		m.mu.Unlock()
		workers.Wait()
		if m.GetTenantByAPIKey(oldKey) != nil {
			t.Fatalf("round %d: revoked key resolved after concurrent cache publications", round)
		}
		if m.GetTenantByAPIKey(newKey) != tn {
			t.Fatalf("round %d: new key did not resolve", round)
		}
	}
}
