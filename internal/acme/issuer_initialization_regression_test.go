package acme

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIssuerInitializationDoesNotGateCachedCertificates(t *testing.T) {
	dir := t.TempDir()
	domains := []string{"cached.example.com"}
	seedCert(t, dir, domains[0], 20*24*time.Hour)
	store := NewCertDiskStore(dir, &Client{}, nil)
	initialized, obtained := 0, 0
	available := false
	store.SetIssuerInitializer(func() error {
		initialized++
		if !available {
			return errors.New("CA temporarily unavailable")
		}
		return nil
	})
	old, err := store.LoadOrObtain(domains)
	if err != nil || initialized != 0 {
		t.Fatalf("cached certificate depends on CA: err=%v calls=%d", err, initialized)
	}
	store.AddDomains(domains)
	original := obtainCertificate
	defer func() { obtainCertificate = original }()
	obtainCertificate = func(*Client, []string, *HTTP01Handler) ([]byte, []byte, error) {
		obtained++
		key, cert := makeCertPEM(t, domains[0], time.Now().Add(90*24*time.Hour))
		return cert, key, nil
	}
	store.renewIfNeeded()
	cached, ok := store.GetCert(domains[0])
	if !ok || cached != old || initialized != 1 || obtained != 0 {
		t.Fatal("failed initialization replaced cache or attempted issuance")
	}
	available = true
	store.renewIfNeeded()
	fresh, _ := store.GetCert(domains[0])
	if fresh == old || initialized != 2 || obtained != 1 {
		t.Fatal("renewal did not retry initialization after CA recovered")
	}
	if _, err := store.loadOrObtain(domains, true); err != nil {
		t.Fatal(err)
	}
	if initialized != 2 || obtained != 2 {
		t.Fatal("successful issuer initialization was repeated")
	}
	t.Log("FIX VERIFIED")
}

func TestIssuerInitializationFailureCannotPublishInvalidCache(t *testing.T) {
	for _, state := range []string{"missing", "invalid", "expired"} {
		t.Run(state, func(t *testing.T) {
			dir := t.TempDir()
			domain := "unavailable.example.com"
			if state == "expired" {
				seedCert(t, dir, domain, -time.Hour)
			}
			if state == "invalid" {
				for _, suffix := range []string{".crt", ".key"} {
					if err := os.WriteFile(filepath.Join(dir, domain+suffix), []byte("invalid"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			store := NewCertDiskStore(dir, &Client{}, nil)
			calls := 0
			store.SetIssuerInitializer(func() error {
				calls++
				return errors.New("CA unavailable")
			})
			if cert, err := store.LoadOrObtain([]string{domain}); err == nil || cert != nil || calls != 1 {
				t.Fatalf("unusable cache served: cert=%v err=%v calls=%d", cert, err, calls)
			}
			if _, ok := store.GetCert(domain); ok {
				t.Fatal("invalid/expired cache was published")
			}
		})
	}
}
