package acme

import (
	"bytes"
	stdtls "crypto/tls"
	"errors"
	"testing"
	"time"

	gwaftls "github.com/guardianwaf/guardianwaf/internal/tls"
)

// Runtime wires this callback before loading the initial certificate. Renewal
// must publish to the same TLS store, not only replace its separate disk cache.
func TestRenewalPublishesActiveCertificate(t *testing.T) {
	dir := t.TempDir()
	domains := []string{"renew.example.com", "alias.example.com"}
	seedCert(t, dir, domains[0], 20*24*time.Hour)
	disk := NewCertDiskStore(dir, &Client{}, nil)
	live := gwaftls.NewCertStore()
	calls := 0
	disk.SetCertificateListener(func(ds []string, cert *stdtls.Certificate) {
		calls++
		// A listener may inspect the store; invoking it under its mutex deadlocks.
		if cached, ok := disk.GetCert(ds[0]); !ok || cached != cert {
			t.Fatal("listener ran before cache publication")
		}
		live.LoadCertFromTLS(ds, cert)
		ds[0] = "mutated.example.com"
	})
	old, err := disk.LoadOrObtain(domains)
	if err != nil {
		t.Fatal(err)
	}
	disk.AddDomains(domains)
	if calls != 1 {
		t.Fatalf("initial publication count=%d", calls)
	}
	original := obtainCertificate
	defer func() { obtainCertificate = original }()
	obtainCertificate = func(*Client, []string, *HTTP01Handler) ([]byte, []byte, error) {
		return nil, nil, errors.New("injected CA failure")
	}
	disk.renewIfNeeded()
	still, err := live.GetCertificate(&stdtls.ClientHelloInfo{ServerName: domains[0]})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !bytes.Equal(still.Certificate[0], old.Certificate[0]) {
		t.Fatal("failed issuance replaced live certificate")
	}
	var issued []byte
	obtainCertificate = func(_ *Client, ds []string, _ *HTTP01Handler) ([]byte, []byte, error) {
		if ds[0] != domains[0] {
			t.Fatal("listener mutated managed domains")
		}
		key, cert := makeCertPEM(t, ds[0], time.Now().Add(90*24*time.Hour))
		issued = cert
		return cert, key, nil
	}
	disk.renewIfNeeded()
	if len(issued) == 0 || calls != 2 {
		t.Fatalf("renewal not published: calls=%d", calls)
	}
	for _, domain := range domains {
		served, err := live.GetCertificate(&stdtls.ClientHelloInfo{ServerName: domain})
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(served.Certificate[0], old.Certificate[0]) {
			t.Fatal("TLS still serves expired-generation certificate")
		}
		cached, ok := disk.GetCert(domain)
		if !ok || cached != served {
			t.Fatal("TLS and ACME cache disagree")
		}
	}
	disk.renewIfNeeded()
	if calls != 2 {
		t.Fatal("fresh certificate renewed again outside renewal window")
	}
}

func TestCertificateListenerCanBeRemoved(t *testing.T) {
	s := NewCertDiskStore(t.TempDir(), nil, nil)
	calls := 0
	s.SetCertificateListener(func([]string, *stdtls.Certificate) { calls++ })
	s.storeCert([]string{"a.example.com"}, &stdtls.Certificate{})
	s.SetCertificateListener(nil)
	s.storeCert([]string{"b.example.com"}, &stdtls.Certificate{})
	if calls != 1 {
		t.Fatalf("listener called after removal: %d", calls)
	}
	if _, ok := s.GetCert("b.example.com"); !ok {
		t.Fatal("removing listener prevented cache update")
	}
}
