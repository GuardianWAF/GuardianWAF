package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// seedCert writes a self-signed cert/key pair for domain into dir with
// NotAfter = now+ttl and returns the leaf NotAfter used.
func seedCert(t *testing.T, dir, domain string, ttl time.Duration) time.Time {
	t.Helper()
	notAfter := time.Now().Add(ttl)
	keyPEM, certPEM := makeCertPEM(t, domain, notAfter)
	safe := sanitizeDomain(domain)
	if err := os.WriteFile(filepath.Join(dir, safe+".crt"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, safe+".key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return notAfter
}

func makeCertPEM(t *testing.T, domain string, notAfter time.Time) (keyPEM, certPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Regression: renewIfNeeded detects the 30-days-before-expiry window but its
// remediation (LoadOrObtain) returns the still-valid cached cert and only
// obtains a new one after EXPIRY — so the documented early renewal never
// happens and certs roll over post-expiry (serving expired certs for up to a
// renewal tick). This test drives renewIfNeeded against an in-window cert and
// asserts the on-disk certificate is actually renewed.
func TestRenewIfNeeded_RenewsWithinWindow(t *testing.T) {
	dir := t.TempDir()
	s := NewCertDiskStore(dir, &Client{}, nil)
	domains := []string{"renew-window.example.com"}
	before := seedCert(t, dir, domains[0], 20*24*time.Hour) // inside the 30-day window
	s.AddDomains(domains)

	// Stub the ACME obtain seam (production initializes it to the real
	// Client method): the unit under test is the force-renew path, not the
	// network. The stub issues a fresh 90-day certificate.
	origObtain := obtainCertificate
	obtainCertificate = func(c *Client, ds []string, h *HTTP01Handler) ([]byte, []byte, error) {
		keyPEM, certPEM := makeCertPEM(t, ds[0], time.Now().Add(90*24*time.Hour))
		return certPEM, keyPEM, nil
	}
	defer func() { obtainCertificate = origObtain }()

	s.renewIfNeeded()

	cert, err := loadX509KeyPair(s.certPath(domains[0]), s.keyPath(domains[0]))
	if err != nil {
		t.Fatalf("loading cert after renewal attempt: %v", err)
	}
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		cert.Leaf, _ = parseCertificate(cert.Certificate[0])
	}
	if cert.Leaf == nil {
		t.Fatal("certificate leaf missing after renewal attempt")
	}
	if !cert.Leaf.NotAfter.After(before.Add(time.Hour)) {
		t.Fatalf("FAIL: cert unchanged after renewIfNeeded on an in-window cert: before=%v after=%v (renewal inert: LoadOrObtain returns the cached cert and never obtains until expiry)", before, cert.Leaf.NotAfter)
	}
}
