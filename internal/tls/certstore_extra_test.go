package tls

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func helloFor(domain string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{ServerName: domain}
}

func TestLoadCertFromTLS_ExactDomain(t *testing.T) {
	cs := NewCertStore()

	certFile, keyFile := generateTestCert(t, "example.com")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	cs.LoadCertFromTLS([]string{"example.com"}, &cert)

	got, err := cs.GetCertificate(helloFor("example.com"))
	if err != nil || got == nil {
		t.Error("expected cert for example.com")
	}

	if cs.CertCount() != 1 {
		t.Errorf("expected 1 cert, got %d", cs.CertCount())
	}
}

func TestLoadCertFromTLS_WildcardDomain(t *testing.T) {
	cs := NewCertStore()

	certFile, keyFile := generateTestCert(t, "*.example.com")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	cs.LoadCertFromTLS([]string{"*.example.com"}, &cert)

	got, err := cs.GetCertificate(helloFor("sub.example.com"))
	if err != nil || got == nil {
		t.Error("expected cert for sub.example.com via wildcard")
	}

	if cs.CertCount() != 1 {
		t.Errorf("expected 1 cert (wildcard), got %d", cs.CertCount())
	}
}

func TestLoadCertFromTLS_MultipleDomains(t *testing.T) {
	cs := NewCertStore()

	certFile, keyFile := generateTestCert(t, "a.com")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	cs.LoadCertFromTLS([]string{"a.com", "b.com", "*.c.com"}, &cert)

	if c, _ := cs.GetCertificate(helloFor("a.com")); c == nil {
		t.Error("expected cert for a.com")
	}
	if c, _ := cs.GetCertificate(helloFor("b.com")); c == nil {
		t.Error("expected cert for b.com")
	}
	if c, _ := cs.GetCertificate(helloFor("sub.c.com")); c == nil {
		t.Error("expected cert for sub.c.com via wildcard")
	}
	// 2 exact + 1 wildcard = 3
	if cs.CertCount() != 3 {
		t.Errorf("expected 3, got %d", cs.CertCount())
	}
}

func TestLoadCertFromTLS_CaseInsensitive(t *testing.T) {
	cs := NewCertStore()

	certFile, keyFile := generateTestCert(t, "Example.COM")
	cert, _ := tls.LoadX509KeyPair(certFile, keyFile)
	cs.LoadCertFromTLS([]string{"Example.COM"}, &cert)

	if c, _ := cs.GetCertificate(helloFor("example.com")); c == nil {
		t.Error("expected case-insensitive cert lookup")
	}
}

func TestReloadIfChanged(t *testing.T) {
	certFile, keyFile := generateTestCert(t, "reload.com")

	cs := NewCertStore()
	err := cs.LoadCert([]string{"reload.com"}, certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	if c, _ := cs.GetCertificate(helloFor("reload.com")); c == nil {
		t.Fatal("expected cert")
	}

	// Sleep then write new cert
	time.Sleep(50 * time.Millisecond)
	certFile2, keyFile2 := generateTestCert(t, "reload.com")
	// Copy new cert to old paths
	certData, _ := os.ReadFile(certFile2)
	keyData, _ := os.ReadFile(keyFile2)
	_ = os.WriteFile(certFile, certData, 0600)
	_ = os.WriteFile(keyFile, keyData, 0600)

	cs.reloadIfChanged()

	if c, _ := cs.GetCertificate(helloFor("reload.com")); c == nil {
		t.Error("expected cert after reload")
	}
}

func TestReloadIfChanged_NoChange(t *testing.T) {
	certFile, keyFile := generateTestCert(t, "stable.com")

	cs := NewCertStore()
	_ = cs.LoadCert([]string{"stable.com"}, certFile, keyFile)

	// No changes
	cs.reloadIfChanged()

	if c, _ := cs.GetCertificate(helloFor("stable.com")); c == nil {
		t.Error("expected cert still available")
	}
}

func TestReloadIfChanged_MissingFile(t *testing.T) {
	certFile, keyFile := generateTestCert(t, "gone.com")

	cs := NewCertStore()
	_ = cs.LoadCert([]string{"gone.com"}, certFile, keyFile)

	// Delete cert file
	os.Remove(certFile)

	// Should not panic
	cs.reloadIfChanged()
}

func TestReloadIfChanged_WildcardReload(t *testing.T) {
	certFile, keyFile := generateTestCert(t, "*.wild.com")

	cs := NewCertStore()
	err := cs.LoadCert([]string{"*.wild.com"}, certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	if c, _ := cs.GetCertificate(helloFor("sub.wild.com")); c == nil {
		t.Fatal("expected wildcard cert")
	}

	// Write new cert
	time.Sleep(50 * time.Millisecond)
	dir := filepath.Dir(certFile)
	certFile2 := filepath.Join(dir, "new_cert.pem")
	keyFile2 := filepath.Join(dir, "new_key.pem")
	newCertFile, newKeyFile := generateTestCert(t, "*.wild.com")
	certData, _ := os.ReadFile(newCertFile)
	keyData, _ := os.ReadFile(newKeyFile)
	_ = certFile2
	_ = keyFile2
	_ = os.WriteFile(certFile, certData, 0600)
	_ = os.WriteFile(keyFile, keyData, 0600)

	cs.reloadIfChanged()

	if c, _ := cs.GetCertificate(helloFor("sub.wild.com")); c == nil {
		t.Error("expected wildcard cert after reload")
	}
}
