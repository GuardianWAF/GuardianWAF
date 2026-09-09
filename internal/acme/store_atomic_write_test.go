package acme

import (
	"os"
	"testing"
	"time"
)

// Regression: loadOrObtain wrote the cert file and then the key file directly.
// A key-write failure (ENOSPC, permissions) after the cert write left a
// MISMATCHED pair on disk (new cert + old key) that fails loadX509KeyPair,
// bricking runtime renewal for the domain until restart. The save must stage
// both files and only then install them, so the disk never holds an
// inconsistent pair.
func TestLoadOrObtain_PartialWriteFailureKeepsConsistentPair(t *testing.T) {
	dir := t.TempDir()
	s := NewCertDiskStore(dir, &Client{}, nil)
	domains := []string{"atomic-write.example.com"}
	_ = seedCert(t, dir, domains[0], 30*24*time.Hour) // valid old pair on disk

	// Make the key file unwritable so the direct key write fails after the
	// cert write has already replaced the old cert (0400 still allows reads).
	keyFile := s.keyPath(domains[0])
	if err := os.Chmod(keyFile, 0o400); err != nil {
		t.Fatal(err)
	}

	origObtain := obtainCertificate
	obtainCertificate = func(c *Client, ds []string, h *HTTP01Handler) ([]byte, []byte, error) {
		keyPEM, certPEM := makeCertPEM(t, ds[0], time.Now().Add(90*24*time.Hour))
		return certPEM, keyPEM, nil
	}
	defer func() { obtainCertificate = origObtain }()

	_, obtainErr := s.loadOrObtain(domains, true)
	// Restore permissions so the consistency check can read the key.
	_ = os.Chmod(keyFile, 0o600)

	if obtainErr == nil {
		t.Log("loadOrObtain returned nil error despite the key write failure; checking disk state directly")
	}

	// The invariant: whatever the error, the on-disk pair must LOAD as a
	// consistent cert/key pair.
	cert, err := loadX509KeyPair(s.certPath(domains[0]), s.keyPath(domains[0]))
	if err != nil {
		t.Fatalf("FAIL: disk pair is INCONSISTENT after a partial write failure: %v (new cert + old key mismatch bricks renewal until restart)", err)
	}
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		cert.Leaf, _ = parseCertificate(cert.Certificate[0])
	}
	if cert.Leaf == nil {
		t.Fatal("certificate leaf missing after partial write failure")
	}
}
