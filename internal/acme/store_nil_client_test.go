package acme

// Regression (bug-hunt round 71): LoadOrObtain panicked on a nil client.
// NewCertDiskStore accepts a nil client, and renewIfNeeded explicitly treats
// nil as the "ACME not configured" state (log + skip) — but LoadOrObtain on a
// cache miss fell through to obtainCertificate(s.client, ...) with a nil
// receiver and panicked in createOrder (c.directory.NewOrder). The obtain
// path now mirrors the renewIfNeeded convention: an explicit
// "ACME client not configured" error instead of a panic.
//
// Boundary: the guard sits AFTER the cache branch, so a nil-client store
// keeps serving valid cached certificates from disk.

import (
	"strings"
	"testing"
	"time"
)

func TestLoadOrObtain_NilClientReturnsErrorNotPanic(t *testing.T) {
	s := NewCertDiskStore(t.TempDir(), nil, nil)

	// Must not panic; must return an explicit, actionable error.
	_, err := s.LoadOrObtain([]string{"nil-client.example.com"})
	if err == nil {
		t.Fatal("FAIL: LoadOrObtain with a nil client returned nil error and no certificate — expected an explicit 'not configured' error")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("FAIL: error does not state the client is not configured: %v", err)
	}
}

func TestLoadOrObtain_NilClientServesCachedCert(t *testing.T) {
	dir := t.TempDir()
	seedCert(t, dir, "cached.example.com", 24*time.Hour) // valid pair on disk

	s := NewCertDiskStore(dir, nil, nil)
	cert, err := s.LoadOrObtain([]string{"cached.example.com"})
	if err != nil {
		t.Fatalf("FAIL: nil-client store refused a valid cached cert: %v", err)
	}
	if cert == nil || cert.Leaf == nil {
		t.Fatal("FAIL: expected the cached certificate to be served, got nil")
	}
}
