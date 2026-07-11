package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJWKThumbprint_CanonicalRFC7638Value(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c := &Client{accountKey: key}

	got := c.jwkThumbprint()
	if got == "" {
		t.Fatalf("jwkThumbprint returned empty")
	}

	jwk := c.jwk()
	canonical := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`,
		jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	sum := sha256.Sum256([]byte(canonical))
	want := base64.RawURLEncoding.EncodeToString(sum[:])

	if got != want {
		t.Fatalf("thumbprint = %q, want %q", got, want)
	}
}

func TestCertDiskStoreLoadOrObtain_CreateCacheDirError(t *testing.T) {
	srv, client := newMockACME(t)
	defer srv.Close()

	cacheParent := t.TempDir()
	cachePath := filepath.Join(cacheParent, "cache-file")
	if err := os.WriteFile(cachePath, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := NewCertDiskStore(cachePath, client, NewHTTP01Handler())
	_, err := store.LoadOrObtain([]string{"mkdir.example.com"})
	if err == nil || !strings.Contains(err.Error(), "creating cache dir") {
		t.Fatalf("expected cache dir creation error, got %v", err)
	}
}

func TestCertDiskStoreLoadOrObtain_WriteCertError(t *testing.T) {
	srv, client := newMockACME(t)
	defer srv.Close()

	cacheDir := t.TempDir()
	store := NewCertDiskStore(cacheDir, client, NewHTTP01Handler())
	if err := os.Mkdir(store.certPath("writecert.example.com"), 0o700); err != nil {
		t.Fatalf("Mkdir cert path: %v", err)
	}

	_, err := store.LoadOrObtain([]string{"writecert.example.com"})
	if err == nil || !strings.Contains(err.Error(), "writing cert") {
		t.Fatalf("expected cert write error, got %v", err)
	}
}

func TestCertDiskStoreLoadOrObtain_WriteKeyError(t *testing.T) {
	srv, client := newMockACME(t)
	defer srv.Close()

	cacheDir := t.TempDir()
	store := NewCertDiskStore(cacheDir, client, NewHTTP01Handler())
	if err := os.Mkdir(store.keyPath("writekey.example.com"), 0o700); err != nil {
		t.Fatalf("Mkdir key path: %v", err)
	}

	_, err := store.LoadOrObtain([]string{"writekey.example.com"})
	if err == nil || !strings.Contains(err.Error(), "writing key") {
		t.Fatalf("expected key write error, got %v", err)
	}
}
