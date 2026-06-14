package main

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	gwaftls "github.com/guardianwaf/guardianwaf/internal/tls"
)

func TestACMEAccountKeyPath(t *testing.T) {
	t.Parallel()

	cacheDir, accountKeyPath, err := acmeAccountKeyPath(filepath.Join("cache", "..", "acme"))
	if err != nil {
		t.Fatalf("acmeAccountKeyPath: %v", err)
	}
	if cacheDir != "acme" {
		t.Fatalf("cacheDir = %q, want %q", cacheDir, "acme")
	}
	if accountKeyPath != filepath.Join("acme", "account.key") {
		t.Fatalf("accountKeyPath = %q", accountKeyPath)
	}

	for _, path := range []string{"", "acme\x00cache"} {
		if _, _, err := acmeAccountKeyPath(path); err == nil {
			t.Fatalf("expected error for %q", path)
		}
	}
}

func TestSetupACMERejectsInvalidCacheDir(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.TLS.ACME.Enabled = true
	cfg.TLS.ACME.Email = "ops@example.com"
	cfg.TLS.ACME.CacheDir = "acme\x00cache"

	if store := setupACME(cfg, http.NewServeMux(), gwaftls.NewCertStore()); store != nil {
		t.Fatal("expected nil ACME disk store for invalid cache dir")
	}
}
