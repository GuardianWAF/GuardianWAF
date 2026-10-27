package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/guardianwaf/guardianwaf/internal/acme"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	gwaftls "github.com/guardianwaf/guardianwaf/internal/tls"
)

func TestRuntimeACMEPublishesReloadedCertificate(t *testing.T) {
	cache := t.TempDir()
	certPath, keyPath := generateTempCerts(t, t.TempDir())
	copyPair := func(cert, key string) {
		t.Helper()
		for source, dest := range map[string]string{cert: filepath.Join(cache, "localhost.crt"), key: filepath.Join(cache, "localhost.key")} {
			data, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dest, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	copyPair(certPath, keyPath)
	live := gwaftls.NewCertStore()
	store := newRuntimeACMEStore(cache, nil, nil, live)
	original, err := store.LoadOrObtain([]string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	served, err := live.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if served != original {
		t.Fatal("initial cache load not published to TLS")
	}
	certPath, keyPath = generateTempCerts(t, t.TempDir())
	copyPair(certPath, keyPath)
	fresh, err := store.LoadOrObtain([]string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	served, err = live.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if served != fresh || bytes.Equal(served.Certificate[0], original.Certificate[0]) {
		t.Fatal("new certificate cache generation not published to TLS")
	}
}

// Serving a valid cached certificate must not depend on CA availability at
// process startup. This seam injects registration failure without live CA I/O.
func TestRuntimeACMECachedCertificateSurvivesCAOutage(t *testing.T) {
	for _, offline := range []bool{false, true} {
		t.Run(fmt.Sprint(offline), func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.TLS.ACME.Enabled = true
			cfg.TLS.ACME.Email = "ops@example.com"
			cfg.TLS.ACME.CacheDir = t.TempDir()
			cfg.TLS.ACME.Domains = []string{"localhost"}
			cert, key := generateTempCerts(t, t.TempDir())
			for src, dst := range map[string]string{cert: filepath.Join(cfg.TLS.ACME.CacheDir, "localhost.crt"), key: filepath.Join(cfg.TLS.ACME.CacheDir, "localhost.key")} {
				data, err := os.ReadFile(src)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dst, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			live := gwaftls.NewCertStore()
			store := setupACMEWithInitializer(cfg, http.NewServeMux(), live, func(*acme.Client, []byte, string, string, string) error {
				if offline {
					return errors.New("injected CA unavailable")
				}
				return nil
			})
			if store != nil {
				defer store.StopRenewal()
			}
			_, err := live.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"})
			if err != nil {
				t.Fatalf("EXPECTED cached certificate served during CA outage=%v; ACTUAL error=%v; PROBLEM CONFIRMED", offline, err)
			}
		})
	}
}
