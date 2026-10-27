package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/acme"
	"github.com/guardianwaf/guardianwaf/internal/config"
	gwaftls "github.com/guardianwaf/guardianwaf/internal/tls"
)

func buildTLSServer(cfg *config.Config, serveMux *http.ServeMux, handler http.Handler) (*http.Server, *gwaftls.CertStore, *acme.CertDiskStore) {
	if !cfg.TLS.Enabled {
		return nil, nil, nil
	}

	certStore := gwaftls.NewCertStore()
	loadConfiguredCertificates(cfg, certStore)
	diskStore := setupACME(cfg, serveMux, certStore)
	certStore.StartReload(30 * time.Second)

	tlsSrv := newRuntimeHTTPServer(cfg.TLS.Listen, handler)
	tlsSrv.TLSConfig = certStore.TLSConfig()
	return tlsSrv, certStore, diskStore
}

func loadConfiguredCertificates(cfg *config.Config, certStore *gwaftls.CertStore) {
	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		if err := certStore.LoadDefaultCert(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil {
			slog.Warn("failed to load default TLS cert", "error", err)
		}
	}

	for _, vh := range cfg.VirtualHosts {
		if vh.TLS.CertFile != "" && vh.TLS.KeyFile != "" {
			if err := certStore.LoadCert(vh.Domains, vh.TLS.CertFile, vh.TLS.KeyFile); err != nil {
				slog.Warn("failed to load TLS cert", "domains", vh.Domains, "error", err)
			}
		}
	}
}

type runtimeACMEInitializer func(*acme.Client, []byte, string, string, string) error

func initializeRuntimeACME(client *acme.Client, keyPEM []byte, cacheDir, keyPath, email string) error {
	if err := client.Init(keyPEM); err != nil {
		return err
	}
	saveACMEAccountKey(cacheDir, keyPath, client)
	return client.Register(email)
}

func setupACME(cfg *config.Config, serveMux *http.ServeMux, certStore *gwaftls.CertStore) *acme.CertDiskStore {
	return setupACMEWithInitializer(cfg, serveMux, certStore, initializeRuntimeACME)
}

func setupACMEWithInitializer(cfg *config.Config, serveMux *http.ServeMux, certStore *gwaftls.CertStore, initialize runtimeACMEInitializer) *acme.CertDiskStore {
	if !cfg.TLS.ACME.Enabled || cfg.TLS.ACME.Email == "" {
		return nil
	}

	acmeHandler := acme.NewHTTP01Handler()
	serveMux.Handle("/.well-known/acme-challenge/", acmeHandler)

	acmeClient := acme.NewClient(acme.LetsEncryptProduction)
	cacheDir, accountKeyPath, err := acmeAccountKeyPath(cfg.TLS.ACME.CacheDir)
	if err != nil {
		slog.Warn("invalid ACME cache dir", "error", err)
		return nil
	}
	diskStore := newRuntimeACMEStore(cacheDir, acmeClient, acmeHandler, certStore)
	accountEmail := cfg.TLS.ACME.Email
	diskStore.SetIssuerInitializer(func() error {
		// A failed registration may already have persisted a new account key.
		// Reload it on retry so an outage does not keep generating new accounts.
		var accountKeyPEM []byte
		if data, err := os.ReadFile(accountKeyPath); err == nil { // #nosec G304 -- path remains inside the cleaned operator-selected ACME cache dir.
			accountKeyPEM = data
		}
		return initialize(acmeClient, accountKeyPEM, cacheDir, accountKeyPath, accountEmail)
	})
	for _, domains := range collectACMEDomains(cfg) {
		diskStore.AddDomains(domains)
		_, err := diskStore.LoadOrObtain(domains)
		if err != nil {
			slog.Warn("ACME cert failed", "domains", domains, "error", err)
			continue
		}
	}
	diskStore.StartRenewal(12 * time.Hour)
	return diskStore
}

// newRuntimeACMEStore connects all future cache/renewal publications to the
// active TLS store, including domains first obtained after startup.
func newRuntimeACMEStore(cacheDir string, client *acme.Client, handler *acme.HTTP01Handler, certStore *gwaftls.CertStore) *acme.CertDiskStore {
	store := acme.NewCertDiskStore(cacheDir, client, handler)
	store.SetCertificateListener(certStore.LoadCertFromTLS)
	return store
}

func acmeAccountKeyPath(cacheDir string) (string, string, error) {
	if strings.ContainsRune(cacheDir, 0) {
		return "", "", fmt.Errorf("ACME cache dir contains NUL byte")
	}
	if cacheDir == "" {
		return "", "", fmt.Errorf("ACME cache dir must not be empty")
	}
	cleanCacheDir := filepath.Clean(cacheDir)
	return cleanCacheDir, filepath.Join(cleanCacheDir, "account.key"), nil
}

func saveACMEAccountKey(cacheDir, accountKeyPath string, acmeClient *acme.Client) {
	keyPEM, err := acmeClient.AccountKeyPEM()
	if err != nil {
		return
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		slog.Warn("failed to create ACME cache dir", "error", err)
		return
	}
	if err := os.WriteFile(accountKeyPath, keyPEM, 0o600); err != nil {
		slog.Warn("failed to write ACME account key", "error", err)
	}
}
