package main

import (
	"log/slog"
	"net/http"
	"os"
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

func setupACME(cfg *config.Config, serveMux *http.ServeMux, certStore *gwaftls.CertStore) *acme.CertDiskStore {
	if !cfg.TLS.ACME.Enabled || cfg.TLS.ACME.Email == "" {
		return nil
	}

	acmeHandler := acme.NewHTTP01Handler()
	defer serveMux.Handle("/.well-known/acme-challenge/", acmeHandler)

	acmeClient := acme.NewClient(acme.LetsEncryptProduction)
	accountKeyPath := cfg.TLS.ACME.CacheDir + "/account.key"
	var accountKeyPEM []byte
	if data, err := os.ReadFile(accountKeyPath); err == nil {
		accountKeyPEM = data
	}
	if err := acmeClient.Init(accountKeyPEM); err != nil {
		slog.Warn("ACME init failed", "error", err)
		return nil
	}

	saveACMEAccountKey(cfg, accountKeyPath, acmeClient)
	if err := acmeClient.Register(cfg.TLS.ACME.Email); err != nil {
		slog.Warn("ACME registration failed", "error", err)
		return nil
	}

	diskStore := acme.NewCertDiskStore(cfg.TLS.ACME.CacheDir, acmeClient, acmeHandler)
	for _, domains := range collectACMEDomains(cfg) {
		diskStore.AddDomains(domains)
		cert, err := diskStore.LoadOrObtain(domains)
		if err != nil {
			slog.Warn("ACME cert failed", "domains", domains, "error", err)
			continue
		}
		certStore.LoadCertFromTLS(domains, cert)
	}
	diskStore.StartRenewal(12 * time.Hour)
	return diskStore
}

func saveACMEAccountKey(cfg *config.Config, accountKeyPath string, acmeClient *acme.Client) {
	keyPEM, err := acmeClient.AccountKeyPEM()
	if err != nil {
		return
	}
	if err := os.MkdirAll(cfg.TLS.ACME.CacheDir, 0o700); err != nil {
		slog.Warn("failed to create ACME cache dir", "error", err)
		return
	}
	if err := os.WriteFile(accountKeyPath, keyPEM, 0o600); err != nil {
		slog.Warn("failed to write ACME account key", "error", err)
	}
}
