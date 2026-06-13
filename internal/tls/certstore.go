// Package tls provides TLS certificate management for GuardianWAF.
// It handles certificate loading, SNI-based selection, and hot-reload
// using only the Go standard library.
package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

var certStoreLog = slog.Default().With(slog.String("component", "tls/certstore"))

// CertEntry represents a loaded certificate with its source file paths.
type CertEntry struct {
	Domains  []string // domains this cert covers
	CertFile string
	KeyFile  string
	certMod  time.Time // last modification time of cert file
	keyMod   time.Time // last modification time of key file
}

// CertStore manages TLS certificates with SNI-based selection and hot-reload.
type CertStore struct {
	mu          sync.RWMutex
	certs       map[string]*tls.Certificate // domain -> cert (exact match)
	wildcards   []wildcardCert              // wildcard certs
	defaultCert *tls.Certificate            // fallback cert
	entries     []CertEntry                 // all entries for reload tracking

	stopReload chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
}

type wildcardCert struct {
	suffix string // ".example.com" for *.example.com
	cert   *tls.Certificate
}

// NewCertStore creates an empty cert store.
func NewCertStore() *CertStore {
	return &CertStore{
		certs:      make(map[string]*tls.Certificate),
		stopReload: make(chan struct{}),
	}
}

// LoadDefaultCert loads the default/fallback certificate used when SNI doesn't match.
func (cs *CertStore) LoadDefaultCert(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("loading default cert: %w", err)
	}
	cs.mu.Lock()
	cs.defaultCert = &cert
	cs.mu.Unlock()
	return nil
}

// LoadCert loads a certificate for the given domains.
func (cs *CertStore) LoadCert(domains []string, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("loading cert for %v: %w", domains, err)
	}

	certInfo, _ := os.Stat(certFile)
	keyInfo, _ := os.Stat(keyFile)

	entry := CertEntry{
		Domains:  domains,
		CertFile: certFile,
		KeyFile:  keyFile,
	}
	if certInfo != nil {
		entry.certMod = certInfo.ModTime()
	}
	if keyInfo != nil {
		entry.keyMod = keyInfo.ModTime()
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.entries = append(cs.entries, entry)
	cs.storeCertLocked(domains, &cert)

	return nil
}

// GetCertificate is the tls.Config.GetCertificate callback for SNI-based selection.
func (cs *CertStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	name := strings.ToLower(hello.ServerName)

	// 1. Exact match
	if cert, ok := cs.certs[name]; ok {
		return cert, nil
	}

	// 2. Wildcard match
	for _, wc := range cs.wildcards {
		if strings.HasSuffix(name, wc.suffix) {
			return wc.cert, nil
		}
	}

	// 3. Default cert
	if cs.defaultCert != nil {
		return cs.defaultCert, nil
	}

	return nil, fmt.Errorf("no certificate found for %s", hello.ServerName)
}

// TLSConfig returns a tls.Config using this store for certificate selection.
// HTTP/2 is enabled by default via NextProtos negotiation.
// TLS 1.3 is the minimum version — TLS 1.2 suites are not configurable in TLS 1.3.
func (cs *CertStore) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: cs.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
}

// StartReload begins a background goroutine that checks for certificate file
// changes at the given interval and reloads them automatically.
func (cs *CertStore) StartReload(interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	cs.wg.Add(1)
	go func() {
		defer cs.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				certStoreLog.Error("cert reload panic recovered", "panic", r)
			}
		}()
		tickerInterval := interval
		if tickerInterval <= 0 {
			tickerInterval = 1 * time.Hour
		}
		ticker := time.NewTicker(tickerInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				cs.reloadIfChanged()
			case <-cs.stopReload:
				return
			}
		}
	}()
}

// StopReload stops the background certificate reload goroutine.
func (cs *CertStore) StopReload() {
	_ = cs.StopReloadWithContext(context.Background())
}

// StopReloadWithContext stops the background certificate reload goroutine and
// waits within ctx for any in-flight reload work to finish.
func (cs *CertStore) StopReloadWithContext(ctx context.Context) error {
	cs.stopOnce.Do(func() {
		close(cs.stopReload)
	})
	return waitForReloadLoop(ctx, &cs.wg)
}

func waitForReloadLoop(ctx context.Context, wg *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// CertCount returns the number of loaded certificates (exact + wildcard).
func (cs *CertStore) CertCount() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return len(cs.certs) + len(cs.wildcards)
}

// LoadCertFromTLS stores an already-loaded tls.Certificate for the given domains.
func (cs *CertStore) LoadCertFromTLS(domains []string, cert *tls.Certificate) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.storeCertLocked(domains, cert)
}

// storeCertLocked adds domains to the cert maps. Must be called with cs.mu held.
// Wildcard entries are deduplicated — if a wildcard suffix already exists,
// its cert pointer is updated instead of appending a duplicate.
func (cs *CertStore) storeCertLocked(domains []string, cert *tls.Certificate) {
	for _, domain := range domains {
		lower := strings.ToLower(domain)
		if strings.HasPrefix(lower, "*.") {
			suffix := lower[1:] // "*.example.com" -> ".example.com"
			// Check if this wildcard suffix already exists
			found := false
			for j := range cs.wildcards {
				if cs.wildcards[j].suffix == suffix {
					cs.wildcards[j].cert = cert
					found = true
					break
				}
			}
			if !found {
				cs.wildcards = append(cs.wildcards, wildcardCert{
					suffix: suffix,
					cert:   cert,
				})
			}
		} else {
			cs.certs[lower] = cert
		}
	}
}

// reloadIfChanged checks all cert entries for file modifications and reloads.
func (cs *CertStore) reloadIfChanged() {
	cs.mu.RLock()
	entries := make([]CertEntry, len(cs.entries))
	copy(entries, cs.entries)
	cs.mu.RUnlock()

	for i, entry := range entries {
		certInfo, err := os.Stat(entry.CertFile)
		if err != nil {
			certStoreLog.Warn("cert file stat failed during reload; skipping", "cert", entry.CertFile, "err", err)
			continue
		}
		keyInfo, err := os.Stat(entry.KeyFile)
		if err != nil {
			certStoreLog.Warn("key file stat failed during reload; skipping", "key", entry.KeyFile, "err", err)
			continue
		}

		if certInfo.ModTime().Equal(entry.certMod) && keyInfo.ModTime().Equal(entry.keyMod) {
			continue // no change
		}

		// Reload
		cert, err := tls.LoadX509KeyPair(entry.CertFile, entry.KeyFile)
		if err != nil {
			certStoreLog.Error("failed to reload cert; keeping previous cert", "cert", entry.CertFile, "key", entry.KeyFile, "err", err)
			continue
		}

		certStoreLog.Info("reloaded certificate", "cert", entry.CertFile, "domains", entry.Domains)

		cs.mu.Lock()
		cs.entries[i].certMod = certInfo.ModTime()
		cs.entries[i].keyMod = keyInfo.ModTime()

		for _, domain := range entry.Domains {
			lower := strings.ToLower(domain)
			if strings.HasPrefix(lower, "*.") {
				suffix := lower[1:]
				for j := range cs.wildcards {
					if cs.wildcards[j].suffix == suffix {
						cs.wildcards[j].cert = &cert
						break
					}
				}
			} else {
				cs.certs[lower] = &cert
			}
		}
		cs.mu.Unlock()
	}
}
