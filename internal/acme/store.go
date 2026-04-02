package acme

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CertDiskStore manages cached certificates on disk with automatic renewal.
type CertDiskStore struct {
	cacheDir string
	client   *Client
	handler  *HTTP01Handler
	domains  [][]string // groups of domains to obtain certs for

	mu    sync.RWMutex
	certs map[string]*tls.Certificate // domain -> loaded cert

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewCertDiskStore creates a store that caches certs in the given directory.
func NewCertDiskStore(cacheDir string, client *Client, handler *HTTP01Handler) *CertDiskStore {
	return &CertDiskStore{
		cacheDir: cacheDir,
		client:   client,
		handler:  handler,
		certs:    make(map[string]*tls.Certificate),
		stopCh:   make(chan struct{}),
	}
}

// AddDomains registers a group of domains for certificate management.
func (s *CertDiskStore) AddDomains(domains []string) {
	s.domains = append(s.domains, domains)
}

// LoadOrObtain loads a cached cert from disk, or obtains a new one via ACME.
func (s *CertDiskStore) LoadOrObtain(domains []string) (*tls.Certificate, error) {
	primary := domains[0]

	// Try loading from cache
	certFile := s.certPath(primary)
	keyFile := s.keyPath(primary)

	if fileExists(certFile) && fileExists(keyFile) {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err == nil {
			// Parse leaf for expiry check
			if cert.Leaf == nil && len(cert.Certificate) > 0 {
				cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
			}
			// Use cached cert if not expired
			if cert.Leaf == nil || time.Now().Before(cert.Leaf.NotAfter) {
				s.storeCert(domains, &cert)
				return &cert, nil
			}
			// Cert expired, fall through to obtain new one
		}
	}

	// Obtain new cert
	certPEM, keyPEM, err := s.client.ObtainCertificate(domains, s.handler)
	if err != nil {
		return nil, fmt.Errorf("obtaining cert for %v: %w", domains, err)
	}

	// Save to disk
	if err := os.MkdirAll(s.cacheDir, 0700); err != nil {
		return nil, fmt.Errorf("creating cache dir: %w", err)
	}
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		return nil, fmt.Errorf("writing cert: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("writing key: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading new cert: %w", err)
	}

	s.storeCert(domains, &cert)
	return &cert, nil
}

// GetCert returns a cached cert for the domain, if available.
func (s *CertDiskStore) GetCert(domain string) (*tls.Certificate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cert, ok := s.certs[strings.ToLower(domain)]
	return cert, ok
}

// StartRenewal begins a background goroutine that renews certs 30 days before expiry.
func (s *CertDiskStore) StartRenewal(checkInterval time.Duration) {
	if checkInterval <= 0 {
		checkInterval = 12 * time.Hour
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.renewIfNeeded()
			case <-s.stopCh:
				return
			}
		}
	}()
}

// StopRenewal stops the background renewal goroutine.
func (s *CertDiskStore) StopRenewal() {
	close(s.stopCh)
	s.wg.Wait()
}

// --- Internal ---

func (s *CertDiskStore) storeCert(domains []string, cert *tls.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range domains {
		s.certs[strings.ToLower(d)] = cert
	}
}

func (s *CertDiskStore) renewIfNeeded() {
	for _, domains := range s.domains {
		primary := domains[0]
		certFile := s.certPath(primary)

		if !fileExists(certFile) {
			// No cert yet, obtain
			_, _ = s.LoadOrObtain(domains)
			continue
		}

		cert, err := tls.LoadX509KeyPair(certFile, s.keyPath(primary))
		if err != nil {
			continue
		}

		// Parse leaf to check expiry
		if cert.Leaf == nil && len(cert.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				continue
			}
			cert.Leaf = leaf
		}

		if cert.Leaf != nil {
			renewAt := cert.Leaf.NotAfter.Add(-30 * 24 * time.Hour) // 30 days before expiry
			if time.Now().After(renewAt) {
				// Renew
				_, _ = s.LoadOrObtain(domains)
			}
		}
	}
}

func (s *CertDiskStore) certPath(primary string) string {
	safe := sanitizeDomain(primary)
	return filepath.Join(s.cacheDir, safe+".crt")
}

func (s *CertDiskStore) keyPath(primary string) string {
	safe := sanitizeDomain(primary)
	return filepath.Join(s.cacheDir, safe+".key")
}

func sanitizeDomain(d string) string {
	d = strings.ToLower(d)
	d = strings.ReplaceAll(d, "*", "_wildcard_")
	d = strings.ReplaceAll(d, "/", "_")
	d = strings.ReplaceAll(d, ":", "_")
	return d
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

