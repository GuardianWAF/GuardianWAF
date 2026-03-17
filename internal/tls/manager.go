package tlsmanager

import (
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
)

// Manager handles TLS certificate management with SNI-based routing.
type Manager struct {
	mu           sync.RWMutex
	certificates map[string]*tls.Certificate // SNI hostname -> cert
	defaultCert  *tls.Certificate
}

// NewManager creates a new TLS certificate manager.
func NewManager() *Manager {
	return &Manager{
		certificates: make(map[string]*tls.Certificate),
	}
}

// LoadCertificate loads a certificate and private key from PEM files
// and sets it as the default certificate.
func (m *Manager) LoadCertificate(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaultCert = &cert
	return nil
}

// AddCertificate adds a certificate for a specific hostname (SNI).
func (m *Manager) AddCertificate(hostname string, cert *tls.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certificates[strings.ToLower(hostname)] = cert
}

// GetCertificate is the tls.Config.GetCertificate callback for SNI-based routing.
// It matches the ClientHelloInfo.ServerName against stored certificates.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	serverName := strings.ToLower(hello.ServerName)

	// Exact match
	if cert, ok := m.certificates[serverName]; ok {
		return cert, nil
	}

	// Wildcard match: try *.domain.com for sub.domain.com
	if idx := strings.Index(serverName, "."); idx >= 0 {
		wildcard := "*" + serverName[idx:]
		if cert, ok := m.certificates[wildcard]; ok {
			return cert, nil
		}
	}

	// Fall back to default certificate
	if m.defaultCert != nil {
		return m.defaultCert, nil
	}

	return nil, fmt.Errorf("no certificate found for %s", serverName)
}

// TLSConfig returns a tls.Config configured to use this manager's GetCertificate callback.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// SetDefaultCertificate sets the default certificate used when no SNI match is found.
func (m *Manager) SetDefaultCertificate(cert *tls.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaultCert = cert
}

// CertificateCount returns the number of stored certificates (excluding default).
func (m *Manager) CertificateCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.certificates)
}

// HasDefaultCert returns true if a default certificate is configured.
func (m *Manager) HasDefaultCert() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.defaultCert != nil
}
