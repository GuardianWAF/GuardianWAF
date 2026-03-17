package tlsmanager

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// SNIRouter provides helpers for SNI-based certificate routing.
type SNIRouter struct {
	manager *Manager
}

// NewSNIRouter creates a new SNI router backed by the given manager.
func NewSNIRouter(manager *Manager) *SNIRouter {
	return &SNIRouter{manager: manager}
}

// AddDomainCertificate loads a certificate from PEM data and adds it for the given domain.
func (sr *SNIRouter) AddDomainCertificate(domain string, certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse certificate for %s: %w", domain, err)
	}
	sr.manager.AddCertificate(domain, &cert)
	return nil
}

// AddDomainCertificateFiles loads a certificate from files and adds it for the given domain.
func (sr *SNIRouter) AddDomainCertificateFiles(domain, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate for %s: %w", domain, err)
	}
	sr.manager.AddCertificate(domain, &cert)
	return nil
}

// MatchesDomain checks if a hostname matches a domain pattern (including wildcard).
func MatchesDomain(pattern, hostname string) bool {
	pattern = strings.ToLower(pattern)
	hostname = strings.ToLower(hostname)

	if pattern == hostname {
		return true
	}

	// Wildcard matching: *.example.com matches sub.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		if strings.HasSuffix(hostname, suffix) {
			// Ensure there's exactly one level of subdomain
			prefix := strings.TrimSuffix(hostname, suffix)
			if !strings.Contains(prefix, ".") && prefix != "" {
				return true
			}
		}
	}

	return false
}

// CertificateInfo returns basic info about a certificate.
type CertificateInfo struct {
	CommonName string
	DNSNames   []string
	NotBefore  string
	NotAfter   string
	Issuer     string
}

// GetCertificateInfo parses a PEM-encoded certificate and returns info.
func GetCertificateInfo(certPEM []byte) (*CertificateInfo, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &CertificateInfo{
		CommonName: cert.Subject.CommonName,
		DNSNames:   cert.DNSNames,
		NotBefore:  cert.NotBefore.Format("2006-01-02 15:04:05"),
		NotAfter:   cert.NotAfter.Format("2006-01-02 15:04:05"),
		Issuer:     cert.Issuer.CommonName,
	}, nil
}
