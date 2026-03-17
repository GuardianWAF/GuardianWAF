package tlsmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ACMEClient handles Let's Encrypt certificate issuance via HTTP-01 challenge.
type ACMEClient struct {
	mu         sync.Mutex
	email      string
	domains    []string
	cacheDir   string
	accountKey *ecdsa.PrivateKey
	challenges map[string]string // token -> key authorization
	manager    *Manager
}

// NewACMEClient creates a new ACME client.
func NewACMEClient(email string, domains []string, cacheDir string, manager *Manager) *ACMEClient {
	return &ACMEClient{
		email:      email,
		domains:    domains,
		cacheDir:   cacheDir,
		challenges: make(map[string]string),
		manager:    manager,
	}
}

// HTTPChallengeHandler returns an HTTP handler that serves ACME HTTP-01 challenge
// responses at /.well-known/acme-challenge/<token>.
func (ac *ACMEClient) HTTPChallengeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/.well-known/acme-challenge/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}

		token := strings.TrimPrefix(r.URL.Path, prefix)
		if token == "" {
			http.NotFound(w, r)
			return
		}

		ac.mu.Lock()
		keyAuth, ok := ac.challenges[token]
		ac.mu.Unlock()

		if !ok {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(keyAuth))
	})
}

// SetChallenge stores a challenge token and key authorization for HTTP-01.
func (ac *ACMEClient) SetChallenge(token, keyAuth string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.challenges[token] = keyAuth
}

// ClearChallenge removes a challenge token.
func (ac *ACMEClient) ClearChallenge(token string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	delete(ac.challenges, token)
}

// ObtainCertificate requests a certificate from Let's Encrypt.
//
// This is a simplified implementation showing the ACME flow structure.
// The full ACME protocol requires JSON Web Signature (JWS), nonce handling,
// and polling. This implements the core flow and stubs the API calls.
func (ac *ACMEClient) ObtainCertificate() error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// Step 1: Generate account key (ECDSA P-256) if not already present
	if ac.accountKey == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate account key: %w", err)
		}
		ac.accountKey = key
	}

	// Step 2: Register account with ACME directory
	// TODO: POST to ACME directory URL (e.g., https://acme-v02.api.letsencrypt.org/directory)
	// - Discover newNonce, newAccount, newOrder endpoints
	// - POST JWS-signed request to newAccount with contact email
	// - Handle 201 Created (new account) or 200 OK (existing account)

	// Step 3: Create order for domains
	// TODO: POST JWS-signed request to newOrder endpoint
	// - Body: {"identifiers": [{"type": "dns", "value": "example.com"}]}
	// - Response contains authorization URLs and finalize URL

	// Step 4: Respond to HTTP-01 challenge
	// TODO: For each authorization URL:
	// - GET authorization to find http-01 challenge
	// - Compute key authorization: token + "." + base64url(SHA256(JWK thumbprint))
	// - Store challenge: ac.challenges[token] = keyAuth
	// - POST to challenge URL to signal readiness
	// - Poll authorization until status is "valid"

	// Step 5: Finalize order with CSR
	// TODO: Generate CSR for the requested domains
	// - POST JWS-signed CSR to finalize URL
	// - Poll order until status is "valid"

	// Step 6: Download certificate
	// TODO: GET certificate URL from order
	// - Parse PEM certificate chain
	// - Store in cache directory
	// - Load into TLS manager

	// For now, check if we have cached certificates
	if ac.cacheDir != "" {
		certPath := filepath.Join(ac.cacheDir, "cert.pem")
		keyPath := filepath.Join(ac.cacheDir, "key.pem")
		if _, err := os.Stat(certPath); err == nil {
			if _, err := os.Stat(keyPath); err == nil {
				return ac.manager.LoadCertificate(certPath, keyPath)
			}
		}
	}

	return fmt.Errorf("ACME certificate issuance not fully implemented: use GenerateSelfSigned for development")
}

// StartAutoRenewal starts a background goroutine that checks certificate expiry
// every 12 hours and renews 30 days before expiry.
func (ac *ACMEClient) StartAutoRenewal(stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				ac.checkAndRenew()
			case <-stopCh:
				return
			}
		}
	}()
}

// checkAndRenew checks if certificates need renewal and triggers ObtainCertificate.
func (ac *ACMEClient) checkAndRenew() {
	// Check cached certificate expiry
	if ac.cacheDir == "" {
		return
	}

	certPath := filepath.Join(ac.cacheDir, "cert.pem")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		// No cached cert; try to obtain one
		ac.ObtainCertificate()
		return
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		ac.ObtainCertificate()
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		ac.ObtainCertificate()
		return
	}

	// Renew if expiring within 30 days
	if time.Until(cert.NotAfter) < 30*24*time.Hour {
		ac.ObtainCertificate()
	}
}

// GenerateSelfSigned creates a self-signed certificate for development or fallback.
// The certificate is valid for the specified hosts (domains and/or IPs).
func GenerateSelfSigned(hosts []string) (*tls.Certificate, error) {
	// Generate ECDSA P-256 private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Build certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GuardianWAF Self-Signed"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year validity
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add hosts as SANs
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	// If no hosts provided, default to localhost
	if len(hosts) == 0 {
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Parse into tls.Certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	return &tlsCert, nil
}

// SaveCertificate writes a certificate and key to PEM files.
func SaveCertificate(cert *tls.Certificate, certFile, keyFile string) error {
	if cert == nil || len(cert.Certificate) == 0 {
		return fmt.Errorf("no certificate data to save")
	}

	// Write certificate chain
	f, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer f.Close()

	for _, certBytes := range cert.Certificate {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
			return fmt.Errorf("failed to write certificate: %w", err)
		}
	}

	// Write private key
	kf, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer kf.Close()

	switch key := cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return fmt.Errorf("failed to marshal EC private key: %w", err)
		}
		return pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	default:
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return fmt.Errorf("failed to marshal private key: %w", err)
		}
		return pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}
}
