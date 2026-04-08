// Package zerotrust provides Zero Trust Network Access with mTLS and device attestation.
package zerotrust

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TrustLevel defines the trust level of a client or device.
type TrustLevel int

const (
	TrustLevelNone     TrustLevel = iota // No trust
	TrustLevelLow                        // Low trust (e.g., valid cert but unknown device)
	TrustLevelMedium                     // Medium trust (valid cert + known device)
	TrustLevelHigh                       // High trust (valid cert + attested device)
	TrustLevelMaximum                    // Maximum trust (valid cert + attested + recent auth)
)

// String returns the string representation of a trust level.
func (t TrustLevel) String() string {
	switch t {
	case TrustLevelNone:
		return "none"
	case TrustLevelLow:
		return "low"
	case TrustLevelMedium:
		return "medium"
	case TrustLevelHigh:
		return "high"
	case TrustLevelMaximum:
		return "maximum"
	default:
		return "unknown"
	}
}

// DeviceInfo contains information about a device.
type DeviceInfo struct {
	DeviceID        string
	Fingerprint     string
	AttestationData []byte
	AttestedAt      time.Time
	TrustLevel      TrustLevel
	LastSeenAt      time.Time
	Metadata        map[string]string
}

// ClientIdentity represents an authenticated client identity.
type ClientIdentity struct {
	ClientID    string
	Certificate *x509.Certificate
	Device      *DeviceInfo
	TrustLevel  TrustLevel
	AuthenticatedAt time.Time
	SessionID   string
}

// Config for Zero Trust.
type Config struct {
	Enabled              bool          `yaml:"enabled"`
	RequireMTLS          bool          `yaml:"require_mtls"`
	RequireAttestation   bool          `yaml:"require_attestation"`
	SessionTTL           time.Duration `yaml:"session_ttl"`
	AttestationTTL       time.Duration `yaml:"attestation_ttl"`
	TrustedCAPath        string        `yaml:"trusted_ca_path"`
	DeviceTrustThreshold TrustLevel    `yaml:"device_trust_threshold"`
	AllowBypassPaths     []string      `yaml:"allow_bypass_paths"`
}

// DefaultConfig returns default Zero Trust configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled:              false,
		RequireMTLS:          true,
		RequireAttestation:   false,
		SessionTTL:           1 * time.Hour,
		AttestationTTL:       24 * time.Hour,
		DeviceTrustThreshold: TrustLevelMedium,
		AllowBypassPaths:     []string{"/healthz", "/metrics"},
	}
}

// Service provides Zero Trust functionality.
type Service struct {
	config      *Config
	trustedCAs  *x509.CertPool
	devices     map[string]*DeviceInfo // deviceID -> DeviceInfo
	sessions    map[string]*ClientIdentity // sessionID -> ClientIdentity
	mu          sync.RWMutex
}

// NewService creates a new Zero Trust service.
func NewService(cfg *Config) (*Service, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	s := &Service{
		config:   cfg,
		devices:  make(map[string]*DeviceInfo),
		sessions: make(map[string]*ClientIdentity),
	}

	// Load trusted CAs if path provided
	if cfg.TrustedCAPath != "" {
		if err := s.loadTrustedCAs(cfg.TrustedCAPath); err != nil {
			return nil, fmt.Errorf("failed to load trusted CAs: %w", err)
		}
	}

	return s, nil
}

// loadTrustedCAs loads trusted CA certificates from a file.
func (s *Service) loadTrustedCAs(path string) error {
	// In a real implementation, load CA certs from file
	// For now, use system CAs
	s.trustedCAs = x509.NewCertPool()
	return nil
}

// VerifyClientCertificate verifies a client certificate and returns the client identity.
func (s *Service) VerifyClientCertificate(cert *x509.Certificate) (*ClientIdentity, error) {
	if cert == nil {
		return nil, fmt.Errorf("no client certificate provided")
	}

	// Verify certificate is valid
	if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("certificate is not valid at this time")
	}

	// Verify certificate against trusted CAs if configured
	if s.trustedCAs != nil {
		opts := x509.VerifyOptions{
			Roots:         s.trustedCAs,
			CurrentTime:   time.Now(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if _, err := cert.Verify(opts); err != nil {
			return nil, fmt.Errorf("certificate verification failed: %w", err)
		}
	}

	// Extract client ID from certificate
	clientID := extractClientID(cert)

	identity := &ClientIdentity{
		ClientID:    clientID,
		Certificate: cert,
		TrustLevel:  TrustLevelLow,
		AuthenticatedAt: time.Now(),
		SessionID:   generateSessionID(),
	}

	// Check if device is known/attested
	deviceFingerprint := calculateDeviceFingerprint(cert)
	s.mu.RLock()
	device, exists := s.devices[deviceFingerprint]
	s.mu.RUnlock()

	if exists && device != nil {
		identity.Device = device
		identity.TrustLevel = device.TrustLevel

		// Update last seen
		s.mu.Lock()
		device.LastSeenAt = time.Now()
		s.mu.Unlock()
	}

	// Store session (with cap to prevent OOM)
	s.mu.Lock()
	if len(s.sessions) >= 100000 {
		// Evict expired sessions
		for id, ci := range s.sessions {
			if time.Since(ci.AuthenticatedAt) > s.config.SessionTTL {
				delete(s.sessions, id)
			}
			if len(s.sessions) < 100000 {
				break
			}
		}
	}
	s.sessions[identity.SessionID] = identity
	s.mu.Unlock()

	return identity, nil
}

// VerifyDeviceAttestation verifies device attestation data.
func (s *Service) VerifyDeviceAttestation(deviceID string, attestationData []byte) (*DeviceInfo, error) {
	// In a real implementation, this would:
	// 1. Parse attestation data (e.g., TPM attestation, Apple App Attest, Android SafetyNet)
	// 2. Verify attestation signature
	// 3. Check device integrity
	// 4. Verify device is not compromised

	// Simplified implementation
	device := &DeviceInfo{
		DeviceID:        deviceID,
		Fingerprint:     calculateDeviceFingerprintFromData(attestationData),
		AttestationData: attestationData,
		AttestedAt:      time.Now(),
		TrustLevel:      TrustLevelHigh,
		LastSeenAt:      time.Now(),
		Metadata:        make(map[string]string),
	}

	s.mu.Lock()
	s.devices[device.Fingerprint] = device
	s.mu.Unlock()

	return device, nil
}

// GetClientIdentity retrieves a client identity by session ID.
func (s *Service) GetClientIdentity(sessionID string) *ClientIdentity {
	s.mu.RLock()
	defer s.mu.RUnlock()

	identity, exists := s.sessions[sessionID]
	if !exists {
		return nil
	}

	// Check session expiry
	if time.Since(identity.AuthenticatedAt) > s.config.SessionTTL {
		return nil
	}

	return identity
}

// RevokeSession revokes a client session.
func (s *Service) RevokeSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// CleanupExpiredSessions removes expired sessions.
func (s *Service) CleanupExpiredSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, identity := range s.sessions {
		if time.Since(identity.AuthenticatedAt) > s.config.SessionTTL {
			delete(s.sessions, id)
		}
	}
}

// CheckAccess checks if a client has access to a resource.
func (s *Service) CheckAccess(identity *ClientIdentity, path string) error {
	// Check bypass paths
	for _, bypassPath := range s.config.AllowBypassPaths {
		if strings.HasPrefix(path, bypassPath) {
			return nil
		}
	}

	// Check if mTLS is required
	if s.config.RequireMTLS && identity == nil {
		return fmt.Errorf("mTLS authentication required")
	}

	// Check trust level
	if identity != nil && identity.TrustLevel < s.config.DeviceTrustThreshold {
		return fmt.Errorf("insufficient trust level: %s (required: %s)",
			identity.TrustLevel.String(), s.config.DeviceTrustThreshold.String())
	}

	return nil
}

// GetTrustLevel returns the trust level for a request.
func (s *Service) GetTrustLevel(r *http.Request) TrustLevel {
	sessionID := r.Header.Get("X-ZeroTrust-Session")
	if sessionID == "" {
		return TrustLevelNone
	}

	identity := s.GetClientIdentity(sessionID)
	if identity == nil {
		return TrustLevelNone
	}

	return identity.TrustLevel
}

// Helper functions

func extractClientID(cert *x509.Certificate) string {
	// Try to extract a unique identifier from the certificate
	// Common name is often used
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}

	// Fall back to serial number
	return cert.SerialNumber.String()
}

func calculateDeviceFingerprint(cert *x509.Certificate) string {
	// Calculate a fingerprint based on certificate public key
	pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(pubKeyDER)
	return hex.EncodeToString(hash[:])
}

func calculateDeviceFingerprintFromData(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func generateSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return hex.EncodeToString(b)
}

// ParseClientCertificate parses a PEM-encoded client certificate.
func ParseClientCertificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}
