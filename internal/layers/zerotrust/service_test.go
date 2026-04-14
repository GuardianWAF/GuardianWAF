package zerotrust

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"testing"
	"time"
)

func TestNewService(t *testing.T) {
	service, err := NewService(nil)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	if service == nil {
		t.Fatal("expected service, got nil")
	}
}

func TestNewService_WithConfig(t *testing.T) {
	cfg := &Config{
		Enabled:              true,
		RequireMTLS:          true,
		SessionTTL:           2 * time.Hour,
		DeviceTrustThreshold: TrustLevelHigh,
	}

	service, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	if service.config.SessionTTL != 2*time.Hour {
		t.Errorf("SessionTTL = %v, want %v", service.config.SessionTTL, 2*time.Hour)
	}

	if service.config.DeviceTrustThreshold != TrustLevelHigh {
		t.Errorf("DeviceTrustThreshold = %v, want %v", service.config.DeviceTrustThreshold, TrustLevelHigh)
	}
}

func TestTrustLevel_String(t *testing.T) {
	tests := []struct {
		level    TrustLevel
		expected string
	}{
		{TrustLevelNone, "none"},
		{TrustLevelLow, "low"},
		{TrustLevelMedium, "medium"},
		{TrustLevelHigh, "high"},
		{TrustLevelMaximum, "maximum"},
		{TrustLevel(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.level.String()
			if result != tt.expected {
				t.Errorf("String() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestCalculateDeviceFingerprint(t *testing.T) {
	// Create a test certificate
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "test-client",
		},
		SerialNumber: big.NewInt(12345),
	}

	// This will fail because we can't easily create a public key
	// Just test that it doesn't panic
	_ = calculateDeviceFingerprint(cert)
}

func TestService_CleanupExpiredSessions(t *testing.T) {
	service, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1 * time.Second,
	})

	// Add a test session (already expired)
	sessionID := "test-session-1"
	service.mu.Lock()
	service.sessions[sessionID] = &ClientIdentity{
		ClientID:        "test-client",
		SessionID:       sessionID,
		AuthenticatedAt: time.Now().Add(-2 * time.Second), // Expired
		TrustLevel:      TrustLevelMedium,
	}
	service.mu.Unlock()

	// Verify session exists (directly, not through GetClientIdentity)
	service.mu.RLock()
	_, exists := service.sessions[sessionID]
	service.mu.RUnlock()
	if !exists {
		t.Fatal("expected session to exist before cleanup")
	}

	// Cleanup
	service.CleanupExpiredSessions()

	// Verify session is removed
	service.mu.RLock()
	_, exists = service.sessions[sessionID]
	service.mu.RUnlock()
	if exists {
		t.Error("expected session to be removed after cleanup")
	}
}

func TestService_RevokeSession(t *testing.T) {
	service, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1 * time.Hour,
	})

	// Add a test session
	sessionID := "test-session-1"
	service.sessions[sessionID] = &ClientIdentity{
		ClientID:        "test-client",
		SessionID:       sessionID,
		AuthenticatedAt: time.Now(),
		TrustLevel:      TrustLevelMedium,
	}

	// Revoke
	service.RevokeSession(sessionID)

	// Verify session is removed
	if service.GetClientIdentity(sessionID) != nil {
		t.Error("expected session to be revoked")
	}
}

func TestService_CheckAccess_BypassPaths(t *testing.T) {
	service, _ := NewService(&Config{
		Enabled:          true,
		RequireMTLS:      true,
		AllowBypassPaths: []string{"/healthz", "/metrics"},
	})

	tests := []struct {
		path      string
		shouldErr bool
	}{
		{"/healthz", false},
		{"/healthz/live", false},
		{"/metrics", false},
		{"/api/data", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			err := service.CheckAccess(nil, tt.path)
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for path %s", tt.path)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for path %s: %v", tt.path, err)
			}
		})
	}
}

func TestService_CheckAccess_TrustLevel(t *testing.T) {
	service, _ := NewService(&Config{
		Enabled:              true,
		RequireMTLS:          true,
		DeviceTrustThreshold: TrustLevelHigh,
	})

	tests := []struct {
		name      string
		identity  *ClientIdentity
		shouldErr bool
	}{
		{
			name:      "nil identity",
			identity:  nil,
			shouldErr: true,
		},
		{
			name: "low trust",
			identity: &ClientIdentity{
				ClientID:   "test",
				TrustLevel: TrustLevelLow,
			},
			shouldErr: true,
		},
		{
			name: "medium trust",
			identity: &ClientIdentity{
				ClientID:   "test",
				TrustLevel: TrustLevelMedium,
			},
			shouldErr: true,
		},
		{
			name: "high trust",
			identity: &ClientIdentity{
				ClientID:   "test",
				TrustLevel: TrustLevelHigh,
			},
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.CheckAccess(tt.identity, "/api/data")
			if tt.shouldErr && err == nil {
				t.Error("expected error")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseClientCertificate(t *testing.T) {
	// Test with invalid PEM data
	_, err := ParseClientCertificate([]byte("not a valid pem"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}

	// Test with valid PEM structure (but not a real cert)
	pemData := []byte(`-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpE
-----END CERTIFICATE-----`)
	ParseClientCertificate(pemData)
	// This will fail because the data is incomplete
	// Just verify it doesn't panic
}

func TestService_GetTrustLevel(t *testing.T) {
	service, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1 * time.Hour,
	})

	// Add a session
	sessionID := "test-session"
	service.sessions[sessionID] = &ClientIdentity{
		ClientID:        "test-client",
		SessionID:       sessionID,
		AuthenticatedAt: time.Now(),
		TrustLevel:      TrustLevelHigh,
	}

	// Create request with session header
	req := &http.Request{}
	req.Header = make(http.Header)
	req.Header.Set("X-ZeroTrust-Session", sessionID)

	level := service.GetTrustLevel(req)
	if level != TrustLevelHigh {
		t.Errorf("GetTrustLevel = %v, want %v", level, TrustLevelHigh)
	}
}

func TestService_GetTrustLevel_NoSession(t *testing.T) {
	service, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1 * time.Hour,
	})

	req := &http.Request{}
	req.Header = make(http.Header)
	// No session header set

	level := service.GetTrustLevel(req)
	if level != TrustLevelNone {
		t.Errorf("GetTrustLevel = %v, want %v", level, TrustLevelNone)
	}
}

func TestService_VerifyClientCertificate_Nil(t *testing.T) {
	service, _ := NewService(&Config{
		Enabled: true,
	})

	_, err := service.VerifyClientCertificate(nil)
	if err == nil {
		t.Error("expected error for nil certificate")
	}
}

func TestService_VerifyClientCertificate_Expired(t *testing.T) {
	service, _ := NewService(&Config{
		Enabled: true,
	})

	// Create an expired certificate
	cert := &x509.Certificate{
		NotBefore: time.Now().Add(-2 * time.Hour),
		NotAfter:  time.Now().Add(-1 * time.Hour), // Expired
		Subject:   pkix.Name{CommonName: "test-client"},
	}

	_, err := service.VerifyClientCertificate(cert)
	if err == nil {
		t.Error("expected error for expired certificate")
	}
}

func TestService_VerifyClientCertificate_NotYetValid(t *testing.T) {
	service, _ := NewService(&Config{
		Enabled: true,
	})

	// Create a not-yet-valid certificate
	cert := &x509.Certificate{
		NotBefore: time.Now().Add(1 * time.Hour),
		NotAfter:  time.Now().Add(2 * time.Hour),
		Subject:   pkix.Name{CommonName: "test-client"},
	}

	_, err := service.VerifyClientCertificate(cert)
	if err == nil {
		t.Error("expected error for not-yet-valid certificate")
	}
}

func TestService_VerifyDeviceAttestation(t *testing.T) {
	service, _ := NewService(&Config{
		Enabled: true,
	})

	device, err := service.VerifyDeviceAttestation("device-123", []byte("attestation-data"))
	if err != nil {
		t.Fatalf("VerifyDeviceAttestation failed: %v", err)
	}

	if device.DeviceID != "device-123" {
		t.Errorf("DeviceID = %s, want device-123", device.DeviceID)
	}

	if device.TrustLevel != TrustLevelHigh {
		t.Errorf("TrustLevel = %v, want %v", device.TrustLevel, TrustLevelHigh)
	}

	if len(device.AttestationData) == 0 {
		t.Error("expected attestation data to be stored")
	}
}

func TestService_GetClientIdentity_Expired(t *testing.T) {
	service, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1 * time.Second,
	})

	// Add an expired session
	sessionID := "expired-session"
	service.sessions[sessionID] = &ClientIdentity{
		ClientID:        "test-client",
		SessionID:       sessionID,
		AuthenticatedAt: time.Now().Add(-2 * time.Second),
		TrustLevel:      TrustLevelHigh,
	}

	// GetClientIdentity should return nil for expired sessions
	identity := service.GetClientIdentity(sessionID)
	if identity != nil {
		t.Error("expected nil for expired session")
	}
}

func TestService_GetClientIdentity_NotFound(t *testing.T) {
	service, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1 * time.Hour,
	})

	identity := service.GetClientIdentity("non-existent")
	if identity != nil {
		t.Error("expected nil for non-existent session")
	}
}

func TestExtractClientID(t *testing.T) {
	cert := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "test-client-001"},
		SerialNumber: big.NewInt(9876543210),
	}

	clientID := extractClientID(cert)
	if clientID != "test-client-001" {
		t.Errorf("extractClientID = %s, want test-client-001", clientID)
	}
}

func TestExtractClientID_NoCommonName(t *testing.T) {
	cert := &x509.Certificate{
		Subject:     pkix.Name{CommonName: ""},
		SerialNumber: big.NewInt(12345),
	}

	clientID := extractClientID(cert)
	if clientID != "12345" {
		t.Errorf("extractClientID = %s, want 12345", clientID)
	}
}

func TestGenerateSessionID(t *testing.T) {
	id1 := generateSessionID()
	id2 := generateSessionID()

	if id1 == "" {
		t.Error("expected non-empty session ID")
	}

	if id1 == id2 {
		t.Error("expected unique session IDs")
	}
}

func TestService_CheckAccess_RequireMTLS(t *testing.T) {
	service, _ := NewService(&Config{
		Enabled:     true,
		RequireMTLS: true,
	})

	err := service.CheckAccess(nil, "/api/data")
	if err == nil {
		t.Error("expected error when mTLS required and identity is nil")
	}
}

func TestService_CheckAccess_NoRequireMTLS(t *testing.T) {
	service, _ := NewService(&Config{
		Enabled:     true,
		RequireMTLS: false,
	})

	err := service.CheckAccess(nil, "/api/data")
	if err != nil {
		t.Errorf("unexpected error when mTLS not required: %v", err)
	}
}

func TestContextFunctions(t *testing.T) {
	identity := &ClientIdentity{
		ClientID:   "test-client",
		SessionID:  "test-session",
		TrustLevel: TrustLevelHigh,
	}

	ctx := WithClientIdentity(context.Background(), identity)

	// Test GetClientIdentityFromContext
	retrieved := GetClientIdentityFromContext(ctx)
	if retrieved == nil {
		t.Fatal("expected identity from context")
	}
	if retrieved.ClientID != identity.ClientID {
		t.Errorf("ClientID = %s, want %s", retrieved.ClientID, identity.ClientID)
	}

	// Test GetSessionIDFromContext
	sessionID := GetSessionIDFromContext(ctx)
	if sessionID != identity.SessionID {
		t.Errorf("SessionID = %s, want %s", sessionID, identity.SessionID)
	}

	// Test GetTrustLevelFromContext
	level := GetTrustLevelFromContext(ctx)
	if level != TrustLevelHigh {
		t.Errorf("TrustLevel = %v, want %v", level, TrustLevelHigh)
	}

	// Test IsAuthenticated
	if !IsAuthenticated(ctx) {
		t.Error("expected IsAuthenticated to return true")
	}

	// Test with empty context
	emptyCtx := context.Background()
	if IsAuthenticated(emptyCtx) {
		t.Error("expected IsAuthenticated to return false for empty context")
	}
}
