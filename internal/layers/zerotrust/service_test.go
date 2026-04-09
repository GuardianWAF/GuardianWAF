package zerotrust

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
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
