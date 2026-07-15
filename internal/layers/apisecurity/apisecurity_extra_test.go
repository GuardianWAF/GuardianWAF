package apisecurity

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:])
}

// Cover NewAPIKeyValidator skipping disabled keys.
func TestNewAPIKeyValidator_DisabledKey(t *testing.T) {
	v, err := NewAPIKeyValidator([]APIKeyConfig{
		{Name: "enabled", KeyHash: "sha256:" + hashString("ok"), Enabled: true},
		{Name: "disabled", KeyHash: "sha256:" + hashString("no"), Enabled: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	keys := v.ListKeys()
	if len(keys) != 1 || keys[0] != "enabled" {
		t.Errorf("expected only enabled key, got %v", keys)
	}
}

// Cover Validate prefix lookup fallback.
func TestAPIKeyValidator_Validate_PrefixLookup(t *testing.T) {
	secret := "my-secret-key"
	hashStr := "sha256:" + hashString(secret)
	v, err := NewAPIKeyValidator([]APIKeyConfig{
		{Name: "prefixed", KeyHash: hashStr, KeyPrefix: "gwaf_", Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Exact hash match works
	_, err = v.Validate(secret, "/api/data")
	if err != nil {
		t.Errorf("exact match should succeed: %v", err)
	}

	// Prefix lookup with wrong hash should fail (hashStr[7:] is the hex part)
	_, err = v.Validate("gwaf_wrong_suffix", "/api/data")
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("expected ErrInvalidAPIKey for prefix with wrong hash, got %v", err)
	}
}

// Cover ValidateConstantTime unauthorized path.
func TestValidateConstantTime_UnauthorizedPath(t *testing.T) {
	secret := "secret"
	hashStr := "sha256:" + hashString(secret)
	v, _ := NewAPIKeyValidator([]APIKeyConfig{
		{Name: "restricted", KeyHash: hashStr, Enabled: true, AllowedPaths: []string{"/allowed"}},
	})

	_, err := v.ValidateConstantTime(secret, "/blocked")
	if !errors.Is(err, ErrUnauthorizedPath) {
		t.Errorf("expected ErrUnauthorizedPath, got %v", err)
	}
}

// Cover NewLayer JWT error branch.
func TestNewLayer_JWTError(t *testing.T) {
	cfg := Config{
		Enabled: true,
		JWT: JWTConfig{
			Enabled:      true,
			PublicKeyPEM: "not-valid-pem",
		},
	}
	_, err := NewLayer(&cfg)
	if err == nil {
		t.Error("expected error from invalid JWT PEM")
	}
}

// Cover Process JWT validation failure branch.
func TestProcess_JWTInvalid(t *testing.T) {
	cfg := Config{
		Enabled: true,
		JWT:     JWTConfig{Enabled: true},
	}
	layer, _ := NewLayer(&cfg)
	layer.jwtValidator.publicKey = []byte("secret")

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	ctx := engine.AcquireContext(req, 1, 1024*1024)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for invalid JWT, got %v", result.Action)
	}
}

// Cover Process when layer enabled but no auth configured.
func TestProcess_NoAuthConfigured(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, _ := NewLayer(&cfg)

	req := httptest.NewRequest("GET", "/api/test", nil)
	ctx := engine.AcquireContext(req, 1, 1024*1024)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass when no auth configured, got %v", result.Action)
	}
}

// Cover RefreshJWKS with non-nil validator.
func TestRefreshJWKS_WithValidator(t *testing.T) {
	cfg := Config{
		Enabled: true,
		JWT:     JWTConfig{Enabled: true},
	}
	layer, _ := NewLayer(&cfg)
	// Should not panic even with empty JWKS URL
	layer.RefreshJWKS()
}

// Cover matchPath single-segment wildcard.
func TestMatchPath_SingleSegmentWildcard(t *testing.T) {
	if !matchPath("/api/*/users", "/api/v1/users") {
		t.Error("expected match for /api/v1/users")
	}
	if matchPath("/api/*/users", "/api/v1/items") {
		t.Error("expected no match for different suffix")
	}
	if !matchPath("/api/*/users/extra", "/api/v1/users/extra") {
		t.Error("expected match for /api/v1/users/extra with wildcard")
	}
}
