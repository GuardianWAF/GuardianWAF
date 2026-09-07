package apisecurity

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// Regression tests: API-key configurations that could never authenticate
// must be rejected loudly instead of silently accepted. Two defects
// previously produced silent no-op key configs: (1) the struct comment
// advertised "bcrypt:hash" support but Validate only ever builds
// "sha256:<hex>" lookups, so a bcrypt-configured key failed forever with
// ErrInvalidAPIKey; (2) a bare (unprefixed) key_hash value was stored raw —
// never hashed — so the natural configuration form also never matched. The
// constructor and AddKey now normalize-or-reject, and NewLayer propagates
// the constructor error (fail loud, per its own design comment).

func TestNewAPIKeyValidatorRejectsUnsupportedScheme(t *testing.T) {
	_, err := NewAPIKeyValidator([]APIKeyConfig{
		{Name: "ops", KeyHash: "bcrypt:$2a$10$abcdefghijklmnopqrstuv", Enabled: true},
	})
	if err == nil {
		t.Fatal("FAIL: constructor silently accepted a bcrypt key_hash that can never authenticate")
	}
	if !strings.Contains(err.Error(), "bcrypt") {
		t.Fatalf("FAIL: error does not name the unsupported scheme: %v", err)
	}
}

func TestNewAPIKeyValidatorRejectsEmptyKeyHash(t *testing.T) {
	if _, err := NewAPIKeyValidator([]APIKeyConfig{{Name: "empty", KeyHash: "", Enabled: true}}); err == nil {
		t.Fatal("FAIL: constructor silently accepted an empty key_hash")
	}
}

// A bare (unprefixed) key_hash is treated as the raw key and hashed on load
// — the same contract AddKey has always had — so the natural configuration
// form actually authenticates.
func TestNewAPIKeyValidatorHashesBareValues(t *testing.T) {
	v, err := NewAPIKeyValidator([]APIKeyConfig{
		{Name: "app", KeyHash: "sk-live-secret123", Enabled: true},
	})
	if err != nil {
		t.Fatalf("NewAPIKeyValidator: %v", err)
	}

	cfg, err := v.Validate("sk-live-secret123", "/api")
	if err != nil {
		t.Fatalf("FAIL: bare key_hash value can never authenticate: %v", err)
	}
	if cfg.Name != "app" {
		t.Fatalf("FAIL: matched wrong config %q", cfg.Name)
	}
}

func TestAddKeyNormalizesAndRejects(t *testing.T) {
	v, err := NewAPIKeyValidator(nil)
	if err != nil {
		t.Fatalf("NewAPIKeyValidator: %v", err)
	}

	// Bare value: hashed on add, then authenticates.
	if err := v.AddKey(APIKeyConfig{Name: "app", KeyHash: "sk-live-abc", Enabled: true}); err != nil {
		t.Fatalf("AddKey(bare): %v", err)
	}
	if _, err := v.Validate("sk-live-abc", "/api"); err != nil {
		t.Fatalf("FAIL: bare key added via AddKey can never authenticate: %v", err)
	}

	// Unsupported scheme: rejected loudly.
	if err := v.AddKey(APIKeyConfig{Name: "bad", KeyHash: "bcrypt:$2a$10$x", Enabled: true}); err == nil {
		t.Fatal("FAIL: AddKey silently accepted a bcrypt key_hash")
	}

	// Empty: rejected loudly.
	if err := v.AddKey(APIKeyConfig{Name: "worse", KeyHash: "", Enabled: true}); err == nil {
		t.Fatal("FAIL: AddKey silently accepted an empty key_hash")
	}
}

// Control: the pre-existing sha256-prefixed contract is untouched.
func TestValidateSHA256Control(t *testing.T) {
	sum := sha256.Sum256([]byte("sk-live-control"))
	v, err := NewAPIKeyValidator([]APIKeyConfig{
		{Name: "ctl", KeyHash: "sha256:" + hex.EncodeToString(sum[:]), Enabled: true},
	})
	if err != nil {
		t.Fatalf("NewAPIKeyValidator: %v", err)
	}
	if _, err := v.Validate("sk-live-control", "/api"); err != nil {
		t.Fatalf("FAIL: valid sha256 key rejected: %v", err)
	}
}
