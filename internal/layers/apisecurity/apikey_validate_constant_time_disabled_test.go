package apisecurity

import (
	"errors"
	"testing"
)

// Regression (round 4/25): ValidateConstantTime skipped the Enabled check
// that Validate enforces. AddKey registers Enabled:false configs verbatim
// (only the constructor skips disabled configs), so a runtime-added disabled
// key was rejected by Validate (ErrAPIKeyDisabled) but authenticated through
// ValidateConstantTime — disabling a key did not hold on that path.
func TestValidateConstantTime_DisabledKeyRejected(t *testing.T) {
	v, err := NewAPIKeyValidator(nil)
	if err != nil {
		t.Fatalf("FAIL: constructor: %v", err)
	}
	if err := v.AddKey(APIKeyConfig{
		Name:         "revoked",
		KeyHash:      "gwaf-dead-key-456",
		Enabled:      false,
		AllowedPaths: []string{"/api/*"},
	}); err != nil {
		t.Fatalf("FAIL: AddKey: %v", err)
	}
	if err := v.AddKey(APIKeyConfig{Name: "live", KeyHash: "gwaf-live-key-123", Enabled: true}); err != nil {
		t.Fatalf("FAIL: AddKey(live): %v", err)
	}

	// Parity baseline: Validate rejects the disabled key.
	if _, err := v.Validate("gwaf-dead-key-456", "/api/data"); !errors.Is(err, ErrAPIKeyDisabled) {
		t.Fatalf("FAIL: Validate(disabled) err=%v, want ErrAPIKeyDisabled", err)
	}

	// The constant-time path must reject it too.
	res, err := v.ValidateConstantTime("gwaf-dead-key-456", "/api/data")
	if err == nil {
		name := ""
		if res != nil {
			name = res.Name
		}
		t.Fatalf("FAIL: ValidateConstantTime authenticated disabled key (config=%q, err=nil)", name)
	}
	if !errors.Is(err, ErrAPIKeyDisabled) {
		t.Fatalf("FAIL: ValidateConstantTime(disabled) err=%v, want ErrAPIKeyDisabled", err)
	}

	// Controls: enabled key authenticates; wrong key rejected.
	if res, err := v.ValidateConstantTime("gwaf-live-key-123", "/api/data"); err != nil || res == nil || res.Name != "live" {
		t.Fatalf("FAIL: enabled key must still authenticate: res=%v err=%v", res, err)
	}
	if _, err := v.ValidateConstantTime("wrong-key", "/api/data"); !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("FAIL: wrong key err=%v, want ErrInvalidAPIKey", err)
	}
	if _, err := v.Validate("gwaf-live-key-123", "/api/data"); err != nil {
		t.Fatalf("FAIL: Validate(live) err=%v — Validate path must keep working", err)
	}
}
