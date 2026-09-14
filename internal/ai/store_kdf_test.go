package ai

import (
	"encoding/hex"
	"testing"
)

// Regression (the catalog-closure weak note): deriveStoreKey was a
// PBKDF2-LIKE hand-rolled iterated HMAC (the salt passed as the HMAC
// message, no INT(i) block counter) at 10k iterations. It now delegates to
// the crypto/pbkdf2 stdlib package. This published known-answer vector pins
// the STANDARD construction: PBKDF2-HMAC-SHA256("password", "salt", c=1,
// dkLen=32).
func TestDeriveStoreKeyMatchesPBKDF2KnownVector(t *testing.T) {
	got := hex.EncodeToString(deriveStoreKey([]byte("password"), []byte("salt"), 1))
	want := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if got != want {
		t.Fatalf("FAIL: deriveStoreKey is not standard PBKDF2-HMAC-SHA256:\n got %s\nwant %s", got, want)
	}
}

// The at-rest encryption key derivation must follow OWASP 2023 guidance for
// PBKDF2-HMAC-SHA256 (600,000 iterations), matching the acme client's
// account-key derivation.
func TestEncKeyIterationsFollowOWASPGuidance(t *testing.T) {
	if encKeyIterations != 600000 {
		t.Fatalf("FAIL: encKeyIterations = %d, want 600000 (OWASP 2023 guidance for PBKDF2-HMAC-SHA256)", encKeyIterations)
	}
}
