package tenant

import (
	"path/filepath"
	"testing"
)

func TestPathWithinDir(t *testing.T) {
	// Same path
	dir, _ := filepath.Abs(".")
	if !pathWithinDir(dir, dir) {
		t.Fatal("same path should be within dir")
	}

	// Subdirectory
	sub := filepath.Join(dir, "sub")
	if !pathWithinDir(dir, sub) {
		t.Fatal("subdirectory should be within dir")
	}

	// Outside path
	parent := filepath.Join(dir, "..")
	if pathWithinDir(dir, parent) {
		t.Fatal("parent should not be within dir")
	}
}

func TestTenantFilePath_InvalidFilename(t *testing.T) {
	_, err := tenantFilePath(".", "bad/name.json")
	if err == nil {
		t.Fatal("expected error for filename with path separator")
	}

	_, err = tenantFilePath(".", "noextension")
	if err == nil {
		t.Fatal("expected error for filename without .json extension")
	}
}

func TestValidTenantDataFilename(t *testing.T) {
	if validTenantDataFilename("index.json") {
		t.Fatal("index.json should not be a valid tenant filename")
	}
	if validTenantDataFilename("../etc.json") {
		t.Fatal("filename with path separator should be invalid")
	}
	if validTenantDataFilename("test.txt") {
		t.Fatal("non-.json extension should be invalid")
	}
	if !validTenantDataFilename("tenant_abc123.json") {
		t.Fatal("valid tenant filename should be accepted")
	}
	if validTenantDataFilename("") {
		t.Fatal("empty filename should be invalid")
	}
}

func TestGenerateTenantID(t *testing.T) {
	id, err := generateTenantID("test-tenant")
	if err != nil {
		t.Fatalf("generateTenantID failed: %v", err)
	}
	if len(id) != 32 { // 16 bytes = 32 hex chars
		t.Fatalf("expected 32-char tenant ID, got %q (len=%d)", id, len(id))
	}
	if id == "" {
		t.Fatal("tenant ID should not be empty")
	}
}

func TestGenerateAPIKey(t *testing.T) {
	key, err := generateAPIKey()
	if err != nil {
		t.Fatalf("generateAPIKey failed: %v", err)
	}
	if len(key) != 53 { // "gwaf_" prefix (5) + 24 bytes hex-encoded (48)
		t.Fatalf("expected 53-char API key, got %q (len=%d)", key, len(key))
	}
	if key[:5] != "gwaf_" {
		t.Fatalf("expected gwaf_ prefix, got %q", key[:5])
	}
}

func TestVerifyAPIKey(t *testing.T) {
	// v2 format: valid round-trip
	key, _ := generateAPIKey()
	hash, err := hashAPIKey(key)
	if err != nil {
		t.Fatalf("hashAPIKey failed: %v", err)
	}
	matched, legacy := verifyAPIKey(hash, key)
	if !matched {
		t.Fatal("v2 key should match")
	}
	if legacy {
		t.Fatal("v2 key should not be marked legacy")
	}

	// Wrong key should not match
	matched, _ = verifyAPIKey(hash, "wrong-key")
	if matched {
		t.Fatal("wrong key should not match")
	}

	// Invalid format
	matched, _ = verifyAPIKey("invalid-format", key)
	if matched {
		t.Fatal("invalid format should not match")
	}

	// v2 with bad hex salt
	matched, _ = verifyAPIKey("v2$nothex$abcdef", key)
	if matched {
		t.Fatal("bad hex salt should not match")
	}

	// v2 with bad hex hash
	matched, _ = verifyAPIKey("v2$"+"aabb"+"/invalid", key)
	if matched {
		t.Fatal("bad hex hash should not match")
	}
}

func TestHashVerifyRoundTrip(t *testing.T) {
	apiKey := "test-api-key-12345"
	hash, err := hashAPIKey(apiKey)
	if err != nil {
		t.Fatalf("hashAPIKey failed: %v", err)
	}

	matched, legacy := verifyAPIKey(hash, apiKey)
	if !matched {
		t.Fatal("hash-verify round trip failed")
	}
	if legacy {
		t.Fatal("v2 hash should not be legacy")
	}
}

func TestCleanTenantStorePath_Errors(t *testing.T) {
	// NUL byte in path
	_, err := cleanTenantStorePath("bad\x00path")
	if err == nil {
		t.Fatal("expected error for path with NUL byte")
	}

	// Empty path defaults to data/tenants
	path, err := cleanTenantStorePath("")
	if err != nil {
		t.Fatalf("unexpected error for empty path: %v", err)
	}
	if path != "data/tenants" {
		t.Fatalf("expected data/tenants, got %q", path)
	}
}

func TestTenantDataFilename_EdgeCases(t *testing.T) {
	if validTenantDataFilename("") {
		t.Fatal("empty filename should be invalid")
	}
	if validTenantDataFilename("/absolute.json") {
		t.Fatal("absolute path should be invalid")
	}
	if validTenantDataFilename(".") {
		t.Fatal("dot should be invalid")
	}
}

func TestDeriveKey_DifferentSalts(t *testing.T) {
	key := []byte("test-key")
	salt1 := []byte("salt-123456789012")
	salt2 := []byte("salt-987654321098")

	r1 := deriveKey(key, salt1, 100)
	r2 := deriveKey(key, salt2, 100)

	if len(r1) != 32 {
		t.Fatalf("expected 32-byte derived key, got %d", len(r1))
	}

	// Different salts must produce different results
	equal := true
	for i := range r1 {
		if r1[i] != r2[i] {
			equal = false
			break
		}
	}
	if equal {
		t.Fatal("different salts produced identical derived keys")
	}
}
