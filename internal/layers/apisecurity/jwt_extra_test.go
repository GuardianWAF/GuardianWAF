package apisecurity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- Helper: create HS256 JWT ---

func makeHS256Token(header map[string]string, claims JWTClaims, secret []byte) string {
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return signingInput + "." + sig
}

func makeValidHS256Token(claims JWTClaims, secret []byte) string {
	return makeHS256Token(map[string]string{"alg": "HS256", "typ": "JWT"}, claims, secret)
}

// --- JWT Validate Tests ---

func TestJWTValidate_EmptyToken(t *testing.T) {
	v, err := NewJWTValidator(JWTConfig{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Validate("")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

func TestJWTValidate_InvalidFormat(t *testing.T) {
	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	_, err := v.Validate("not.a.valid.jwt.token")
	if err == nil {
		t.Error("expected error for invalid format")
	}
	if !strings.Contains(err.Error(), "invalid token format") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestJWTValidate_InvalidHeaderEncoding(t *testing.T) {
	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	_, err := v.Validate("!!!.payload.signature")
	if err == nil {
		t.Error("expected error for invalid header")
	}
}

func TestJWTValidate_HS256_Valid(t *testing.T) {
	secret := []byte("test-secret-key-123")
	now := time.Now().Unix()
	claims := JWTClaims{
		Issuer:    "test-issuer",
		Subject:   "user-123",
		ExpiresAt: now + 3600,
		IssuedAt:  now,
	}

	v, err := NewJWTValidator(JWTConfig{
		Enabled: true,
		Issuer:  "test-issuer",
	})
	if err != nil {
		t.Fatal(err)
	}
	v.publicKey = secret

	token := makeValidHS256Token(claims, secret)
	parsed, err := v.Validate(token)
	if err != nil {
		t.Fatalf("expected valid token, got: %v", err)
	}
	if parsed.Subject != "user-123" {
		t.Errorf("expected subject 'user-123', got %q", parsed.Subject)
	}
	if parsed.Issuer != "test-issuer" {
		t.Errorf("expected issuer 'test-issuer', got %q", parsed.Issuer)
	}
}

func TestJWTValidate_HS256_Expired(t *testing.T) {
	secret := []byte("test-secret")
	claims := JWTClaims{
		ExpiresAt: time.Now().Unix() - 3600, // expired 1 hour ago
	}

	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	v.publicKey = secret

	token := makeValidHS256Token(claims, secret)
	_, err := v.Validate(token)
	if err == nil {
		t.Error("expected error for expired token")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestJWTValidate_HS256_WrongSecret(t *testing.T) {
	secret := []byte("correct-secret")
	wrongSecret := []byte("wrong-secret")
	claims := JWTClaims{
		ExpiresAt: time.Now().Unix() + 3600,
	}

	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	v.publicKey = wrongSecret

	token := makeValidHS256Token(claims, secret)
	_, err := v.Validate(token)
	if err == nil {
		t.Error("expected error for wrong secret")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestJWTValidate_WrongIssuer(t *testing.T) {
	secret := []byte("secret")
	claims := JWTClaims{
		Issuer:    "wrong-issuer",
		ExpiresAt: time.Now().Unix() + 3600,
	}

	v, _ := NewJWTValidator(JWTConfig{Enabled: true, Issuer: "expected-issuer"})
	v.publicKey = secret

	token := makeValidHS256Token(claims, secret)
	_, err := v.Validate(token)
	if err == nil {
		t.Error("expected error for wrong issuer")
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestJWTValidate_WrongAudience(t *testing.T) {
	secret := []byte("secret")
	claims := JWTClaims{
		Audience:  "wrong-audience",
		ExpiresAt: time.Now().Unix() + 3600,
	}

	v, _ := NewJWTValidator(JWTConfig{Enabled: true, Audience: "expected-audience"})
	v.publicKey = secret

	token := makeValidHS256Token(claims, secret)
	_, err := v.Validate(token)
	if err == nil {
		t.Error("expected error for wrong audience")
	}
	if !strings.Contains(err.Error(), "audience") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestJWTValidate_NotYetValid(t *testing.T) {
	secret := []byte("secret")
	claims := JWTClaims{
		NotBefore: time.Now().Unix() + 3600, // valid in 1 hour
		ExpiresAt: time.Now().Unix() + 7200,
	}

	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	v.publicKey = secret

	token := makeValidHS256Token(claims, secret)
	_, err := v.Validate(token)
	if err == nil {
		t.Error("expected error for not-yet-valid token")
	}
}

func TestJWTValidate_DisallowedAlgorithm(t *testing.T) {
	secret := []byte("secret")
	token := makeHS256Token(map[string]string{"alg": "none", "typ": "JWT"}, JWTClaims{}, secret)

	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	v.publicKey = secret

	_, err := v.Validate(token)
	if err == nil {
		t.Error("expected error for disallowed algorithm")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- Audience Tests ---

func TestHasAudience_String(t *testing.T) {
	v := &JWTValidator{}
	if !v.hasAudience("expected", "expected") {
		t.Error("should match string audience")
	}
	if v.hasAudience("wrong", "expected") {
		t.Error("should not match wrong audience")
	}
}

func TestHasAudience_Slice(t *testing.T) {
	v := &JWTValidator{}
	if !v.hasAudience([]any{"a", "expected", "b"}, "expected") {
		t.Error("should find audience in slice")
	}
	if v.hasAudience([]any{"a", "b"}, "expected") {
		t.Error("should not find missing audience")
	}
}

func TestHasAudience_StringSlice(t *testing.T) {
	v := &JWTValidator{}
	if !v.hasAudience([]string{"a", "expected"}, "expected") {
		t.Error("should find audience in string slice")
	}
}

func TestHasAudience_OtherType(t *testing.T) {
	v := &JWTValidator{}
	if v.hasAudience(123, "expected") {
		t.Error("should not match non-string type")
	}
}

// --- Algorithm Tests ---

func TestIsAlgorithmAllowed_Default(t *testing.T) {
	v := &JWTValidator{}
	allowed := []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512"}
	for _, alg := range allowed {
		if !v.isAlgorithmAllowed(alg) {
			t.Errorf("algorithm %s should be allowed by default", alg)
		}
	}
	if v.isAlgorithmAllowed("none") {
		t.Error("'none' should not be allowed")
	}
	if v.isAlgorithmAllowed("HS123") {
		t.Error("unknown algorithm should not be allowed")
	}
}

func TestIsAlgorithmAllowed_Custom(t *testing.T) {
	v := &JWTValidator{config: JWTConfig{Algorithms: []string{"HS256"}}}
	if !v.isAlgorithmAllowed("HS256") {
		t.Error("HS256 should be allowed")
	}
	if v.isAlgorithmAllowed("RS256") {
		t.Error("RS256 should not be allowed when only HS256 is configured")
	}
}

// --- Bearer Token Extraction ---

func TestExtractBearerToken_Valid(t *testing.T) {
	l := &Layer{}
	headers := map[string][]string{
		"Authorization": {"Bearer my-token-123"},
	}
	token := l.extractBearerToken(headers)
	if token != "my-token-123" {
		t.Errorf("expected 'my-token-123', got %q", token)
	}
}

func TestExtractBearerToken_MissingHeader(t *testing.T) {
	l := &Layer{}
	token := l.extractBearerToken(map[string][]string{})
	if token != "" {
		t.Errorf("expected empty, got %q", token)
	}
}

func TestExtractBearerToken_NoBearerPrefix(t *testing.T) {
	l := &Layer{}
	headers := map[string][]string{
		"Authorization": {"Basic dXNlcjpwYXNz"},
	}
	token := l.extractBearerToken(headers)
	// Without Bearer prefix, returns the whole value
	if token != "Basic dXNlcjpwYXNz" {
		t.Errorf("expected raw token, got %q", token)
	}
}

func TestExtractBearerToken_CaseInsensitive(t *testing.T) {
	l := &Layer{}
	headers := map[string][]string{
		"authorization": {"Bearer my-token"},
	}
	token := l.extractBearerToken(headers)
	if token != "my-token" {
		t.Errorf("expected 'my-token' with case-insensitive header, got %q", token)
	}
}

// --- getHeaderValue ---

func TestGetHeaderValue_CaseInsensitive(t *testing.T) {
	headers := map[string][]string{
		"X-Custom-Header": {"value1"},
	}
	if got := getHeaderValue(headers, "x-custom-header"); got != "value1" {
		t.Errorf("expected 'value1', got %q", got)
	}
	if got := getHeaderValue(headers, "X-CUSTOM-HEADER"); got != "value1" {
		t.Errorf("expected 'value1', got %q", got)
	}
}

func TestGetHeaderValue_Missing(t *testing.T) {
	headers := map[string][]string{
		"Other": {"value"},
	}
	if got := getHeaderValue(headers, "X-Missing"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// --- GenerateToken + Validate Roundtrip ---

func TestGenerateToken_HS256(t *testing.T) {
	secret := []byte("roundtrip-secret")
	now := time.Now().Unix()
	claims := JWTClaims{
		Issuer:    "test",
		Subject:   "user-1",
		ExpiresAt: now + 3600,
		IssuedAt:  now,
	}

	token, err := GenerateToken(claims, secret, "HS256")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Verify it's a valid JWT structure
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	// Validate with the same secret
	v, _ := NewJWTValidator(JWTConfig{Enabled: true, Issuer: "test"})
	v.publicKey = secret

	parsed, err := v.Validate(token)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if parsed.Subject != "user-1" {
		t.Errorf("subject mismatch: got %q", parsed.Subject)
	}
}

func TestGenerateToken_UnsupportedAlg(t *testing.T) {
	_, err := GenerateToken(JWTClaims{}, []byte("secret"), "RS256")
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

// --- API Key Validation ---

func TestValidateConstantTime_Valid(t *testing.T) {
	key := "my-secret-key"
	hash := sha256.Sum256([]byte(key))
	hashStr := "sha256:" + fmt.Sprintf("%x", hash[:])

	v, _ := NewAPIKeyValidator([]APIKeyConfig{
		{Name: "test", KeyHash: hashStr, Enabled: true},
	})

	result, err := v.ValidateConstantTime(key, "/api/data")
	if err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
	if result.Name != "test" {
		t.Errorf("expected name 'test', got %q", result.Name)
	}
}

func TestValidateConstantTime_Invalid(t *testing.T) {
	key := "my-secret-key"
	hash := sha256.Sum256([]byte(key))
	hashStr := "sha256:" + fmt.Sprintf("%x", hash[:])

	v, _ := NewAPIKeyValidator([]APIKeyConfig{
		{Name: "test", KeyHash: hashStr, Enabled: true},
	})

	_, err := v.ValidateConstantTime("wrong-key", "/api/data")
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

func TestValidateConstantTime_Empty(t *testing.T) {
	key := "my-secret-key"
	hash := sha256.Sum256([]byte(key))
	hashStr := "sha256:" + fmt.Sprintf("%x", hash[:])

	v, _ := NewAPIKeyValidator([]APIKeyConfig{
		{Name: "test", KeyHash: hashStr, Enabled: true},
	})

	_, err := v.ValidateConstantTime("", "/api/data")
	if err == nil {
		t.Error("expected error for empty key")
	}
}

// --- Layer Process with JWT ---

func TestLayerProcess_JWTAuth(t *testing.T) {
	secret := []byte("test-secret")
	now := time.Now().Unix()
	claims := JWTClaims{
		Issuer:    "test",
		Subject:   "user-1",
		ExpiresAt: now + 3600,
		IssuedAt:  now,
	}

	cfg := Config{
		Enabled: true,
		JWT: JWTConfig{
			Enabled: true,
		},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Inject HMAC key
	layer.jwtValidator.publicKey = secret

	token := makeValidHS256Token(claims, secret)

	req := httptest.NewRequest("GET", "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	ctx := engine.AcquireContext(req, 1, 1024*1024)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Score > 0 {
		t.Errorf("valid JWT should not add score, got %d", result.Score)
	}
}

func TestLayerProcess_NoAuth(t *testing.T) {
	cfg := Config{
		Enabled: true,
		JWT: JWTConfig{
			Enabled: true,
		},
	}
	layer, _ := NewLayer(&cfg)

	req := httptest.NewRequest("GET", "/api/protected", nil)
	ctx := engine.AcquireContext(req, 1, 1024*1024)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	// No auth header → should add score (unauthorized)
	if result.Score == 0 {
		t.Error("expected non-zero score for missing auth")
	}
}

// --- Base64 Helpers ---

func TestDecodeBase64(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		ok       bool
	}{
		{"aGVsbG8", "hello", true},
		{"dGVzdA==", "test", true},
		{"!!!", "", false},
	}
	for _, tt := range tests {
		got, err := decodeBase64(tt.input)
		if tt.ok {
			if err != nil || string(got) != tt.expected {
				t.Errorf("decodeBase64(%q) = %q, %v; want %q, nil", tt.input, got, err, tt.expected)
			}
		} else {
			if err == nil {
				t.Errorf("decodeBase64(%q) expected error", tt.input)
			}
		}
	}
}

func TestDecodeBase64Raw(t *testing.T) {
	got, err := decodeBase64Raw("aGVsbG8")
	if err != nil || string(got) != "hello" {
		t.Errorf("decodeBase64Raw: got %q, %v", got, err)
	}
}

func TestAddPadding(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"YWJj", "YWJj"}, // len%4=0
		{"YWI", "YWI="},  // len%4=3
		{"YW", "YW=="},   // len%4=2
		{"YQ", "YQ=="},   // len%4=2
	}
	for _, tt := range tests {
		got := addPadding(tt.input)
		if got != tt.expected {
			t.Errorf("addPadding(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestStripLeadingZeros(t *testing.T) {
	tests := []struct {
		input    []byte
		expected []byte
	}{
		{[]byte{0, 0, 1, 2}, []byte{1, 2}},
		{[]byte{1, 2, 3}, []byte{1, 2, 3}},
		{[]byte{0, 0, 0}, []byte{0, 0, 0}}, // all zeros returns the slice unchanged
	}
	for _, tt := range tests {
		got := stripLeadingZeros(tt.input)
		if string(got) != string(tt.expected) {
			t.Errorf("stripLeadingZeros(%v) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

// --- ASN1 Parsing ---

func TestAsn1Unmarshal_TooShort(t *testing.T) {
	var esig struct{ R, S *big.Int }
	err := asn1Unmarshal([]byte{0x30}, &esig)
	if err == nil {
		t.Error("expected error for too-short input")
	}
}

func TestAsn1Unmarshal_WrongTag(t *testing.T) {
	var esig struct{ R, S *big.Int }
	err := asn1Unmarshal([]byte{0x02, 0x01, 0x01}, &esig)
	if err == nil {
		t.Error("expected error for wrong tag")
	}
}

// --- File Operations Stubs ---

func TestSetFileOps(t *testing.T) {
	openCalled := false
	SetFileOps(
		func(path string) (any, error) { openCalled = true; return nil, fmt.Errorf("test") },
		func(any) {},
		func(any, []byte) (int, error) { return 0, nil },
	)
	if !openCalled {
		// Just verify it doesn't panic — the function is a setter
	}
	// Reset
	SetFileOps(nil, nil, nil)
}

// --- Clock Skew ---

func TestJWTValidate_ClockSkew(t *testing.T) {
	secret := []byte("secret")
	// Token expired 5 seconds ago
	claims := JWTClaims{
		ExpiresAt: time.Now().Unix() - 5,
	}

	v, _ := NewJWTValidator(JWTConfig{
		Enabled:          true,
		ClockSkewSeconds: 30, // allow 30s skew
	})
	v.publicKey = secret

	token := makeValidHS256Token(claims, secret)
	_, err := v.Validate(token)
	if err != nil {
		t.Errorf("expected token to be valid within clock skew, got: %v", err)
	}
}

// --- API Key via HTTP ---

func TestLayerProcess_APIKeyAuth_Valid(t *testing.T) {
	key := "valid-api-key"
	hash := sha256.Sum256([]byte(key))
	hashStr := "sha256:" + fmt.Sprintf("%x", hash[:])

	cfg := Config{
		Enabled: true,
		APIKeys: APIKeysConfig{
			Enabled: true,
			Keys: []APIKeyConfig{
				{Name: "test-key", KeyHash: hashStr, Enabled: true},
			},
		},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("X-API-Key", "valid-api-key")

	ctx := engine.AcquireContext(req, 1, 1024*1024)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Score > 0 {
		t.Errorf("valid API key should not add score, got %d", result.Score)
	}
}

func TestLayerProcess_APIKeyAuth_Invalid(t *testing.T) {
	key := "valid-api-key"
	hash := sha256.Sum256([]byte(key))
	hashStr := "sha256:" + fmt.Sprintf("%x", hash[:])

	cfg := Config{
		Enabled: true,
		APIKeys: APIKeysConfig{
			Enabled: true,
			Keys: []APIKeyConfig{
				{Name: "test-key", KeyHash: hashStr, Enabled: true},
			},
		},
	}
	layer, _ := NewLayer(&cfg)

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("X-API-Key", "invalid-key")

	ctx := engine.AcquireContext(req, 1, 1024*1024)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Score == 0 {
		t.Error("invalid API key should add score")
	}
}

// --- Layer AddAPIKey / RemoveAPIKey ---

func TestLayer_AddAPIKey(t *testing.T) {
	cfg := Config{
		Enabled: true,
		APIKeys: APIKeysConfig{
			Enabled: true,
			Keys:    []APIKeyConfig{},
		},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	key := "new-runtime-key"
	hash := sha256.Sum256([]byte(key))
	hashStr := "sha256:" + fmt.Sprintf("%x", hash[:])

	err = layer.AddAPIKey(APIKeyConfig{
		Name:      "runtime-key",
		KeyHash:   hashStr,
		KeyPrefix: "new-",
		Enabled:   true,
	})
	if err != nil {
		t.Fatalf("AddAPIKey error: %v", err)
	}

	// Verify the key works
	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("X-API-Key", key)
	ctx := engine.AcquireContext(req, 1, 1024*1024)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Score > 0 {
		t.Errorf("valid runtime key should not add score, got %d", result.Score)
	}
}

func TestLayer_RemoveAPIKey(t *testing.T) {
	key := "removable-key"
	hash := sha256.Sum256([]byte(key))
	hashStr := "sha256:" + fmt.Sprintf("%x", hash[:])

	cfg := Config{
		Enabled: true,
		APIKeys: APIKeysConfig{
			Enabled: true,
			Keys: []APIKeyConfig{
				{Name: "remove-test", KeyHash: hashStr, KeyPrefix: "rem-", Enabled: true},
			},
		},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	removed := layer.RemoveAPIKey("remove-test")
	if !removed {
		t.Error("expected key to be removed")
	}

	// Key should no longer work
	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("X-API-Key", key)
	ctx := engine.AcquireContext(req, 1, 1024*1024)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Score == 0 {
		t.Error("removed key should cause auth failure")
	}
}

func TestLayer_AddAPIKey_NilValidator(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = layer.AddAPIKey(APIKeyConfig{Name: "test"})
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestLayer_RemoveAPIKey_NilValidator(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	removed := layer.RemoveAPIKey("test")
	if removed {
		t.Error("expected false with nil validator")
	}
}

// --- Layer RefreshJWKS ---

func TestLayer_RefreshJWKS_NilValidator(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Should not panic
	layer.RefreshJWKS()
}

// --- Layer Start / Stop ---

func TestLayer_StartStop(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	layer.Start()
	layer.Stop()
}

// --- API Key Rate Limiting ---

func TestAPIKeyValidator_RateLimit(t *testing.T) {
	key := "rate-limited-key"
	hash := sha256.Sum256([]byte(key))
	hashStr := "sha256:" + fmt.Sprintf("%x", hash[:])

	v, err := NewAPIKeyValidator([]APIKeyConfig{
		{
			Name:      "rate-test",
			KeyHash:   hashStr,
			Enabled:   true,
			RateLimit: 3,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Should succeed for first 3 requests
	for i := 0; i < 3; i++ {
		_, err := v.Validate(key, "/api/data")
		if err != nil {
			t.Errorf("request %d should succeed, got: %v", i+1, err)
		}
	}

	// 4th request should be rate limited
	_, err = v.Validate(key, "/api/data")
	if err != ErrRateLimitExceeded {
		t.Errorf("expected rate limit error, got: %v", err)
	}
}

// --- API Key Path Restrictions ---

func TestAPIKeyValidator_PathRestriction(t *testing.T) {
	key := "path-limited-key"
	hash := sha256.Sum256([]byte(key))
	hashStr := "sha256:" + fmt.Sprintf("%x", hash[:])

	v, err := NewAPIKeyValidator([]APIKeyConfig{
		{
			Name:         "path-test",
			KeyHash:      hashStr,
			Enabled:      true,
			AllowedPaths: []string{"/api/v1/*"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Allowed path
	cfg, err := v.Validate(key, "/api/v1/users")
	if err != nil {
		t.Errorf("allowed path should succeed: %v", err)
	}
	if cfg.Name != "path-test" {
		t.Errorf("expected path-test, got %q", cfg.Name)
	}

	// Disallowed path
	_, err = v.Validate(key, "/admin/dashboard")
	if err != ErrUnauthorizedPath {
		t.Errorf("expected unauthorized path error, got: %v", err)
	}
}

// --- API Key Disabled ---
// Note: NewAPIKeyValidator skips disabled keys during init.
// A key added at runtime then disabled via AddKey with Enabled=false
// can still be looked up but returns ErrAPIKeyDisabled.

func TestAPIKeyValidator_DisabledKey_Runtime(t *testing.T) {
	key := "runtime-disabled"
	hash := sha256.Sum256([]byte(key))
	hashStr := "sha256:" + fmt.Sprintf("%x", hash[:])

	v, err := NewAPIKeyValidator([]APIKeyConfig{})
	if err != nil {
		t.Fatal(err)
	}

	// Add enabled key first
	err = v.AddKey(APIKeyConfig{
		Name:    "to-disable",
		KeyHash: hashStr,
		Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify it works
	_, err = v.Validate(key, "/api/data")
	if err != nil {
		t.Fatalf("enabled key should work: %v", err)
	}

	// Now disable it by re-adding with Enabled=false
	err = v.AddKey(APIKeyConfig{
		Name:    "to-disable",
		KeyHash: hashStr,
		Enabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = v.Validate(key, "/api/data")
	if err != ErrAPIKeyDisabled {
		t.Errorf("expected disabled error, got: %v", err)
	}
}

// --- API Key Add/Remove via Validator ---

func TestAPIKeyValidator_AddKey(t *testing.T) {
	v, err := NewAPIKeyValidator([]APIKeyConfig{})
	if err != nil {
		t.Fatal(err)
	}

	key := "dynamic-key"
	hash := sha256.Sum256([]byte(key))
	hashStr := "sha256:" + fmt.Sprintf("%x", hash[:])

	err = v.AddKey(APIKeyConfig{
		Name:    "dynamic",
		KeyHash: hashStr,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("AddKey error: %v", err)
	}

	cfg, err := v.Validate(key, "/api/data")
	if err != nil {
		t.Fatalf("validate after add failed: %v", err)
	}
	if cfg.Name != "dynamic" {
		t.Errorf("expected dynamic, got %q", cfg.Name)
	}
}

func TestAPIKeyValidator_RemoveKey(t *testing.T) {
	key := "to-remove"
	hash := sha256.Sum256([]byte(key))
	hashStr := "sha256:" + fmt.Sprintf("%x", hash[:])

	v, err := NewAPIKeyValidator([]APIKeyConfig{
		{Name: "removable", KeyHash: hashStr, Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	removed := v.RemoveKey("removable")
	if !removed {
		t.Error("expected key to be removed")
	}

	_, err = v.Validate(key, "/api/data")
	if err != ErrInvalidAPIKey {
		t.Errorf("expected invalid after removal, got: %v", err)
	}
}

func TestAPIKeyValidator_RemoveKey_NotFound(t *testing.T) {
	v, _ := NewAPIKeyValidator([]APIKeyConfig{})
	removed := v.RemoveKey("nonexistent")
	if removed {
		t.Error("expected false for nonexistent key")
	}
}

// --- RSA Signature Verification ---

func makeRSAToken(claims JWTClaims, privateKey *rsa.PrivateKey) string {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	h := sha256.Sum256([]byte(signingInput))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h[:])
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64
}

func makeRS384Token(claims JWTClaims, privateKey *rsa.PrivateKey) string {
	header := map[string]string{"alg": "RS384", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	h := sha512.Sum384([]byte(signingInput))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, h[:])
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64
}

func makeRS512Token(claims JWTClaims, privateKey *rsa.PrivateKey) string {
	header := map[string]string{"alg": "RS512", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	h := sha512.Sum512([]byte(signingInput))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, h[:])
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64
}

func TestJWTValidate_RS256_Valid(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	claims := JWTClaims{
		Issuer:    "test-issuer",
		Subject:   "rsa-user",
		ExpiresAt: now + 3600,
		IssuedAt:  now,
	}

	v, _ := NewJWTValidator(JWTConfig{Enabled: true, Issuer: "test-issuer"})
	v.publicKey = &privateKey.PublicKey

	token := makeRSAToken(claims, privateKey)
	parsed, err := v.Validate(token)
	if err != nil {
		t.Fatalf("expected valid RS256 token, got: %v", err)
	}
	if parsed.Subject != "rsa-user" {
		t.Errorf("expected subject 'rsa-user', got %q", parsed.Subject)
	}
}

func TestJWTValidate_RS256_WrongKey(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	claims := JWTClaims{ExpiresAt: time.Now().Unix() + 3600}
	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	v.publicKey = &wrongKey.PublicKey

	token := makeRSAToken(claims, privateKey)
	_, err := v.Validate(token)
	if err == nil {
		t.Error("expected error for wrong RSA key")
	}
}

func TestJWTValidate_RS384_Valid(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := JWTClaims{ExpiresAt: time.Now().Unix() + 3600}

	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	v.publicKey = &privateKey.PublicKey

	token := makeRS384Token(claims, privateKey)
	_, err := v.Validate(token)
	if err != nil {
		t.Fatalf("expected valid RS384 token, got: %v", err)
	}
}

func TestJWTValidate_RS512_Valid(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := JWTClaims{ExpiresAt: time.Now().Unix() + 3600}

	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	v.publicKey = &privateKey.PublicKey

	token := makeRS512Token(claims, privateKey)
	_, err := v.Validate(token)
	if err != nil {
		t.Fatalf("expected valid RS512 token, got: %v", err)
	}
}

func TestVerifyRSASignature_NotRSAKey(t *testing.T) {
	err := verifyRSASignature([]byte("not-rsa"), crypto.SHA256, "data", []byte("sig"))
	if err == nil {
		t.Error("expected error for non-RSA key")
	}
	if !strings.Contains(err.Error(), "not an RSA") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- ECDSA Signature Verification ---

func makeECDSAToken(claims JWTClaims, privateKey *ecdsa.PrivateKey) string {
	header := map[string]string{"alg": "ES256", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	h := sha256.Sum256([]byte(signingInput))
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, h[:])
	// DER encode
	sig := encodeECDSASignature(r, s)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64
}

func makeECDSATokenRaw(claims JWTClaims, privateKey *ecdsa.PrivateKey) string {
	header := map[string]string{"alg": "ES256", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	h := sha256.Sum256([]byte(signingInput))
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, h[:])
	// Raw format: r || s (each 32 bytes for P-256)
	rb := r.Bytes()
	sb := s.Bytes()
	raw := make([]byte, 64)
	copy(raw[32-len(rb):32], rb)
	copy(raw[64-len(sb):], sb)
	sigB64 := base64.RawURLEncoding.EncodeToString(raw)
	return signingInput + "." + sigB64
}

func encodeECDSASignature(r, s *big.Int) []byte {
	rb := r.Bytes()
	sb := s.Bytes()
	// Prepend 0x00 if high bit set
	if rb[0]&0x80 != 0 {
		rb = append([]byte{0x00}, rb...)
	}
	if sb[0]&0x80 != 0 {
		sb = append([]byte{0x00}, sb...)
	}
	// DER encode each INTEGER
	ri := append([]byte{0x02, byte(len(rb))}, rb...)
	si := append([]byte{0x02, byte(len(sb))}, sb...)
	seq := append(ri, si...)
	// Encode SEQUENCE with proper length
	result := []byte{0x30}
	if len(seq) >= 128 {
		// Multi-byte length: 0x81 + length byte
		result = append(result, 0x81, byte(len(seq)))
	} else {
		result = append(result, byte(len(seq)))
	}
	return append(result, seq...)
}

func TestJWTValidate_ES256_Valid(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := JWTClaims{Subject: "ec-user", ExpiresAt: time.Now().Unix() + 3600}
	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	v.publicKey = &privateKey.PublicKey

	token := makeECDSAToken(claims, privateKey)
	parsed, err := v.Validate(token)
	if err != nil {
		t.Fatalf("expected valid ES256 token, got: %v", err)
	}
	if parsed.Subject != "ec-user" {
		t.Errorf("expected subject 'ec-user', got %q", parsed.Subject)
	}
}

func TestJWTValidate_ES256_RawFormat(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	claims := JWTClaims{ExpiresAt: time.Now().Unix() + 3600}

	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	v.publicKey = &privateKey.PublicKey

	token := makeECDSATokenRaw(claims, privateKey)
	_, err := v.Validate(token)
	if err != nil {
		t.Fatalf("expected valid ES256 token with raw signature, got: %v", err)
	}
}

func TestJWTValidate_ES256_WrongKey(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := JWTClaims{ExpiresAt: time.Now().Unix() + 3600}
	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	v.publicKey = &wrongKey.PublicKey

	token := makeECDSAToken(claims, privateKey)
	_, err := v.Validate(token)
	if err == nil {
		t.Error("expected error for wrong ECDSA key")
	}
}

func TestVerifyECDSASignature_NotECDSAKey(t *testing.T) {
	err := verifyECDSASignature([]byte("not-ecdsa"), crypto.SHA256, "data", make([]byte, 64))
	if err == nil {
		t.Error("expected error for non-ECDSA key")
	}
	if !strings.Contains(err.Error(), "not an ECDSA") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyECDSASignature_InvalidFormat(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// 48 bytes is neither DER nor raw (64 bytes)
	err := verifyECDSASignature(&privateKey.PublicKey, crypto.SHA256, "data", make([]byte, 48))
	if err == nil {
		t.Error("expected error for invalid signature format")
	}
}

// --- HMAC HS384/HS512 ---

func makeHS384Token(claims JWTClaims, secret []byte) string {
	return makeSignedToken(map[string]string{"alg": "HS384", "typ": "JWT"}, claims, secret, sha512.New384)
}

func makeHS512Token(claims JWTClaims, secret []byte) string {
	return makeSignedToken(map[string]string{"alg": "HS512", "typ": "JWT"}, claims, secret, sha512.New)
}

func makeSignedToken(header map[string]string, claims JWTClaims, secret []byte, hashFunc func() hash.Hash) string {
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64
	h := hmac.New(hashFunc, secret)
	h.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return signingInput + "." + sig
}

func TestJWTValidate_HS384_Valid(t *testing.T) {
	secret := []byte("hs384-secret")
	claims := JWTClaims{Subject: "hs384-user", ExpiresAt: time.Now().Unix() + 3600}

	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	v.publicKey = secret

	token := makeHS384Token(claims, secret)
	parsed, err := v.Validate(token)
	if err != nil {
		t.Fatalf("expected valid HS384 token, got: %v", err)
	}
	if parsed.Subject != "hs384-user" {
		t.Errorf("expected subject 'hs384-user', got %q", parsed.Subject)
	}
}

func TestJWTValidate_HS512_Valid(t *testing.T) {
	secret := []byte("hs512-secret")
	claims := JWTClaims{Subject: "hs512-user", ExpiresAt: time.Now().Unix() + 3600}

	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	v.publicKey = secret

	token := makeHS512Token(claims, secret)
	parsed, err := v.Validate(token)
	if err != nil {
		t.Fatalf("expected valid HS512 token, got: %v", err)
	}
	if parsed.Subject != "hs512-user" {
		t.Errorf("expected subject 'hs512-user', got %q", parsed.Subject)
	}
}

func TestVerifyHMACSignature_NotBytes(t *testing.T) {
	err := verifyHMACSignature(42, sha256.New, "data", []byte("sig"))
	if err == nil {
		t.Error("expected error for non-byte key")
	}
	if !strings.Contains(err.Error(), "not an HMAC") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- verifySignature unsupported algorithm ---

func TestVerifySignature_UnsupportedAlgorithm(t *testing.T) {
	v := &JWTValidator{}
	err := v.verifySignature("UNKNOWN", "data", []byte("sig"), []byte("key"))
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

// --- JWKS Fetching ---

func TestFetchJWKS_RSAKey(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kid": "key-1",
					"kty": "RSA",
					"use": "sig",
					"n":   n,
					"e":   e,
				},
			},
		}
		json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	v, _ := NewJWTValidator(JWTConfig{
		Enabled: true,
		JWKSURL: srv.URL,
	})
	// Manually trigger fetch (constructor starts it in goroutine)
	v.fetchJWKS()

	// Verify key was cached
	k, ok := v.jwksCache.Load("key-1")
	if !ok {
		t.Fatal("expected JWKS key to be cached")
	}
	rsaKey, ok := k.(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected RSA public key")
	}
	if rsaKey.N.Cmp(privateKey.N) != 0 {
		t.Error("N mismatch")
	}
}

func TestFetchJWKS_ECKey(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	x := base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kid": "ec-key-1",
					"kty": "EC",
					"use": "sig",
					"crv": "P-256",
					"x":   x,
					"y":   y,
				},
			},
		}
		json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	v, _ := NewJWTValidator(JWTConfig{Enabled: true, JWKSURL: srv.URL})
	v.fetchJWKS()

	k, ok := v.jwksCache.Load("ec-key-1")
	if !ok {
		t.Fatal("expected EC JWKS key to be cached")
	}
	ecKey, ok := k.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("expected ECDSA public key")
	}
	if ecKey.X.Cmp(privateKey.X) != 0 {
		t.Error("X mismatch")
	}
}

func TestFetchJWKS_EmptyURL(t *testing.T) {
	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	// Should return without error
	v.fetchJWKS()
}

func TestFetchJWKS_BadResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	v, _ := NewJWTValidator(JWTConfig{Enabled: true, JWKSURL: srv.URL})
	// Should not panic
	v.fetchJWKS()
}

func TestFetchJWKS_NoKid(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"n":   n,
					"e":   e,
					// no kid
				},
			},
		}
		json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	v, _ := NewJWTValidator(JWTConfig{Enabled: true, JWKSURL: srv.URL})
	v.fetchJWKS()

	// Key without kid should not be cached
	v.jwksCache.Range(func(k, v any) bool {
		t.Error("expected no keys cached without kid")
		return false
	})
}

func TestValidate_WithJWKSKidLookup(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	// Pre-populate JWKS cache with the key
	v.jwksCache.Store("my-key-id", &privateKey.PublicKey)

	claims := JWTClaims{ExpiresAt: time.Now().Unix() + 3600}
	// Create token with kid in header
	headerJSON, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "my-key-id"})
	payloadJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64
	h := sha256.Sum256([]byte(signingInput))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h[:])
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	parsed, err := v.Validate(token)
	if err != nil {
		t.Fatalf("expected valid token with JWKS kid, got: %v", err)
	}
	if parsed.ExpiresAt == 0 {
		t.Error("expected claims to be parsed")
	}
}

func TestValidate_NoVerificationKey(t *testing.T) {
	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	// No publicKey set, no kid in header

	token := makeValidHS256Token(JWTClaims{ExpiresAt: time.Now().Unix() + 3600}, []byte("secret"))
	_, err := v.Validate(token)
	if err == nil {
		t.Error("expected error for no verification key")
	}
	if !strings.Contains(err.Error(), "no verification key") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- parsePublicKey ---

func TestParsePublicKey_NoPEM(t *testing.T) {
	_, err := parsePublicKey([]byte("not PEM data"))
	if err == nil {
		t.Error("expected error for non-PEM data")
	}
}

func TestParsePublicKey_InvalidPEM(t *testing.T) {
	_, err := parsePublicKey([]byte("-----BEGIN but no end"))
	if err == nil {
		t.Error("expected error for incomplete PEM")
	}
}

func TestParsePublicKey_InvalidBase64(t *testing.T) {
	_, err := parsePublicKey([]byte("-----BEGIN PUBLIC KEY-----\n!!!invalid!!!\n-----END PUBLIC KEY-----"))
	if err == nil {
		t.Error("expected error for invalid base64 in PEM")
	}
}

func TestParsePublicKey_InvalidDER(t *testing.T) {
	// Valid base64 but invalid DER content
	b64 := base64.StdEncoding.EncodeToString([]byte("this is not a real key"))
	_, err := parsePublicKey([]byte("-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----"))
	if err == nil {
		t.Error("expected error for invalid DER")
	}
}

// --- loadPublicKeyFromFile ---

func TestLoadPublicKeyFromFile(t *testing.T) {
	called := false
	SetFileOps(
		func(path string) (any, error) { called = true; return "fake-file", nil },
		func(any) {},
		func(any, []byte) (int, error) { return 0, fmt.Errorf("read error") },
	)
	defer SetFileOps(nil, nil, nil)

	_, err := loadPublicKeyFromFile("test.pem")
	if err == nil {
		t.Error("expected error from read failure")
	}
	if !called {
		t.Error("expected openFile to be called")
	}
}

// --- NewJWTValidator with PublicKeyPEM ---

func TestNewJWTValidator_WithPublicKeyPEM(t *testing.T) {
	// Invalid PEM should fail
	_, err := NewJWTValidator(JWTConfig{
		Enabled:      true,
		PublicKeyPEM: "not-valid-pem",
	})
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestNewJWTValidator_WithPublicKeyFile(t *testing.T) {
	SetFileOps(
		func(path string) (any, error) { return "file", nil },
		func(any) {},
		func(any, []byte) (int, error) { return 0, fmt.Errorf("read error") },
	)
	defer SetFileOps(nil, nil, nil)

	_, err := NewJWTValidator(JWTConfig{
		Enabled:       true,
		PublicKeyFile: "test.pem",
	})
	if err == nil {
		t.Error("expected error for unreadable key file")
	}
}

// --- parseLength / parseLengthFrom ---

func TestParseLength_SingleByte(t *testing.T) {
	p := &asn1Parser{data: []byte{0x05, 'a', 'b', 'c', 'd', 'e'}}
	l, err := p.parseLength()
	if err != nil || l != 5 {
		t.Errorf("expected length 5, got %d, err %v", l, err)
	}
}

func TestParseLength_MultiByte(t *testing.T) {
	// 0x81 means 1 byte follows for the length value
	p := &asn1Parser{data: []byte{0x81, 0x10}} // length = 16
	l, err := p.parseLength()
	if err != nil || l != 16 {
		t.Errorf("expected length 16, got %d, err %v", l, err)
	}
}

func TestParseLength_EmptyData(t *testing.T) {
	p := &asn1Parser{data: []byte{}}
	_, err := p.parseLength()
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestParseLength_Overflow(t *testing.T) {
	// 0x82 means 2 bytes follow, but data is too short
	p := &asn1Parser{data: []byte{0x82, 0x01}}
	_, err := p.parseLength()
	if err == nil {
		t.Error("expected error for length overflow")
	}
}

func TestParseLengthFrom_SingleByte(t *testing.T) {
	data := []byte{0x03, 'a', 'b', 'c'}
	l, err := parseLengthFrom(&data)
	if err != nil || l != 3 {
		t.Errorf("expected length 3, got %d, err %v", l, err)
	}
}

func TestParseLengthFrom_MultiByte(t *testing.T) {
	data := []byte{0x82, 0x00, 0x20} // length = 32
	l, err := parseLengthFrom(&data)
	if err != nil || l != 32 {
		t.Errorf("expected length 32, got %d, err %v", l, err)
	}
}

func TestParseLengthFrom_Empty(t *testing.T) {
	data := []byte{}
	_, err := parseLengthFrom(&data)
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestParseLengthFrom_Overflow(t *testing.T) {
	data := []byte{0x83, 0x01} // 3 bytes needed, only 1 available
	_, err := parseLengthFrom(&data)
	if err == nil {
		t.Error("expected error for overflow")
	}
}

// --- parseValue deeper coverage ---

func TestParseValue_NoLengthByte(t *testing.T) {
	p := &asn1Parser{data: []byte{0x30}} // SEQUENCE tag but no length
	var esig struct{ R, S *big.Int }
	err := p.parseValue(&esig)
	if err == nil {
		t.Error("expected error for missing length")
	}
}

func TestParseValue_WrongTag(t *testing.T) {
	p := &asn1Parser{data: []byte{0x02, 0x01, 0x01}} // INTEGER, not SEQUENCE
	var esig struct{ R, S *big.Int }
	err := p.parseValue(&esig)
	if err == nil {
		t.Error("expected error for wrong tag")
	}
}

// --- extractAPIKey ---

func TestExtractAPIKey_CustomHeader(t *testing.T) {
	l := &Layer{config: Config{APIKeys: APIKeysConfig{HeaderName: "X-Custom-Key"}}}
	headers := map[string][]string{"X-Custom-Key": {"my-custom-key"}}
	key := l.extractAPIKey(headers, nil)
	if key != "my-custom-key" {
		t.Errorf("expected 'my-custom-key', got %q", key)
	}
}

func TestExtractAPIKey_QueryParam(t *testing.T) {
	l := &Layer{config: Config{}}
	headers := map[string][]string{}
	queryParams := map[string][]string{"api_key": {"query-key"}}
	key := l.extractAPIKey(headers, queryParams)
	if key != "query-key" {
		t.Errorf("expected 'query-key', got %q", key)
	}
}

func TestExtractAPIKey_CustomQueryParam(t *testing.T) {
	l := &Layer{config: Config{APIKeys: APIKeysConfig{QueryParam: "token"}}}
	queryParams := map[string][]string{"token": {"my-token"}}
	key := l.extractAPIKey(map[string][]string{}, queryParams)
	if key != "my-token" {
		t.Errorf("expected 'my-token', got %q", key)
	}
}

func TestExtractAPIKey_Empty(t *testing.T) {
	l := &Layer{config: Config{}}
	key := l.extractAPIKey(map[string][]string{}, nil)
	if key != "" {
		t.Errorf("expected empty, got %q", key)
	}
}

// --- Skip Path Tests ---

func TestLayerProcess_SkipPath(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		SkipPaths: []string{"/health"},
		JWT:       JWTConfig{Enabled: true},
	}
	layer, _ := NewLayer(&cfg)
	secret := []byte("secret")
	layer.jwtValidator.publicKey = secret

	req := httptest.NewRequest("GET", "/health", nil)
	ctx := engine.AcquireContext(req, 1, 1024*1024)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for skipped path, got %v", result.Action)
	}
}

func TestLayer_AddRemoveSkipPath(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, _ := NewLayer(&cfg)

	layer.AddSkipPath("/metrics")
	if !layer.shouldSkipPath("/metrics") {
		t.Error("expected /metrics to be skipped")
	}

	layer.RemoveSkipPath("/metrics")
	if layer.shouldSkipPath("/metrics") {
		t.Error("expected /metrics to not be skipped after removal")
	}
}

func TestLayerProcess_WildcardSkipPath(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		SkipPaths: []string{"/static/*"},
		JWT:       JWTConfig{Enabled: true},
	}
	layer, _ := NewLayer(&cfg)
	secret := []byte("secret")
	layer.jwtValidator.publicKey = secret

	req := httptest.NewRequest("GET", "/static/css/main.css", nil)
	ctx := engine.AcquireContext(req, 1, 1024*1024)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for wildcard skipped path, got %v", result.Action)
	}
}

// --- Stats ---

func TestLayer_Stats(t *testing.T) {
	key := "stats-key"
	hash := sha256.Sum256([]byte(key))
	hashStr := "sha256:" + fmt.Sprintf("%x", hash[:])

	cfg := Config{
		Enabled: true,
		APIKeys: APIKeysConfig{
			Enabled: true,
			Keys:    []APIKeyConfig{{Name: "test", KeyHash: hashStr, Enabled: true}},
		},
	}
	layer, _ := NewLayer(&cfg)

	stats := layer.Stats()
	if stats["enabled"] != true {
		t.Error("expected enabled=true")
	}
	if stats["api_key_count"] != 1 {
		t.Errorf("expected api_key_count=1, got %v", stats["api_key_count"])
	}
}

// --- Layer Process with API key via query param ---

func TestLayerProcess_APIKeyViaQueryParam(t *testing.T) {
	key := "query-api-key"
	hash := sha256.Sum256([]byte(key))
	hashStr := "sha256:" + fmt.Sprintf("%x", hash[:])

	cfg := Config{
		Enabled: true,
		APIKeys: APIKeysConfig{
			Enabled: true,
			Keys: []APIKeyConfig{
				{Name: "query-test", KeyHash: hashStr, Enabled: true},
			},
		},
	}
	layer, _ := NewLayer(&cfg)

	req := httptest.NewRequest("GET", "/api/data?api_key=query-api-key", nil)
	ctx := engine.AcquireContext(req, 1, 1024*1024)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Score > 0 {
		t.Errorf("valid API key via query param should not add score, got %d", result.Score)
	}
}

// --- JWKS fetch with non-200 response ---

func TestFetchJWKS_EC_P384_P521(t *testing.T) {
	for _, tc := range []struct {
		name   string
		curve  elliptic.Curve
		crvID  string
	}{
		{"P-384", elliptic.P384(), "P-384"},
		{"P-521", elliptic.P521(), "P-521"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, _ := ecdsa.GenerateKey(tc.curve, rand.Reader)
			x := base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes())
			y := base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes())

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				jwks := map[string]any{
					"keys": []map[string]any{{
						"kid": tc.name, "kty": "EC", "use": "sig",
						"crv": tc.crvID, "x": x, "y": y,
					}},
				}
				json.NewEncoder(w).Encode(jwks)
			}))
			defer srv.Close()

			v, _ := NewJWTValidator(JWTConfig{Enabled: true, JWKSURL: srv.URL})
			v.fetchJWKS()

			k, ok := v.jwksCache.Load(tc.name)
			if !ok {
				t.Fatal("expected key to be cached")
			}
			ecKey := k.(*ecdsa.PublicKey)
			if ecKey.X.Cmp(privateKey.X) != 0 {
				t.Error("X mismatch")
			}
		})
	}
}

// --- ECDSA ES384 / ES512 tokens via verifySignature ---

func TestJWTValidate_ES384_Valid(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	claims := JWTClaims{ExpiresAt: time.Now().Unix() + 3600}

	headerJSON, _ := json.Marshal(map[string]string{"alg": "ES384", "typ": "JWT"})
	payloadJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	h := sha512.Sum384([]byte(signingInput))
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, h[:])
	sig := encodeECDSASignature(r, s)
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	v.publicKey = &privateKey.PublicKey
	_, err := v.Validate(token)
	if err != nil {
		t.Fatalf("expected valid ES384 token, got: %v", err)
	}
}

func TestJWTValidate_ES512_Valid(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	claims := JWTClaims{ExpiresAt: time.Now().Unix() + 3600}

	headerJSON, _ := json.Marshal(map[string]string{"alg": "ES512", "typ": "JWT"})
	payloadJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	h := sha512.Sum512([]byte(signingInput))
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, h[:])
	sig := encodeECDSASignature(r, s)
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	v, _ := NewJWTValidator(JWTConfig{Enabled: true})
	v.publicKey = &privateKey.PublicKey
	_, err := v.Validate(token)
	if err != nil {
		t.Fatalf("expected valid ES512 token, got: %v", err)
	}
}

// --- JWKS unknown curve ---

func TestFetchJWKS_UnknownCurve(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	x := base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]any{
			"keys": []map[string]any{{
				"kid": "unknown-curve", "kty": "EC", "use": "sig",
				"crv": "Ed25519", "x": x, "y": y, // unsupported curve
			}},
		}
		json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	v, _ := NewJWTValidator(JWTConfig{Enabled: true, JWKSURL: srv.URL})
	v.fetchJWKS()

	_, ok := v.jwksCache.Load("unknown-curve")
	if ok {
		t.Error("expected key with unknown curve to not be cached")
	}
}
