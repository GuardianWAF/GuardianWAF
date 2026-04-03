package apisecurity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
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
