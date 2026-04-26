package apisecurity

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Suppress unused import warnings
var (
	_ = sha256.Sum256
	_ = base64.RawURLEncoding
	_ = (*rsa.PublicKey)(nil)
	_ = (*big.Int)(nil)
	_ = http.StatusOK
	_ = strings.HasPrefix
	_ = sync.Map{}
	_ = (*config.WAFConfig)(nil)
	_ = engine.ActionPass
	_ = (*JWTValidator)(nil)
	_ = crypto.SHA256
)

// --- RSA-PSS signature verification ---

func TestCoverage_VerifyRSAPSSSignature(t *testing.T) {
	// Use manually constructed RSA public key for PSS test
	// RSA-PSS with an empty/zero key and bad signature should fail verification
	key := &rsa.PublicKey{
		N: big.NewInt(12345),
		E: 65537,
	}
	err := verifyRSAPSSSignature(key, crypto.SHA256, "test.data", []byte("bad-signature"))
	if err == nil {
		t.Error("verifyRSAPSSSignature with bad signature should fail")
	}
}

func TestCoverage_VerifyRSAPSSSignature_WrongKeyType(t *testing.T) {
	// Pass an empty RSA key with invalid data
	wrongKey := &rsa.PublicKey{}
	data := "test.data"
	sig := []byte("invalid-signature")

	err := verifyRSAPSSSignature(wrongKey, crypto.SHA256, data, sig)
	if err == nil {
		t.Error("verifyRSAPSSSignature with invalid data should fail")
	}
}

func TestCoverage_VerifyRSAPSSSignature_RS256ViaVerifySignature(t *testing.T) {
	// Test that PS256 algorithm routes to verifyRSAPSSSignature
	v := &JWTValidator{}
	err := v.verifySignature("PS256", "test", []byte("sig"), nil)
	if err == nil {
		t.Error("PS256 with nil key should fail")
	}
}

// --- ASN.1 OID helpers ---

func TestCoverage_IsRSAOID(t *testing.T) {
	// Valid RSA OID: 06 09 2A 86 48 86 F7 0D 01 01 01
	rsaOID := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}
	if !isRSAOID(rsaOID) {
		t.Error("isRSAOID should match RSA OID")
	}

	// Too short
	if isRSAOID([]byte{0x06, 0x09}) {
		t.Error("isRSAOID should reject short data")
	}

	// Wrong OID
	wrongOID := []byte{0x06, 0x09, 0x2B, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}
	if isRSAOID(wrongOID) {
		t.Error("isRSAOID should reject wrong OID")
	}
}

func TestCoverage_IsP256OID(t *testing.T) {
	// P-256 OID: 1.2.840.10045.3.1.7
	p256OID := []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
	if !isP256OID(p256OID) {
		t.Error("isP256OID should match P-256 OID")
	}
	// Too short
	if isP256OID([]byte{0x06}) {
		t.Error("isP256OID should reject short data")
	}
	// Wrong OID
	wrongOID := []byte{0x06, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	if isP256OID(wrongOID) {
		t.Error("isP256OID should reject wrong OID")
	}
}

func TestCoverage_IsP384OID(t *testing.T) {
	// P-384 OID: 1.3.132.0.34
	p384OID := []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22}
	if !isP384OID(p384OID) {
		t.Error("isP384OID should match P-384 OID")
	}
	// Too short
	if isP384OID([]byte{0x06}) {
		t.Error("isP384OID should reject short data")
	}
	// Wrong OID
	if isP384OID([]byte{0x06, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Error("isP384OID should reject wrong OID")
	}
}

func TestCoverage_IsP521OID(t *testing.T) {
	// P-521 OID: 1.3.132.0.35
	p521OID := []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23}
	if !isP521OID(p521OID) {
		t.Error("isP521OID should match P-521 OID")
	}
	// Too short
	if isP521OID([]byte{0x06}) {
		t.Error("isP521OID should reject short data")
	}
	// Wrong OID
	if isP521OID([]byte{0x06, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Error("isP521OID should reject wrong OID")
	}
}

// --- ASN.1 BitString and OID parsing ---

func TestCoverage_ParseASN1BitString(t *testing.T) {
	// Valid BIT STRING: tag=0x03, length=3, unused_bits=0, data=0xAB 0xCD
	valid := []byte{0x03, 0x03, 0x00, 0xAB, 0xCD}
	data, err := parseASN1BitString(valid)
	if err != nil {
		t.Errorf("parseASN1BitString(valid) error = %v", err)
	}
	if len(data) != 2 || data[0] != 0xAB || data[1] != 0xCD {
		t.Errorf("parseASN1BitString data = %x, want abcd", data)
	}

	// Too short
	_, err = parseASN1BitString([]byte{0x03, 0x01})
	if err == nil {
		t.Error("parseASN1BitString(short) should fail")
	}

	// Wrong tag
	_, err = parseASN1BitString([]byte{0x04, 0x03, 0x00, 0xAB, 0xCD})
	if err == nil {
		t.Error("parseASN1BitString(wrong tag) should fail")
	}

	// Invalid length (length exceeds data)
	_, err = parseASN1BitString([]byte{0x03, 0x05, 0x00, 0xAB})
	if err == nil {
		t.Error("parseASN1BitString(oversize) should fail")
	}

	// Zero length bit string
	_, err = parseASN1BitString([]byte{0x03, 0x00})
	if err == nil {
		t.Error("parseASN1BitString(zero length) should fail")
	}
}

func TestCoverage_ParseASN1OID(t *testing.T) {
	// Valid OID
	valid := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}
	data, err := parseASN1OID(valid)
	if err != nil {
		t.Errorf("parseASN1OID(valid) error = %v", err)
	}
	if len(data) != len(valid) {
		t.Errorf("parseASN1OID data len = %d, want %d", len(data), len(valid))
	}

	// Too short
	_, err = parseASN1OID([]byte{0x06})
	if err == nil {
		t.Error("parseASN1OID(short) should fail")
	}

	// Wrong tag
	_, err = parseASN1OID([]byte{0x05, 0x01, 0x01})
	if err == nil {
		t.Error("parseASN1OID(wrong tag) should fail")
	}

	// Length exceeds data
	_, err = parseASN1OID([]byte{0x06, 0x10, 0x01})
	if err == nil {
		t.Error("parseASN1OID(oversize) should fail")
	}
}

// --- parseASN1Integer negative number handling ---

func TestCoverage_ParseASN1Integer_Negative(t *testing.T) {
	// Negative integer: high bit set
	neg := []byte{0x02, 0x01, 0xFF} // -1
	_, err := parseASN1Integer(neg)
	if err == nil {
		t.Error("parseASN1Integer(negative) should fail")
	}
}

// --- PKIX RSA public key parsing ---

func TestCoverage_ParsePKIXRSAPublicKey(t *testing.T) {
	// Build a valid PKIX SubjectPublicKeyInfo for RSA
	// This tests the parsePKIXRSAPublicKey path

	// Start with raw RSA key components
	modulus := big.NewInt(123456789)
	exponent := big.NewInt(65537)

	// Build inner RSAPublicKey SEQUENCE
	rsaIntN := append([]byte{0x02}, encodeASN1Length(len(modulus.Bytes()))...)
	rsaIntN = append(rsaIntN, modulus.Bytes()...)
	rsaIntE := append([]byte{0x02}, encodeASN1Length(len(exponent.Bytes()))...)
	rsaIntE = append(rsaIntE, exponent.Bytes()...)
	rsaSeqContent := append(rsaIntN, rsaIntE...)
	rsaSeq := append([]byte{0x30}, encodeASN1Length(len(rsaSeqContent))...)
	rsaSeq = append(rsaSeq, rsaSeqContent...)

	// Wrap in BIT STRING
	bitStringContent := append([]byte{0x00}, rsaSeq...) // 0 unused bits
	bitString := append([]byte{0x03}, encodeASN1Length(len(bitStringContent))...)
	bitString = append(bitString, bitStringContent...)

	// Algorithm identifier: RSA OID + NULL
	rsaOID := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}
	nullParam := []byte{0x05, 0x00}
	algoContent := append(rsaOID, nullParam...)
	algoSeq := append([]byte{0x30}, encodeASN1Length(len(algoContent))...)
	algoSeq = append(algoSeq, algoContent...)

	// Outer SEQUENCE
	spkiContent := append(algoSeq, bitString...)
	spki := append([]byte{0x30}, encodeASN1Length(len(spkiContent))...)
	spki = append(spki, spkiContent...)

	key := parsePKIXRSAPublicKey(spki)
	if key == nil {
		t.Fatal("parsePKIXRSAPublicKey returned nil for valid PKIX RSA key")
	}
	if key.N.Cmp(modulus) != 0 {
		t.Errorf("modulus mismatch: got %v, want %v", key.N, modulus)
	}
	if key.E != 65537 {
		t.Errorf("exponent mismatch: got %d, want 65537", key.E)
	}
}

func TestCoverage_ParsePKIXRSAPublicKey_InvalidInputs(t *testing.T) {
	// Too short
	if parsePKIXRSAPublicKey([]byte{0x30, 0x01}) != nil {
		t.Error("should reject short data")
	}

	// Not RSA OID
	ecOID := []byte{0x06, 0x07, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE}
	algoContent := append(ecOID, []byte{0x05, 0x00}...)
	algoSeq := append([]byte{0x30}, encodeASN1Length(len(algoContent))...)
	algoSeq = append(algoSeq, algoContent...)
	bitString := []byte{0x03, 0x02, 0x00, 0x00}
	spkiContent := append(algoSeq, bitString...)
	spki := append([]byte{0x30}, encodeASN1Length(len(spkiContent))...)
	spki = append(spki, spkiContent...)

	if parsePKIXRSAPublicKey(spki) != nil {
		t.Error("should reject non-RSA OID")
	}
}

// --- parseECDSAPublicKey ---

func TestCoverage_ParseECDSAPublicKey(t *testing.T) {
	// Test with invalid DER (not a valid EC key)
	if parseECDSAPublicKey([]byte{0x30, 0x01}) != nil {
		t.Error("should reject short data")
	}

	// Test with data that has valid SEQUENCE but wrong algorithm
	// Build a SPKI with non-EC curve OID
	algoOID := []byte{0x06, 0x01, 0xFF}
	algoSeqContent := append(algoOID, algoOID...)
	algoSeq := append([]byte{0x30}, encodeASN1Length(len(algoSeqContent))...)
	algoSeq = append(algoSeq, algoSeqContent...)
	bitString := []byte{0x03, 0x02, 0x00, 0x00}
	spkiContent := append(algoSeq, bitString...)
	spki := append([]byte{0x30}, encodeASN1Length(len(spkiContent))...)
	spki = append(spki, spkiContent...)

	if parseECDSAPublicKey(spki) != nil {
		t.Error("should reject unknown curve OID")
	}
}

// --- parseRSAPublicKey edge cases ---

func TestCoverage_ParseRSAPublicKey_InvalidRaw(t *testing.T) {
	// Test with DER that's not a valid RSA key
	if parseRSAPublicKey([]byte{0x30, 0x02, 0x02, 0x00}) != nil {
		t.Error("should reject invalid RSA key DER")
	}
}

// --- parseRawRSAPublicKey edge cases ---

func TestCoverage_ParseRawRSAPublicExponent(t *testing.T) {
	// Test with SEQUENCE containing zero modulus
	content := []byte{
		0x02, 0x01, 0x00, // modulus = 0 (zero)
		0x02, 0x01, 0x01, // exponent = 1
	}
	seq := append([]byte{0x30}, encodeASN1Length(len(content))...)
	seq = append(seq, content...)
	if parseRawRSAPublicKey(seq) != nil {
		t.Error("should reject zero modulus")
	}

	// Test with negative exponent
	content = []byte{
		0x02, 0x01, 0x01,  // modulus = 1
		0x02, 0x01, 0xFF,  // exponent negative
	}
	seq = append([]byte{0x30}, encodeASN1Length(len(content))...)
	seq = append(seq, content...)
	if parseRawRSAPublicKey(seq) != nil {
		t.Error("should reject negative exponent")
	}
}

// --- JWTValidator.Stop() ---

func TestCoverage_JWTValidator_Stop(t *testing.T) {
	cfg := JWTConfig{
		Enabled:          true,
		Algorithms:       []string{"HS256"},
		ClockSkewSeconds: 300,
	}
	v, err := NewJWTValidator(cfg)
	if err != nil {
		t.Fatalf("NewJWTValidator failed: %v", err)
	}

	// Call Stop twice to test idempotency
	v.Stop()
	v.Stop() // should not panic
}

// --- JWTValidator.refreshJWKSPeriodically ---

func TestCoverage_RefreshJWKSPeriodically(t *testing.T) {
	cfg := JWTConfig{
		Enabled:    true,
		JWKSURL:    "http://invalid-host-that-does-not-exist.local/jwks",
		Algorithms: []string{"RS256"},
	}
	v, err := NewJWTValidator(cfg)
	if err != nil {
		// URL validation rejects .local, skip
		t.Skip("JWKS URL validation rejects .local")
	}
	// Stop immediately to exercise the stop path of refreshJWKSPeriodically
	v.Stop()
}

// --- Layer.Stop with JWT validator ---

func TestCoverage_Layer_Stop_WithJWT(t *testing.T) {
	cfg := Config{
		Enabled: true,
		JWT: JWTConfig{
			Enabled:          true,
			Algorithms:       []string{"HS256"},
			ClockSkewSeconds: 300,
		},
	}
	l, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}
	l.Stop()
}

// --- Process: no valid auth when only API keys configured ---

func TestCoverage_Process_NoAuthWithAPIKeys(t *testing.T) {
	cfg := Config{
		Enabled: true,
		APIKeys: APIKeysConfig{
			Enabled:    true,
			HeaderName: "X-API-Key",
			Keys: []APIKeyConfig{
				{
					Name:    "test-key",
					KeyHash: "sha256:" + sha256Hex("test-secret"),
					Enabled: true,
				},
			},
		},
	}
	l, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	ctx := &engine.RequestContext{
		Headers:     map[string][]string{},
		QueryParams: map[string][]string{},
		Path:        "/api/test",
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Process(no auth) action = %v, want Block", result.Action)
	}
	if len(result.Findings) == 0 {
		t.Error("Process(no auth) should have findings")
	}
}

// --- extractAPIKey with query param ---

func TestCoverage_ExtractAPIKey_QueryParam(t *testing.T) {
	cfg := Config{
		Enabled: true,
		APIKeys: APIKeysConfig{
			Enabled:    true,
			HeaderName: "X-API-Key",
			QueryParam: "api_key",
		},
	}
	l, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	// Test extraction from query params
	key := l.extractAPIKey(
		map[string][]string{},
		map[string][]string{"api_key": {"my-api-key"}},
	)
	if key != "my-api-key" {
		t.Errorf("extractAPIKey(query) = %q, want %q", key, "my-api-key")
	}

	// Test header takes precedence
	key = l.extractAPIKey(
		map[string][]string{"X-API-Key": {"header-key"}},
		map[string][]string{"api_key": {"query-key"}},
	)
	if key != "header-key" {
		t.Errorf("extractAPIKey(header+query) = %q, want %q", key, "header-key")
	}

	// Test no query param configured
	cfg2 := Config{
		APIKeys: APIKeysConfig{
			Enabled:    true,
			HeaderName: "X-API-Key",
		},
	}
	l2, _ := NewLayer(&cfg2)
	key = l2.extractAPIKey(
		map[string][]string{},
		map[string][]string{"api_key": {"query-key"}},
	)
	if key != "" {
		t.Errorf("extractAPIKey(no query param configured) = %q, want empty", key)
	}
}

// --- validateJWKSURL coverage ---

func TestCoverage_ValidateJWKSURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"empty host", "http://", true},
		{"invalid url", "://invalid", true},
		{"localhost", "http://localhost/jwks", true},
		{"internal suffix", "http://something.internal/jwks", true},
		{"local suffix", "http://something.local/jwks", true},
		{"localhost suffix", "http://something.localhost/jwks", true},
		{"loopback IP", "http://127.0.0.1/jwks", true},
		{"private IP", "http://10.0.0.1/jwks", true},
		{"link local IP", "http://169.254.1.1/jwks", true},
		{"public URL", "https://auth.example.com/.well-known/jwks.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateJWKSURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateJWKSURL(%s) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

// --- VerifySignature unsupported algorithm ---

func TestCoverage_VerifySignature_UnsupportedAlg(t *testing.T) {
	v := &JWTValidator{}
	err := v.verifySignature("EdDSA", "test", []byte("sig"), nil)
	if err == nil {
		t.Error("verifySignature(EdDSA) should fail")
	}
	if !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Errorf("verifySignature(EdDSA) error = %v, want unsupported", err)
	}
}

// --- isAlgorithmAllowed edge cases ---

func TestCoverage_IsAlgorithmAllowed(t *testing.T) {
	tests := []struct {
		name    string
		config  JWTConfig
		alg     string
		allowed bool
	}{
		{
			"none algorithm",
			JWTConfig{Algorithms: []string{"RS256"}},
			"none",
			false,
		},
		{
			"empty algorithm",
			JWTConfig{Algorithms: []string{"RS256"}},
			"",
			false,
		},
		{
			"default allowed RS256",
			JWTConfig{},
			"RS256",
			true,
		},
		{
			"default allowed ES256",
			JWTConfig{},
			"ES256",
			true,
		},
		{
			"default not allowed HS256",
			JWTConfig{},
			"HS256",
			false,
		},
		{
			"default not allowed PS256",
			JWTConfig{},
			"PS256",
			false,
		},
		{
			"explicit HS256 allowed",
			JWTConfig{Algorithms: []string{"HS256"}},
			"HS256",
			true,
		},
		{
			"HMAC blocked with asymmetric source PEM",
			JWTConfig{PublicKeyPEM: "some-key", Algorithms: []string{"HS256"}},
			"HS256",
			false,
		},
		{
			"HMAC blocked with asymmetric source file",
			JWTConfig{PublicKeyFile: "/path/to/key", Algorithms: []string{"HS256"}},
			"HS256",
			false,
		},
		{
			"HMAC blocked with asymmetric source JWKS",
			JWTConfig{JWKSURL: "https://example.com/jwks", Algorithms: []string{"HS256"}},
			"HS256",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &JWTValidator{config: tt.config}
			result := v.isAlgorithmAllowed(tt.alg)
			if result != tt.allowed {
				t.Errorf("isAlgorithmAllowed(%s) = %v, want %v", tt.alg, result, tt.allowed)
			}
		})
	}
}

// --- GenerateToken unsupported algorithm ---

func TestCoverage_GenerateToken_UnsupportedAlg(t *testing.T) {
	_, err := GenerateToken(JWTClaims{}, []byte("secret"), "RS256")
	if err == nil {
		t.Error("GenerateToken(RS256) should fail")
	}
}

// --- Tenant WAF config integration ---

func TestCoverage_Process_TenantConfigDisabled(t *testing.T) {
	cfg := Config{
		Enabled: true,
		JWT: JWTConfig{
			Enabled:          true,
			Algorithms:       []string{"HS256"},
			ClockSkewSeconds: 300,
		},
	}
	l, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	tenantConfig := &config.WAFConfig{}
	tenantConfig.APISecurity.Enabled = false

	ctx := &engine.RequestContext{
		Headers:         map[string][]string{},
		QueryParams:     map[string][]string{},
		Path:            "/api/test",
		TenantWAFConfig: tenantConfig,
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Process(tenant disabled) action = %v, want Pass", result.Action)
	}
}

// --- Handler tests ---

func TestCoverage_Handler_ServeHTTP_Unauthorized(t *testing.T) {
	cfg := Config{
		Enabled: true,
		JWT: JWTConfig{
			Enabled:          true,
			Algorithms:       []string{"HS256"},
			ClockSkewSeconds: 300,
		},
	}
	l, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	// Request without auth
	ctx := &engine.RequestContext{
		Headers:     map[string][]string{},
		QueryParams: map[string][]string{},
		Path:        "/api/test",
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Process(unauthorized) action = %v, want Block", result.Action)
	}
}

// --- JWT with JWKS server test ---

func TestCoverage_JWTWithJWKS(t *testing.T) {
	// Build a JWKS response with a manually constructed RSA key
	n := big.NewInt(123456789)
	e := big.NewInt(65537)

	jwksResp := fmt.Sprintf(`{"keys":[{"kid":"test-key","kty":"RSA","use":"sig","n":"%s","e":"%s"}]}`,
		base64.RawURLEncoding.EncodeToString(n.Bytes()),
		base64.RawURLEncoding.EncodeToString(e.Bytes()),
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, jwksResp)
	}))
	defer server.Close()

	v := &JWTValidator{
		config: JWTConfig{
			JWKSURL:    server.URL,
			Algorithms: []string{"RS256"},
		},
		jwksCache:   &sync.Map{},
		client:      server.Client(),
		ssrfChecked: true, // Skip SSRF check for test
	}
	v.fetchJWKS()

	// Verify key was cached
	_, ok := v.jwksCache.Load("test-key")
	if !ok {
		t.Error("fetchJWKS should have cached the key")
	}
}

// --- fetchJWKS with EC key ---

func TestCoverage_FetchJWKS_ECKeys(t *testing.T) {
	// Build a JWKS response with EC keys (P-256, P-384, P-521)
	ecResp := `{"keys":[
		{"kid":"p256","kty":"EC","use":"sig","crv":"P-256","x":"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis","y":"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"},
		{"kid":"p384","kty":"EC","use":"sig","crv":"P-384","x":"VF8NJrw8aOy3mPkQs4CralOSCDiFCkH07LCx-LoGRTm-TjF5PBnzEVXKIBIvI6vl","y":"7UJhlIg5sOqpZkooposLBxnCTkAjRqC5JoQrqH5YjjGBqDZcB4jjordaAmhCVVIi"},
		{"kid":"p521","kty":"EC","use":"sig","crv":"P-521","x":"AH1W81uIdJhBjWQ0nP6u1UliQMsZySRcYkFDpHPebPuSnsNEak CSLm1tE23SMfOfjsxFpO7AOYJAZ7jXzpA7BjH","y":"AdfFqIL5L6BqOTX7sGm1EcjxFZBa4WwbUjVMZMtk7RwJPL-DQvry7l7Xa7MOxV4ONmS3zEYFh3LfcBjRTFpIqXGe"},
		{"kid":"no-curve","kty":"EC","use":"sig","crv":"unknown","x":"AAAA","y":"AAAA"},
		{"kid":"no-kty","use":"sig"}
	]}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, ecResp)
	}))
	defer server.Close()

	v := &JWTValidator{
		config: JWTConfig{
			JWKSURL:    server.URL,
			Algorithms: []string{"ES256"},
		},
		jwksCache:   &sync.Map{},
		client:      server.Client(),
		ssrfChecked: true,
	}
	v.fetchJWKS()

	// P-256 key should be cached
	if _, ok := v.jwksCache.Load("p256"); !ok {
		t.Error("P-256 EC key should be cached")
	}
	// Unknown curve should not be cached
	if _, ok := v.jwksCache.Load("no-curve"); ok {
		t.Error("Unknown curve EC key should not be cached")
	}
}

// --- fetchJWKS with empty URL ---

func TestCoverage_FetchJWKS_EmptyURL(t *testing.T) {
	v := &JWTValidator{
		config:     JWTConfig{JWKSURL: ""},
		jwksCache:  &sync.Map{},
	}
	v.fetchJWKS() // Should return immediately
}

// --- fetchJWKS with server error ---

func TestCoverage_FetchJWKS_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	v := &JWTValidator{
		config:      JWTConfig{JWKSURL: server.URL},
		jwksCache:   &sync.Map{},
		client:      server.Client(),
		ssrfChecked: true,
	}
	v.fetchJWKS() // Should handle gracefully
}

// --- fetchJWKS with invalid JSON ---

func TestCoverage_FetchJWKS_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer server.Close()

	v := &JWTValidator{
		config:      JWTConfig{JWKSURL: server.URL},
		jwksCache:   &sync.Map{},
		client:      server.Client(),
		ssrfChecked: true,
	}
	v.fetchJWKS() // Should handle gracefully
}

// --- parseASN1Elements edge cases ---

func TestCoverage_ParseASN1Elements_ShortData(t *testing.T) {
	// Single byte remaining (less than 2)
	elements, err := parseASN1Elements([]byte{0x30})
	if err != nil {
		t.Errorf("parseASN1Elements(short data) error = %v", err)
	}
	if len(elements) != 0 {
		t.Errorf("parseASN1Elements(short data) should return 0 elements")
	}
}

func TestCoverage_ParseASN1Length_LongForm(t *testing.T) {
	// Long form with numBytes > 4
	_, _, err := parseASN1Length([]byte{0x85, 0x01, 0x02, 0x03, 0x04, 0x05})
	if err == nil {
		t.Error("parseASN1Length(numBytes>4) should fail")
	}
}

// --- parseValue edge cases ---

func TestCoverage_ASN1Unmarshal_ShortData(t *testing.T) {
	var esig struct{ R, S *big.Int }
	err := asn1Unmarshal([]byte{0x30}, &esig)
	if err == nil {
		t.Error("asn1Unmarshal(short) should fail")
	}
}

func TestCoverage_ASN1Unmarshal_WrongTag(t *testing.T) {
	var esig struct{ R, S *big.Int }
	err := asn1Unmarshal([]byte{0x31, 0x02, 0x02, 0x01}, &esig)
	if err == nil {
		t.Error("asn1Unmarshal(wrong tag) should fail")
	}
}

func TestCoverage_ParseLength_NoLengthByte(t *testing.T) {
	p := &asn1Parser{data: []byte{}}
	_, err := p.parseLength()
	if err == nil {
		t.Error("parseLength(empty) should fail")
	}
}

// --- Helper function ---

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:])
}

func encodeASN1Length(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	// Simple encoding for lengths up to 65535
	if length <= 0xFF {
		return []byte{0x81, byte(length)}
	}
	return []byte{0x82, byte(length >> 8), byte(length & 0xFF)}
}

// --- parsePublicKey with Ed25519 ---

func TestCoverage_ParseEd25519PublicKey(t *testing.T) {
	// Raw 32-byte key
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	key := parseEd25519PublicKey(raw)
	if key == nil {
		t.Error("parseEd25519PublicKey(32 bytes) should return key")
	}

	// Wrong length
	key = parseEd25519PublicKey([]byte{1, 2, 3})
	if key != nil {
		t.Error("parseEd25519PublicKey(short) should return nil")
	}
}

// --- parsePublicKey with invalid PEM ---

func TestCoverage_ParsePublicKey_InvalidPEM(t *testing.T) {
	// No PEM markers
	_, err := parsePublicKey([]byte("not PEM data"))
	if err == nil {
		t.Error("parsePublicKey(no PEM) should fail")
	}

	// END before BEGIN
	_, err = parsePublicKey([]byte("-----END-----\n-----BEGIN-----"))
	if err == nil {
		t.Error("parsePublicKey(inverted PEM) should fail")
	}

	// Valid PEM structure but invalid base64
	_, err = parsePublicKey([]byte("-----BEGIN PUBLIC KEY-----\n!!!invalid-base64!!!\n-----END PUBLIC KEY-----"))
	if err == nil {
		t.Error("parsePublicKey(invalid base64) should fail")
	}

	// Valid PEM but unknown key type
	_, err = parsePublicKey([]byte("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----"))
	if err == nil {
		t.Error("parsePublicKey(unknown key type) should fail")
	}
}

// --- loadPublicKeyFromFile stub test ---

func TestCoverage_LoadPublicKeyFromFile(t *testing.T) {
	// Default stubs should return error
	_, err := loadPublicKeyFromFile("/nonexistent")
	if err == nil {
		t.Error("loadPublicKeyFromFile with default stubs should fail")
	}
}

// --- JWTClaims audience checking ---

func TestCoverage_HasAudience_Nil(t *testing.T) {
	v := &JWTValidator{}
	if v.hasAudience(nil, "expected") {
		t.Error("hasAudience(nil) should return false")
	}
}

// --- VerifySignature PS384/PS512 with non-RSA key ---

func TestCoverage_VerifySignature_PS384_PS512(t *testing.T) {
	v := &JWTValidator{}
	// PS384
	err := v.verifySignature("PS384", "test", []byte("sig"), nil)
	if err == nil {
		t.Error("PS384 with nil key should fail")
	}

	// PS512
	err = v.verifySignature("PS512", "test", []byte("sig"), nil)
	if err == nil {
		t.Error("PS512 with nil key should fail")
	}
}

// --- VerifySignature ES384/ES512 ---

func TestCoverage_VerifySignature_ES384_ES512(t *testing.T) {
	v := &JWTValidator{}
	err := v.verifySignature("ES384", "test", []byte("sig"), nil)
	if err == nil {
		t.Error("ES384 with nil key should fail")
	}
	err = v.verifySignature("ES512", "test", []byte("sig"), nil)
	if err == nil {
		t.Error("ES512 with nil key should fail")
	}
}

// --- refreshJWKSPeriodically ---

func TestCoverage_RefreshJWKSPeriodically_Exercise(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"keys":[{"kid":"rotated-key","kty":"RSA","use":"sig","n":"AQAB","e":"AQAB"}]}`)
	}))
	defer server.Close()

	v := &JWTValidator{
		config: JWTConfig{
			JWKSURL:    server.URL,
			Algorithms: []string{"RS256"},
		},
		jwksCache:   &sync.Map{},
		client:      server.Client(),
		stopCh:      make(chan struct{}),
		ssrfChecked: true,
	}

	// Run refreshJWKSPeriodically in a goroutine with short interval
	done := make(chan struct{})
	go func() {
		defer close(done)
		v.refreshJWKSPeriodically(50 * time.Millisecond)
	}()

	// Wait for at least one refresh
	time.Sleep(200 * time.Millisecond)
	v.Stop()    // triggers stopCh close
	<-done      // wait for goroutine to exit

	if callCount == 0 {
		t.Error("expected at least one JWKS refresh call")
	}
}

// --- NewJWTValidator with PublicKeyPEM ---

func TestCoverage_NewJWTValidator_WithPublicKeyPEM(t *testing.T) {
	// Build a valid PEM for an RSA public key
	modulus := big.NewInt(123456789)
	exponent := big.NewInt(65537)

	// Build inner RSAPublicKey SEQUENCE
	rsaIntN := append([]byte{0x02}, encodeASN1Length(len(modulus.Bytes()))...)
	rsaIntN = append(rsaIntN, modulus.Bytes()...)
	rsaIntE := append([]byte{0x02}, encodeASN1Length(len(exponent.Bytes()))...)
	rsaIntE = append(rsaIntE, exponent.Bytes()...)
	rsaSeqContent := append(rsaIntN, rsaIntE...)
	rsaSeq := append([]byte{0x30}, encodeASN1Length(len(rsaSeqContent))...)
	rsaSeq = append(rsaSeq, rsaSeqContent...)

	bitStringContent := append([]byte{0x00}, rsaSeq...)
	bitString := append([]byte{0x03}, encodeASN1Length(len(bitStringContent))...)
	bitString = append(bitString, bitStringContent...)

	rsaOID := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}
	nullParam := []byte{0x05, 0x00}
	algoContent := append(rsaOID, nullParam...)
	algoSeq := append([]byte{0x30}, encodeASN1Length(len(algoContent))...)
	algoSeq = append(algoSeq, algoContent...)

	spkiContent := append(algoSeq, bitString...)
	spki := append([]byte{0x30}, encodeASN1Length(len(spkiContent))...)
	spki = append(spki, spkiContent...)

	b64 := base64.StdEncoding.EncodeToString(spki)
	pem := "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----"

	cfg := JWTConfig{
		Enabled:          true,
		PublicKeyPEM:     pem,
		Algorithms:       []string{"RS256"},
		ClockSkewSeconds: 300,
	}
	v, err := NewJWTValidator(cfg)
	if err != nil {
		t.Fatalf("NewJWTValidator with valid PEM failed: %v", err)
	}
	if v.publicKey == nil {
		t.Error("publicKey should be set from PEM")
	}
}

// --- NewJWTValidator with invalid PEM ---

func TestCoverage_NewJWTValidator_InvalidPEM(t *testing.T) {
	cfg := JWTConfig{
		Enabled:      true,
		PublicKeyPEM: "not a valid PEM",
		Algorithms:   []string{"RS256"},
	}
	_, err := NewJWTValidator(cfg)
	if err == nil {
		t.Error("NewJWTValidator with invalid PEM should fail")
	}
}

// --- NewJWTValidator with PublicKeyFile (stub fails) ---

func TestCoverage_NewJWTValidator_PublicKeyFile(t *testing.T) {
	cfg := JWTConfig{
		Enabled:       true,
		PublicKeyFile: "/path/to/key",
		Algorithms:    []string{"RS256"},
	}
	_, err := NewJWTValidator(cfg)
	if err == nil {
		t.Error("NewJWTValidator with PublicKeyFile should fail (stubs not set)")
	}
}

// --- fetchJWKS with SSRF re-validation ---

func TestCoverage_FetchJWKS_SSRFRevalidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"keys":[]}`)
	}))
	defer server.Close()

	// ssrfChecked=false should trigger re-validation, which rejects localhost
	v := &JWTValidator{
		config:     JWTConfig{JWKSURL: server.URL},
		jwksCache:  &sync.Map{},
		client:     server.Client(),
		ssrfChecked: false,
	}
	v.fetchJWKS()
	// Should not panic; SSRF check fails silently
}

// --- parseASN1Sequence edge case: length exceeds data ---

func TestCoverage_ParseASN1Sequence_LengthExceedsData(t *testing.T) {
	// SEQUENCE with length longer than available data
	_, err := parseASN1Sequence([]byte{0x30, 0x10, 0x01}) // length=16, only 1 byte
	if err == nil {
		t.Error("parseASN1Sequence should reject length exceeding data")
	}
}

// --- parseASN1Integer edge cases ---

func TestCoverage_ParseASN1Integer_EdgeCases(t *testing.T) {
	// Integer too short
	_, err := parseASN1Integer([]byte{0x02})
	if err == nil {
		t.Error("parseASN1Integer(short) should fail")
	}

	// Wrong tag
	_, err = parseASN1Integer([]byte{0x04, 0x01, 0x01})
	if err == nil {
		t.Error("parseASN1Integer(wrong tag) should fail")
	}

	// Integer length exceeds data
	_, err = parseASN1Integer([]byte{0x02, 0x10, 0x01})
	if err == nil {
		t.Error("parseASN1Integer(length exceeds data) should fail")
	}
}

// --- parseASN1Elements with element exceeding data ---

func TestCoverage_ParseASN1Elements_ElementExceedsData(t *testing.T) {
	// Element with length exceeding remaining data
	_, err := parseASN1Elements([]byte{0x02, 0x10, 0x01}) // integer with length=16
	if err == nil {
		t.Error("parseASN1Elements should reject element exceeding data")
	}
}
