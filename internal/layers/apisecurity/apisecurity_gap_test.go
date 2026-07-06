package apisecurity

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestLayerOrder(t *testing.T) {
	l := &Layer{}
	if got := l.Order(); got != engine.OrderAPISecurity {
		t.Fatalf("Order() = %d, want %d", got, engine.OrderAPISecurity)
	}
}

func TestLayerProcess_TenantOverrideDisabled(t *testing.T) {
	cfg := Config{Enabled: true, JWT: JWTConfig{Enabled: true}}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &engine.RequestContext{
		Path:    "/api/protected",
		Headers: map[string][]string{"Authorization": {"Bearer malformed.token.value"}},
		TenantWAFConfig: &config.WAFConfig{
			APISecurity: config.APISecurityConfig{Enabled: false},
		},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected pass when tenant config disables api security, got %v", result.Action)
	}
}

func TestLayerProcess_JWTTenantMismatch(t *testing.T) {
	secret := []byte("tenant-mismatch-secret")
	now := time.Now().Unix()
	claims := JWTClaims{
		Subject:   "user-123",
		TenantID:  "tenant-a",
		ExpiresAt: now + 3600,
		IssuedAt:  now,
	}

	layer, err := NewLayer(&Config{
		Enabled: true,
		JWT: JWTConfig{Enabled: true, Algorithms: []string{"HS256"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	layer.jwtValidator.publicKey = secret

	token := makeValidHS256Token(claims, secret)
	ctx := &engine.RequestContext{
		Path:     "/api/protected",
		Headers:  map[string][]string{"Authorization": {"Bearer " + token}},
		Metadata: map[string]any{},
		TenantID: "tenant-b",
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Fatalf("expected block for tenant mismatch, got %v", result.Action)
	}
	if len(result.Findings) == 0 || !strings.Contains(result.Findings[0].Description, "tenant_id claim") {
		t.Fatalf("expected tenant mismatch finding, got %#v", result.Findings)
	}
}

func TestJWTValidate_HMACKidPath_Success(t *testing.T) {
	secret := []byte("kid-secret")
	now := time.Now().Unix()
	claims := JWTClaims{Subject: "kid-user", ExpiresAt: now + 3600, IssuedAt: now}
	v, err := NewJWTValidator(JWTConfig{Enabled: true, Algorithms: []string{"HS256"}})
	if err != nil {
		t.Fatal(err)
	}
	v.hmacKeys.Store("kid-1", hmacKey(secret))

	token := makeHS256Token(map[string]string{"alg": "HS256", "typ": "JWT", "kid": "kid-1"}, claims, secret)
	parsed, err := v.Validate(token)
	if err != nil {
		t.Fatalf("expected valid token via kid HMAC path, got %v", err)
	}
	if parsed.Subject != claims.Subject {
		t.Fatalf("Subject = %q, want %q", parsed.Subject, claims.Subject)
	}
}

func TestVerifyHMACKey_ErrorBranches(t *testing.T) {
	v := &JWTValidator{hmacKeys: &sync.Map{}}

	if err := v.verifyHMACKey("missing", "a.b", []byte("sig"), "HS256"); err == nil || !strings.Contains(err.Error(), "no HMAC key found") {
		t.Fatalf("expected missing kid error, got %v", err)
	}

	v.hmacKeys.Store("bad-type", []byte("not-hmacKey"))
	if err := v.verifyHMACKey("bad-type", "a.b", []byte("sig"), "HS256"); err == nil || !strings.Contains(err.Error(), "is not an HMAC key") {
		t.Fatalf("expected wrong type error, got %v", err)
	}

	v.hmacKeys.Store("good", hmacKey([]byte("secret")))
	if err := v.verifyHMACKey("good", "a.b", []byte("sig"), "HS999"); err == nil || !strings.Contains(err.Error(), "unsupported HMAC algorithm") {
		t.Fatalf("expected unsupported algorithm error, got %v", err)
	}
}

func TestVerifySignature_HS384AndUnsupported(t *testing.T) {
	secret := []byte("hs384-secret")
	claims := JWTClaims{Subject: "hs384-user", ExpiresAt: time.Now().Unix() + 3600}
	token := makeHS384Token(claims, secret)
	parts := strings.Split(token, ".")
	sig, err := decodeBase64Raw(parts[2])
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewJWTValidator(JWTConfig{Enabled: true, Algorithms: []string{"HS384"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.verifySignature("HS384", parts[0]+"."+parts[1], sig, secret); err != nil {
		t.Fatalf("expected HS384 inline verification to succeed, got %v", err)
	}
	if err := v.verifySignature("bogus", parts[0]+"."+parts[1], sig, secret); err == nil || !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Fatalf("expected unsupported algorithm error, got %v", err)
	}
}
