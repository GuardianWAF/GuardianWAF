package apisecurity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// signHS256WithKid mints an HS256 token carrying a "kid" header, which routes
// Validate down the v.hmacKeys branch.
func signHS256WithKid(t *testing.T, kid string, secret []byte, claims JWTClaims) string {
	t.Helper()
	headerJSON, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON)
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func newKidValidator(t *testing.T, kid string, secret []byte, cfg JWTConfig) *JWTValidator {
	t.Helper()
	v := &JWTValidator{config: cfg, hmacKeys: &sync.Map{}, jwksCache: &sync.Map{}}
	v.hmacKeys.Store(kid, hmacKey(secret))
	return v
}

// TestValidate_KidHMACPathEnforcesClaims pins the fix for the kid-indexed HMAC
// branch, which used to `return &claims, nil` immediately after the signature
// check. Because exp/nbf/iss/aud are validated at the bottom of Validate, that
// early return accepted correctly-signed but expired, not-yet-valid,
// wrong-issuer and wrong-audience tokens. A signature check is not a claim
// check; both must run on every path.
func TestValidate_KidHMACPathEnforcesClaims(t *testing.T) {
	const kid = "shared-key-1"
	secret := []byte("super-secret-hmac-key-for-testing")
	now := time.Now().Unix()

	tests := []struct {
		name    string
		cfg     JWTConfig
		claims  JWTClaims
		wantErr string
	}{
		{
			name:    "expired token is rejected",
			cfg:     JWTConfig{Algorithms: []string{"HS256"}},
			claims:  JWTClaims{Subject: "u1", ExpiresAt: now - 3600},
			wantErr: "token expired",
		},
		{
			name:    "not-yet-valid token is rejected",
			cfg:     JWTConfig{Algorithms: []string{"HS256"}},
			claims:  JWTClaims{Subject: "u1", NotBefore: now + 3600, ExpiresAt: now + 7200},
			wantErr: "token not yet valid",
		},
		{
			name:    "wrong issuer is rejected",
			cfg:     JWTConfig{Algorithms: []string{"HS256"}, Issuer: "https://issuer.example"},
			claims:  JWTClaims{Subject: "u1", Issuer: "https://attacker.example", ExpiresAt: now + 3600},
			wantErr: "invalid issuer",
		},
		{
			name:    "wrong audience is rejected",
			cfg:     JWTConfig{Algorithms: []string{"HS256"}, Audience: "api.example"},
			claims:  JWTClaims{Subject: "u1", Audience: "other.example", ExpiresAt: now + 3600},
			wantErr: "invalid audience",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newKidValidator(t, kid, secret, tt.cfg)
			token := signHS256WithKid(t, kid, secret, tt.claims)

			got, err := v.Validate(token)
			if err == nil {
				t.Fatalf("Validate accepted a token it must reject (%s); claims = %+v", tt.wantErr, got)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestValidate_KidHMACPathAcceptsValidToken guards against over-correcting the
// above into rejecting everything on the kid path.
func TestValidate_KidHMACPathAcceptsValidToken(t *testing.T) {
	const kid = "shared-key-1"
	secret := []byte("super-secret-hmac-key-for-testing")
	now := time.Now().Unix()

	v := newKidValidator(t, kid, secret, JWTConfig{
		Algorithms: []string{"HS256"},
		Issuer:     "https://issuer.example",
		Audience:   "api.example",
	})
	token := signHS256WithKid(t, kid, secret, JWTClaims{
		Subject:   "u1",
		Issuer:    "https://issuer.example",
		Audience:  "api.example",
		NotBefore: now - 60,
		ExpiresAt: now + 3600,
	})

	claims, err := v.Validate(token)
	if err != nil {
		t.Fatalf("Validate rejected a valid kid-HMAC token: %v", err)
	}
	if claims.Subject != "u1" {
		t.Fatalf("claims.Subject = %q, want u1", claims.Subject)
	}
}

// TestValidate_KidHMACPathStillRejectsBadSignature confirms the signature check
// itself did not regress when it stopped returning early.
func TestValidate_KidHMACPathStillRejectsBadSignature(t *testing.T) {
	const kid = "shared-key-1"
	v := newKidValidator(t, kid, []byte("the-real-secret"), JWTConfig{Algorithms: []string{"HS256"}})
	token := signHS256WithKid(t, kid, []byte("the-wrong-secret"), JWTClaims{
		Subject:   "u1",
		ExpiresAt: time.Now().Unix() + 3600,
	})

	if _, err := v.Validate(token); err == nil {
		t.Fatal("Validate accepted a token signed with the wrong secret")
	}
}
