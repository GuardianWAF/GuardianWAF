package apisecurity

import (
	"strings"
	"testing"
)

func FuzzJWTValidatorConfig(f *testing.F) {
	f.Add(true, "issuer", "audience", "RS256,ES256", 30)
	f.Add(false, "", "", "", 0)
	f.Add(true, "https://auth.example.com", "api", "HS256", 300)
	f.Add(true, "", "", "", 0)

	f.Fuzz(func(t *testing.T, enabled bool, issuer, audience, algsStr string, clockSkew int) {
		var algs []string
		if algsStr != "" {
			for _, a := range strings.Split(algsStr, ",") {
				algs = append(algs, strings.TrimSpace(a))
			}
		}
		cfg := JWTConfig{
			Enabled:          enabled,
			Issuer:           issuer,
			Audience:         audience,
			Algorithms:      algs,
			ClockSkewSeconds: clockSkew,
		}

		// NewJWTValidator with these configs should not panic
		_, _ = NewJWTValidator(cfg)
	})
}

func FuzzJWTValidateInput(f *testing.F) {
	f.Add("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.invalid")
	f.Add("")
	f.Add("not.a.jwt")
	f.Add("a.b.c")
	f.Add("HEADER.PAYLOAD.SIGNATURE")
	f.Add("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdA")

	f.Fuzz(func(t *testing.T, token string) {
		// Build a validator with no config for fuzzing
		cfg := JWTConfig{
			Enabled: true,
		}
		v, err := NewJWTValidator(cfg)
		if err != nil {
			// Skip if validator creation fails (e.g., no key)
			return
		}

		// Validate should handle any input gracefully
		_, _ = v.Validate(token)
	})
}

func FuzzJWTValidateEmptyConfig(f *testing.F) {
	f.Add(true, "", "", "", 0)

	f.Fuzz(func(t *testing.T, enabled bool, issuer, audience, algsStr string, clockSkew int) {
		var algs []string
		if algsStr != "" {
			for _, a := range strings.Split(algsStr, ",") {
				algs = append(algs, strings.TrimSpace(a))
			}
		}
		cfg := JWTConfig{
			Enabled:          enabled,
			Issuer:           issuer,
			Audience:         audience,
			Algorithms:      algs,
			ClockSkewSeconds: clockSkew,
		}

		v, err := NewJWTValidator(cfg)
		if err != nil {
			return
		}

		// Validate with various malformed tokens should not panic
		_, _ = v.Validate("")
		_, _ = v.Validate("not-a-token")
		_, _ = v.Validate("a.b")
		_, _ = v.Validate("a.b.c.d")
	})
}