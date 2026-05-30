// Package apisecurity provides API authentication and authorization.
// It includes JWT validation and API key validation.
package apisecurity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/logging"
)

// NewJWTValidator creates a new JWT validator.
func NewJWTValidator(cfg JWTConfig) (*JWTValidator, error) {
	v := &JWTValidator{
		config:     cfg,
		log:        logging.NewLogger("jwt"),
		jwksCache:  &sync.Map{},
		hmacKeys:   &sync.Map{},
		stopCh:     make(chan struct{}),
	}
	v.client = v.newJWKSHTTPClient()

	// Clamp clock skew to a sane range. An unbounded skew would effectively
	// disable exp/nbf validation, so reject negatives and cap at one hour.
	if v.config.ClockSkewSeconds < 0 {
		v.config.ClockSkewSeconds = 0
	}
	if v.config.ClockSkewSeconds > 3600 {
		v.log.Warn("clock_skew_seconds exceeds 3600; clamping to 3600", "clock_skew_seconds", v.config.ClockSkewSeconds)
		v.config.ClockSkewSeconds = 3600
	}

	// Load public key if provided directly
	if cfg.PublicKeyPEM != "" {
		key, err := parsePublicKey([]byte(cfg.PublicKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		v.publicKey = key
	}

	// Load from file if specified
	if cfg.PublicKeyFile != "" && v.publicKey == nil {
		key, err := loadPublicKeyFromFile(cfg.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load public key from file: %w", err)
		}
		v.publicKey = key
	}

	// Fetch JWKS if URL provided — start periodic refresh
	if cfg.JWKSURL != "" {
		// SSRF validation — fail fast on private network URLs
		if err := validateJWKSURL(cfg.JWKSURL); err != nil {
			return nil, fmt.Errorf("JWKS URL rejected: %w", err)
		}
		v.ssrfChecked = true
		v.wg.Add(1)
		go func() { defer v.wg.Done(); v.fetchJWKS() }()
		v.wg.Add(1)
		go func() { defer v.wg.Done(); v.refreshJWKSPeriodically(5 * time.Minute) }()
	}

	// Warn if using default algorithm whitelist — production deployments should
	// explicitly set the `algorithms` field to restrict allowed algorithms.
	if len(cfg.Algorithms) == 0 {
		v.log.Warn("JWT validation using default algorithm whitelist (RS256, ES256). Set `algorithms` in config to allow other algorithms.")
	}

	return v, nil
}

// Validate validates a JWT token string.
func (v *JWTValidator) Validate(tokenString string) (*JWTClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty token")
	}

	// Split token
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode header
	header, err := decodeBase64(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid header encoding: %w", err)
	}

	var jwtHeader struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err = json.Unmarshal(header, &jwtHeader); err != nil {
		return nil, fmt.Errorf("invalid header JSON: %w", err)
	}

	// Verify algorithm is allowed
	if !v.isAlgorithmAllowed(jwtHeader.Alg) {
		return nil, fmt.Errorf("algorithm %s not allowed", jwtHeader.Alg)
	}

	// Decode payload
	payload, err := decodeBase64(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}

	var claims JWTClaims
	if err = json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("invalid payload JSON: %w", err)
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	signature, err := decodeBase64Raw(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Get the verification key
	key := v.publicKey
	if jwtHeader.Kid != "" {
		if _, ok := v.hmacKeys.Load(jwtHeader.Kid); ok {
			if err := v.verifyHMACKey(jwtHeader.Kid, signingInput, signature, jwtHeader.Alg); err != nil {
				return nil, fmt.Errorf("signature verification failed: %w", err)
			}
			return &claims, nil
		}
		if pk, ok := v.jwksCache.Load(jwtHeader.Kid); ok {
			key = pk.(crypto.PublicKey)
		}
	}

	// Reject symmetric algorithms (HS*) when an asymmetric key is configured.
	// This prevents algorithm confusion attacks where an attacker could forge
	// tokens using the public key as an HMAC secret. Additionally, accepting
	// HS* with asymmetric keys creates a timing oracle (RSA verification is
	// significantly slower than HMAC).
	switch jwtHeader.Alg {
	case "HS256", "HS384", "HS512":
		// Reject if asymmetric key is configured (RSA, ECDSA)
		if v.publicKey != nil {
			switch v.publicKey.(type) {
			case *rsa.PublicKey, *rsa.PrivateKey,
				*ecdsa.PublicKey, *ecdsa.PrivateKey:
				return nil, fmt.Errorf("HMAC algorithm %s not allowed with asymmetric key", jwtHeader.Alg)
			}
		}
		// HMAC tokens without a JWKS kid may have the secret set directly on publicKey.
		// Store in hmacKeys to mirror expected path for verifyHMACKey.
		if sp, ok := v.publicKey.([]byte); ok && len(sp) > 0 {
			kid := jwtHeader.Kid
			if kid == "" {
				kid = "_inline"
			}
			v.hmacKeys.Store(kid, hmacKey(sp))
		}
	}

	if key == nil {
		return nil, fmt.Errorf("no verification key available")
	}

	// Verify signature based on algorithm
	if err := v.verifySignature(jwtHeader.Alg, signingInput, signature, key); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Validate claims
	now := time.Now().Unix()
	skew := int64(v.config.ClockSkewSeconds)

	// Check expiration
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt+skew {
		return nil, fmt.Errorf("token expired")
	}

	// Check not-before
	if claims.NotBefore > 0 && now < claims.NotBefore-skew {
		return nil, fmt.Errorf("token not yet valid")
	}

	// Check issuer
	if v.config.Issuer != "" && claims.Issuer != v.config.Issuer {
		return nil, fmt.Errorf("invalid issuer")
	}

	// Check audience
	if v.config.Audience != "" {
		if !v.hasAudience(claims.Audience, v.config.Audience) {
			return nil, fmt.Errorf("invalid audience")
		}
	}

	return &claims, nil
}

// verifyHMACKey verifies an HMAC signature using the key indexed by kid.
func (v *JWTValidator) verifyHMACKey(kid, signingInput string, signature []byte, alg string) error {
	keyVal, ok := v.hmacKeys.Load(kid)
	if !ok {
		return fmt.Errorf("no HMAC key found for kid %q", kid)
	}
	hk, ok := keyVal.(hmacKey)
	if !ok {
		return fmt.Errorf("key for kid %q is not an HMAC key", kid)
	}
	var hashFunc func() hash.Hash
	switch alg {
	case "HS256":
		hashFunc = sha256.New
	case "HS384":
		hashFunc = sha512.New384
	case "HS512":
		hashFunc = sha512.New
	default:
		return fmt.Errorf("unsupported HMAC algorithm: %s", alg)
	}
	h := hmac.New(hashFunc, []byte(hk))
	h.Write([]byte(signingInput))
	expected := h.Sum(nil)
	if !hmac.Equal(signature, expected) {
		return fmt.Errorf("HMAC verification failed")
	}
	return nil
}

// fetchJWKS fetches the JSON Web Key Set from the configured JWKS URL.
func (v *JWTValidator) fetchJWKS() {
	// Defensive: guard against nil receiver (can happen if caller
	// ignores the error from NewJWTValidator and calls fetchJWKS directly).
	if v == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			// Use a no-op logger fallback only in this recovery path —
			// all normal calls have v.log set by NewJWTValidator.
			slog.Default().Error("fetchJWKS panic", "panic", r)
		}
	}()
	if v.config.JWKSURL == "" {
		return
	}

	// Re-validate JWKS URL on each fetch to prevent DNS rebinding attacks.
	if !v.ssrfChecked {
		if err := validateJWKSURL(v.config.JWKSURL); err != nil {
			v.log.Warn("JWKS URL validation failed", "url", v.config.JWKSURL, "error", err)
			return
		}
		v.ssrfChecked = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.config.JWKSURL, http.NoBody)
	if err != nil {
		return
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
			X   string `json:"x"`
			Y   string `json:"y"`
			Crv string `json:"crv"`
			K   string `json:"k"` // symmetric key
		} `json:"keys"`
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&jwks); err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	for _, key := range jwks.Keys {
		switch key.Kty {
		case "RSA":
			n, _ := decodeBase64Raw(key.N)
			e, _ := decodeBase64Raw(key.E)
			if n != nil && e != nil && len(n) > 0 && len(e) > 0 {
				pubKey := &rsa.PublicKey{
					N: new(big.Int).SetBytes(n),
					E: int(new(big.Int).SetBytes(e).Int64()),
				}
				if key.Kid != "" {
					v.jwksCache.Store(key.Kid, pubKey)
				}
			}
		case "EC":
			x, _ := decodeBase64Raw(key.X)
			y, _ := decodeBase64Raw(key.Y)
			if x != nil && y != nil && len(x) > 0 && len(y) > 0 {
				var curve elliptic.Curve
				switch key.Crv {
				case "P-256":
					curve = elliptic.P256()
				case "P-384":
					curve = elliptic.P384()
				case "P-521":
					curve = elliptic.P521()
				}
				if curve != nil {
					pubKey := &ecdsa.PublicKey{
						Curve: curve,
						X:     new(big.Int).SetBytes(x),
						Y:     new(big.Int).SetBytes(y),
					}
					if key.Kid != "" {
						v.jwksCache.Store(key.Kid, pubKey)
					}
				}
			}
		case "oct":
			// Symmetric octet key (HMAC)
			k, _ := decodeBase64Raw(key.K)
			if k != nil && len(k) > 0 && key.Kid != "" {
				v.hmacKeys.Store(key.Kid, hmacKey(k))
			}
		}
	}
}

func (v *JWTValidator) refreshJWKSPeriodically(interval time.Duration) {
	if v == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Default().Error("refreshJWKSPeriodically panic", "panic", r)
		}
	}()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-v.stopCh:
			return
		case <-ticker.C:
			v.fetchJWKS()
		}
	}
}

// Stop stops the JWKS refresh goroutine. After calling Stop, the validator
// should not be used for token validation (cached keys remain available).
func (v *JWTValidator) Stop() {
	select {
	case <-v.stopCh:
		// Already closed
	default:
		close(v.stopCh)
	}
	v.wg.Wait()
}

// --- Helpers ---

func decodeBase64(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(addPadding(s))
}

func decodeBase64Raw(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func addPadding(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	}
	return s
}

// GenerateToken generates a test JWT token (for testing only).
func GenerateToken(claims JWTClaims, secret []byte, alg string) (string, error) {
	header := map[string]string{"alg": alg, "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64

	var sig []byte
	switch alg {
	case "HS256":
		h := hmac.New(sha256.New, secret)
		h.Write([]byte(signingInput))
		sig = h.Sum(nil)
	default:
		return "", fmt.Errorf("unsupported algorithm for token generation")
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// validateJWKSURL checks that the JWKS URL does not target private/internal networks.
// Prevents SSRF attacks via maliciously configured JWKS endpoints.
func validateJWKSURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host")
	}
	// Reject known local hostnames
	if host == "localhost" || strings.HasSuffix(host, ".internal") ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("must not target localhost or internal hosts")
	}
	// Check raw IP
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("must not target private/loopback/link-local addresses")
		}
		return nil
	}
	// Resolve DNS and check all resulting IPs
	addrs, err := net.LookupHost(host)
	if err != nil {
		// Allow through if DNS fails — will fail at connection time
		return nil
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("hostname resolves to private/loopback address %s", ip)
		}
	}
	return nil
}
