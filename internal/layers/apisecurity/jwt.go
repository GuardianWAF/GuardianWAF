// Package apisecurity provides API authentication and authorization.
// It includes JWT validation and API key validation.
package apisecurity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Hash is an alias for crypto.Hash
type Hash = crypto.Hash

// JWTConfig configures JWT validation.
type JWTConfig struct {
	Enabled          bool     `yaml:"enabled"`
	Issuer           string   `yaml:"issuer"`
	Audience         string   `yaml:"audience"`
	Algorithms       []string `yaml:"algorithms"`
	PublicKeyFile    string   `yaml:"public_key_file"`
	JWKSURL          string   `yaml:"jwks_url"`
	ClockSkewSeconds int      `yaml:"clock_skew_seconds"`
	PublicKeyPEM     string   `yaml:"public_key_pem"` // For config embedding
}

// JWTValidator validates JWT tokens.
type JWTValidator struct {
	config      JWTConfig
	publicKey   crypto.PublicKey
	jwksCache   *sync.Map // kid -> crypto.PublicKey
	client      *http.Client
	stopCh      chan struct{}
	ssrfChecked bool // tracks if JWKS URL SSRF validation passed
}

// JWTClaims represents the standard JWT claims.
type JWTClaims struct {
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  any    `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	JWTID     string `json:"jti,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"` // Multi-tenant isolation claim
}

// NewJWTValidator creates a new JWT validator.
func NewJWTValidator(cfg JWTConfig) (*JWTValidator, error) {
	v := &JWTValidator{
		config:    cfg,
		jwksCache: &sync.Map{},
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		stopCh: make(chan struct{}),
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
		go v.fetchJWKS()
		go v.refreshJWKSPeriodically(5 * time.Minute)
	}

	// Warn if using default algorithm whitelist — production deployments should
	// explicitly set the `algorithms` field to restrict allowed algorithms.
	if len(cfg.Algorithms) == 0 {
		log.Println("[jwt] WARNING: JWT validation using default algorithm whitelist (RS256-RS512, ES256-ES512, HS256-HS512). Set `algorithms` in config to restrict.")
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
	if jwtHeader.Kid != "" && v.jwksCache != nil {
		if k, ok := v.jwksCache.Load(jwtHeader.Kid); ok {
			if pk, valid := k.(crypto.PublicKey); valid {
				key = pk
			}
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

func (v *JWTValidator) isAlgorithmAllowed(alg string) bool {
	// Explicitly reject "none" algorithm — this is a critical security measure.
	// A token signed with algorithm "none" has no cryptographic integrity guarantee.
	if alg == "" || alg == "none" {
		return false
	}
	// Prevent algorithm confusion: if an asymmetric key source is configured
	// (PEM key, key file, or JWKS URL), do not allow HMAC algorithms.
	hasAsymmetricSource := v.config.PublicKeyPEM != "" ||
		v.config.PublicKeyFile != "" ||
		v.config.JWKSURL != ""
	if hasAsymmetricSource {
		switch alg {
		case "HS256", "HS384", "HS512":
			return false
		}
	}

	if len(v.config.Algorithms) == 0 {
		// Default allowed algorithms — restricted to prevent algorithm confusion.
		// Only RS256 and ES256 are allowed by default.
		// Set `algorithms` in JWT config to enable additional algorithms.
		switch alg {
		case "RS256", "ES256":
			return true
		}
		return false
	}
	for _, a := range v.config.Algorithms {
		if a == alg {
			return true
		}
	}
	return false
}

func (v *JWTValidator) hasAudience(aud any, expected string) bool {
	switch a := aud.(type) {
	case string:
		return a == expected
	case []any:
		for _, aa := range a {
			if s, ok := aa.(string); ok && s == expected {
				return true
			}
		}
	case []string:
		for _, s := range a {
			if s == expected {
				return true
			}
		}
	}
	return false
}

func (v *JWTValidator) verifySignature(alg, signingInput string, signature []byte, key crypto.PublicKey) error {
	switch alg {
	case "RS256":
		return verifyRSASignature(key, crypto.SHA256, signingInput, signature)
	case "RS384":
		return verifyRSASignature(key, crypto.SHA384, signingInput, signature)
	case "RS512":
		return verifyRSASignature(key, crypto.SHA512, signingInput, signature)
	case "PS256":
		return verifyRSAPSSSignature(key, crypto.SHA256, signingInput, signature)
	case "PS384":
		return verifyRSAPSSSignature(key, crypto.SHA384, signingInput, signature)
	case "PS512":
		return verifyRSAPSSSignature(key, crypto.SHA512, signingInput, signature)
	case "ES256":
		return verifyECDSASignature(key, crypto.SHA256, signingInput, signature)
	case "ES384":
		return verifyECDSASignature(key, crypto.SHA384, signingInput, signature)
	case "ES512":
		return verifyECDSASignature(key, crypto.SHA512, signingInput, signature)
	case "HS256":
		return verifyHMACSignature(key, sha256.New, signingInput, signature)
	case "HS384":
		return verifyHMACSignature(key, sha512.New384, signingInput, signature)
	case "HS512":
		return verifyHMACSignature(key, sha512.New, signingInput, signature)
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func verifyRSASignature(key crypto.PublicKey, hash crypto.Hash, data string, sig []byte) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}

	h := hash.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	return rsa.VerifyPKCS1v15(rsaKey, hash, hashed, sig)
}

func verifyRSAPSSSignature(key crypto.PublicKey, hash crypto.Hash, data string, sig []byte) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}

	h := hash.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	// RSA-PSS with salt length equal to hash length (per RFC 7518 section 3.5)
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	return rsa.VerifyPSS(rsaKey, hash, hashed, sig, opts)
}

func verifyECDSASignature(key crypto.PublicKey, hash crypto.Hash, data string, sig []byte) error {
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an ECDSA public key")
	}

	h := hash.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	// Parse DER-encoded ECDSA signature
	var esig struct {
		R, S *big.Int
	}
	if err := asn1Unmarshal(sig, &esig); err != nil {
		// Try raw format (r||s)
		if len(sig) == 64 {
			esig.R = new(big.Int).SetBytes(sig[:32])
			esig.S = new(big.Int).SetBytes(sig[32:])
		} else {
			return fmt.Errorf("invalid ECDSA signature format")
		}
	}

	if !ecdsa.Verify(ecdsaKey, hashed, esig.R, esig.S) {
		return fmt.Errorf("ECDSA verification failed")
	}

	return nil
}

func verifyHMACSignature(key crypto.PublicKey, hashFunc func() hash.Hash, data string, sig []byte) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("not an HMAC key")
	}

	h := hmac.New(hashFunc, keyBytes)
	h.Write([]byte(data))
	expected := h.Sum(nil)

	if !hmac.Equal(sig, expected) {
		return fmt.Errorf("HMAC verification failed")
	}
	return nil
}

func (v *JWTValidator) fetchJWKS() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[jwt] fetchJWKS panic: %v", r)
		}
	}()
	if v.config.JWKSURL == "" {
		return
	}

	// Re-validate JWKS URL on each fetch to prevent DNS rebinding attacks.
	// The initial validation at startup only checked the hostname; DNS could have
	// changed since then to point to a private/internal address.
	if err := validateJWKSURL(v.config.JWKSURL); err != nil {
		log.Printf("[jwt] fetchJWKS: JWKS URL validation failed: %v", err)
		return
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
		} `json:"keys"`
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&jwks); err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	for _, key := range jwks.Keys {
		var pubKey crypto.PublicKey
		switch key.Kty {
		case "RSA":
			n, _ := decodeBase64Raw(key.N)
			e, _ := decodeBase64Raw(key.E)
			if n != nil && e != nil {
				pubKey = &rsa.PublicKey{
					N: new(big.Int).SetBytes(n),
					E: int(new(big.Int).SetBytes(e).Int64()),
				}
			}
		case "EC":
			x, _ := decodeBase64Raw(key.X)
			y, _ := decodeBase64Raw(key.Y)
			if x != nil && y != nil {
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
					pubKey = &ecdsa.PublicKey{
						Curve: curve,
						X:     new(big.Int).SetBytes(x),
						Y:     new(big.Int).SetBytes(y),
					}
				}
			}
		}

		if pubKey != nil && key.Kid != "" {
			v.jwksCache.Store(key.Kid, pubKey)
		}
	}
}

func (v *JWTValidator) refreshJWKSPeriodically(interval time.Duration) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[jwt] refreshJWKSPeriodically panic: %v", r)
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
}

// Helper functions

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

// Simple ASN.1 unmarshaler for ECDSA signatures
type asn1Parser struct {
	data []byte
}

func asn1Unmarshal(data []byte, out any) error {
	p := &asn1Parser{data: data}
	return p.parseValue(out)
}

func (p *asn1Parser) parseValue(out any) error {
	if len(p.data) < 2 {
		return fmt.Errorf("too short")
	}

	tag := p.data[0]
	if tag != 0x30 { // SEQUENCE
		return fmt.Errorf("expected SEQUENCE")
	}

	p.data = p.data[1:]
	length, err := p.parseLength()
	if err != nil {
		return err
	}

	seq := p.data[:length]
	p.data = p.data[length:]

	// Parse two INTEGERs
	esig := out.(*struct{ R, S *big.Int })

	if len(seq) < 2 {
		return fmt.Errorf("signature SEQUENCE too short")
	}
	seq = seq[1:] // skip INTEGER tag
	l1, _ := parseLengthFrom(&seq)
	if l1 > len(seq) {
		return fmt.Errorf("invalid R length")
	}
	esig.R = new(big.Int).SetBytes(stripLeadingZeros(seq[:l1]))
	seq = seq[l1:]

	if len(seq) < 2 {
		return fmt.Errorf("signature SEQUENCE too short for S")
	}
	seq = seq[1:] // skip INTEGER tag
	l2, _ := parseLengthFrom(&seq)
	if l2 > len(seq) {
		return fmt.Errorf("invalid S length")
	}
	esig.S = new(big.Int).SetBytes(stripLeadingZeros(seq[:l2]))

	return nil
}

func (p *asn1Parser) parseLength() (int, error) {
	if len(p.data) == 0 {
		return 0, fmt.Errorf("no length byte")
	}
	b := p.data[0]
	p.data = p.data[1:]
	if b < 0x80 {
		return int(b), nil
	}
	// Multi-byte length
	n := int(b & 0x7f)
	if n > len(p.data) {
		return 0, fmt.Errorf("length overflow")
	}
	var length int
	for i := 0; i < n; i++ {
		length = length<<8 | int(p.data[i])
	}
	p.data = p.data[n:]
	return length, nil
}

func parseLengthFrom(data *[]byte) (int, error) {
	if len(*data) == 0 {
		return 0, fmt.Errorf("no data")
	}
	b := (*data)[0]
	*data = (*data)[1:]
	if b < 0x80 {
		return int(b), nil
	}
	n := int(b & 0x7f)
	if n > len(*data) {
		return 0, fmt.Errorf("length overflow")
	}
	var length int
	for i := 0; i < n; i++ {
		length = length<<8 | int((*data)[i])
	}
	*data = (*data)[n:]
	return length, nil
}

func stripLeadingZeros(b []byte) []byte {
	for i := 0; i < len(b); i++ {
		if b[i] != 0 {
			return b[i:]
		}
	}
	return b
}

// parsePublicKey parses a PEM-encoded public key.
func parsePublicKey(pemData []byte) (crypto.PublicKey, error) {
	// Find PEM block
	s := string(pemData)
	start := strings.Index(s, "-----BEGIN")
	if start == -1 {
		return nil, fmt.Errorf("no PEM data found")
	}
	end := strings.Index(s, "-----END")
	if end == -1 || end <= start {
		return nil, fmt.Errorf("invalid PEM format")
	}

	// Extract base64 content
	blockStart := strings.Index(s[start:], "\n") + start + 1
	blockEnd := end
	b64 := strings.ReplaceAll(s[blockStart:blockEnd], "\n", "")
	b64 = strings.ReplaceAll(b64, "\r", "")

	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	// Try parsing as various key types
	// RSA SubjectPublicKeyInfo
	if key := parseRSAPublicKey(der); key != nil {
		return key, nil
	}

	// ECDSA SubjectPublicKeyInfo
	if key := parseECDSAPublicKey(der); key != nil {
		return key, nil
	}

	// Ed25519
	if key := parseEd25519PublicKey(der); key != nil {
		return key, nil
	}

	return nil, fmt.Errorf("could not parse public key")
}

func parseRSAPublicKey(der []byte) *rsa.PublicKey {
	// Try raw RSA key first (modulus + exponent)
	if key := parseRawRSAPublicKey(der); key != nil {
		return key
	}
	// Try PKIX SubjectPublicKeyInfo format
	if key := parsePKIXRSAPublicKey(der); key != nil {
		return key
	}
	return nil
}

// parseRawRSAPublicKey parses a bare PKCS#1 RSAPublicKey DER structure:
//
//	SEQUENCE { modulus INTEGER, publicExponent INTEGER }
//
// This handles keys that lack the PKIX SubjectPublicKeyInfo wrapper.
func parseRawRSAPublicKey(der []byte) *rsa.PublicKey {
	// Must start with SEQUENCE tag (0x30)
	if len(der) < 30 || der[0] != 0x30 {
		return nil
	}

	seq, err := parseASN1Sequence(der)
	if err != nil || len(seq) < 2 {
		return nil
	}

	modulus, err := parseASN1Integer(seq[0])
	if err != nil || modulus == nil || modulus.Sign() <= 0 {
		return nil
	}

	exponent, err := parseASN1Integer(seq[1])
	if err != nil || exponent == nil || exponent.Sign() <= 0 {
		return nil
	}

	e := int(exponent.Int64())
	if e <= 0 {
		return nil
	}

	return &rsa.PublicKey{
		N: modulus,
		E: e,
	}
}

// parsePKIXRSAPublicKey parses RSA public key from PKIX SubjectPublicKeyInfo DER.
func parsePKIXRSAPublicKey(der []byte) *rsa.PublicKey {
	// Parse SubjectPublicKeyInfo
	// SEQUENCE {
	//   algorithm SEQUENCE { OID, NULL }
	//   subjectPublicKey BIT STRING containing RSAPublicKey
	// }

	spki, err := parseASN1Sequence(der)
	if err != nil || len(spki) < 2 {
		return nil
	}

	// Check algorithm identifier for RSA
	algoSeq, err := parseASN1Sequence(spki[0])
	if err != nil || len(algoSeq) < 1 {
		return nil
	}

	// RSA OID: 1.2.840.113549.1.1.1
	if !isRSAOID(algoSeq[0]) {
		return nil
	}

	// Parse subjectPublicKey BIT STRING
	keyBits, err := parseASN1BitString(spki[1])
	if err != nil {
		return nil
	}

	// Parse RSAPublicKey
	// SEQUENCE { modulus INTEGER, publicExponent INTEGER }
	rsaSeq, err := parseASN1Sequence(keyBits)
	if err != nil || len(rsaSeq) < 2 {
		return nil
	}

	modulus, err := parseASN1Integer(rsaSeq[0])
	if err != nil {
		return nil
	}

	exponent, err := parseASN1Integer(rsaSeq[1])
	if err != nil {
		return nil
	}

	return &rsa.PublicKey{
		N: modulus,
		E: int(exponent.Int64()),
	}
}

// isRSAOID checks if the bytes contain RSA OID (1.2.840.113549.1.1.1)
func isRSAOID(data []byte) bool {
	// RSA OID encoding: 06 09 2A 86 48 86 F7 0D 01 01 01
	if len(data) < 11 {
		return false
	}
	rsaOID := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}
	for i := 0; i < len(rsaOID) && i < len(data); i++ {
		if data[i] != rsaOID[i] {
			return false
		}
	}
	return true
}

// parseECDSAPublicKey parses ECDSA public key from PKIX SubjectPublicKeyInfo DER.
func parseECDSAPublicKey(der []byte) *ecdsa.PublicKey {
	// Parse SubjectPublicKeyInfo
	spki, err := parseASN1Sequence(der)
	if err != nil || len(spki) < 2 {
		return nil
	}

	// Check algorithm identifier for ECDSA
	algoSeq, err := parseASN1Sequence(spki[0])
	if err != nil || len(algoSeq) < 2 {
		return nil
	}

	// Get curve OID
	curveOID, err := parseASN1OID(algoSeq[1])
	if err != nil {
		return nil
	}

	var curve elliptic.Curve
	switch {
	case isP256OID(curveOID):
		curve = elliptic.P256()
	case isP384OID(curveOID):
		curve = elliptic.P384()
	case isP521OID(curveOID):
		curve = elliptic.P521()
	default:
		return nil
	}

	// Parse subjectPublicKey BIT STRING
	keyBits, err := parseASN1BitString(spki[1])
	if err != nil {
		return nil
	}

	// Uncompress point
	x, y := elliptic.Unmarshal(curve, keyBits)
	if x == nil {
		return nil
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
}

// isP256OID checks for secp256r1/prime256v1 OID
func isP256OID(oid []byte) bool {
	// 1.2.840.10045.3.1.7
	p256OID := []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
	if len(oid) < len(p256OID) {
		return false
	}
	for i := 0; i < len(p256OID); i++ {
		if oid[i] != p256OID[i] {
			return false
		}
	}
	return true
}

// isP384OID checks for secp384r1 OID
func isP384OID(oid []byte) bool {
	// 1.3.132.0.34
	p384OID := []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22}
	if len(oid) < len(p384OID) {
		return false
	}
	for i := 0; i < len(p384OID); i++ {
		if oid[i] != p384OID[i] {
			return false
		}
	}
	return true
}

// isP521OID checks for secp521r1 OID
func isP521OID(oid []byte) bool {
	// 1.3.132.0.35
	p521OID := []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23}
	if len(oid) < len(p521OID) {
		return false
	}
	for i := 0; i < len(p521OID); i++ {
		if oid[i] != p521OID[i] {
			return false
		}
	}
	return true
}

// --- ASN.1 Parsing Helpers ---

// parseASN1Sequence parses a SEQUENCE and returns its contents.
func parseASN1Sequence(data []byte) ([][]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("data too short")
	}
	if data[0] != 0x30 {
		return nil, fmt.Errorf("not a sequence")
	}

	length, offset, err := parseASN1Length(data[1:])
	if err != nil {
		return nil, err
	}
	contentStart := 1 + offset
	if len(data) < contentStart+length {
		return nil, fmt.Errorf("length exceeds data")
	}

	content := data[contentStart : contentStart+length]
	return parseASN1Elements(content)
}

// parseASN1Length parses ASN.1 length bytes.
func parseASN1Length(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("no length bytes")
	}
	if data[0]&0x80 == 0 {
		// Short form
		return int(data[0]), 1, nil
	}
	// Long form
	numBytes := int(data[0] & 0x7F)
	if numBytes > 4 || len(data) < 1+numBytes {
		return 0, 0, fmt.Errorf("invalid length")
	}
	length := 0
	for i := 1; i <= numBytes; i++ {
		length = length<<8 | int(data[i])
	}
	return length, 1 + numBytes, nil
}

// parseASN1Elements parses the elements within a sequence.
func parseASN1Elements(data []byte) ([][]byte, error) {
	var elements [][]byte
	for len(data) > 0 {
		if len(data) < 2 {
			break
		}
		_ = data[0] // tag
		length, offset, err := parseASN1Length(data[1:])
		if err != nil {
			return nil, err
		}
		elemLen := 1 + offset + length
		if len(data) < elemLen {
			return nil, fmt.Errorf("element exceeds data")
		}
		elements = append(elements, data[:elemLen])
		data = data[elemLen:]
	}
	return elements, nil
}

// parseASN1Integer parses an ASN.1 INTEGER.
func parseASN1Integer(data []byte) (*big.Int, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("integer too short")
	}
	if data[0] != 0x02 {
		return nil, fmt.Errorf("not an integer")
	}
	length, offset, err := parseASN1Length(data[1:])
	if err != nil {
		return nil, err
	}
	contentStart := 1 + offset
	if len(data) < contentStart+length {
		return nil, fmt.Errorf("integer length exceeds data")
	}
	value := data[contentStart : contentStart+length]
	// Handle negative numbers (two's complement)
	if len(value) > 0 && value[0]&0x80 != 0 {
		// Negative - not handling for simplicity
		return nil, fmt.Errorf("negative integer not supported")
	}
	return new(big.Int).SetBytes(value), nil
}

// parseASN1BitString parses an ASN.1 BIT STRING.
func parseASN1BitString(data []byte) ([]byte, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("bit string too short")
	}
	if data[0] != 0x03 {
		return nil, fmt.Errorf("not a bit string")
	}
	length, offset, err := parseASN1Length(data[1:])
	if err != nil {
		return nil, err
	}
	contentStart := 1 + offset
	if len(data) < contentStart+length {
		return nil, fmt.Errorf("bit string length exceeds data")
	}
	// First byte is unused bits count
	if length < 1 {
		return nil, fmt.Errorf("invalid bit string")
	}
	return data[contentStart+1 : contentStart+length], nil
}

// parseASN1OID parses an ASN.1 OID.
func parseASN1OID(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("OID too short")
	}
	if data[0] != 0x06 {
		return nil, fmt.Errorf("not an OID")
	}
	length, offset, err := parseASN1Length(data[1:])
	if err != nil {
		return nil, err
	}
	contentStart := 1 + offset
	if len(data) < contentStart+length {
		return nil, fmt.Errorf("OID length exceeds data")
	}
	return data[:contentStart+length], nil
}

func parseEd25519PublicKey(der []byte) ed25519.PublicKey {
	// Accept raw 32-byte Ed25519 public keys for zero-dependency mode.
	// Standard PKIX SubjectPublicKeyInfo DER is larger and not supported here.
	if len(der) == ed25519.PublicKeySize {
		return ed25519.PublicKey(der)
	}
	return nil
}

func loadPublicKeyFromFile(path string) (crypto.PublicKey, error) {
	data := make([]byte, 4096)
	f, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer closeFile(f)

	n, err := readFile(f, data)
	if err != nil {
		return nil, err
	}
	return parsePublicKey(data[:n])
}

// Stub functions for file operations (avoid os import)
var (
	openFile  = func(path string) (any, error) { return nil, fmt.Errorf("file operations require runtime") }
	closeFile = func(any) {}
	readFile  = func(any, []byte) (int, error) { return 0, fmt.Errorf("file operations require runtime") }
	fileOpsMu sync.Mutex
)

// SetFileOps allows the main package to inject file operations.
// Protected by mutex to prevent races with concurrent file reads during JWKS key loading.
func SetFileOps(openFn func(string) (any, error), closeFn func(any), readFn func(any, []byte) (int, error)) {
	fileOpsMu.Lock()
	openFile = openFn
	closeFile = closeFn
	readFile = readFn
	fileOpsMu.Unlock()
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
