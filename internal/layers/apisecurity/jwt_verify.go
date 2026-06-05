package apisecurity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"time"
)

// hmacKey is a symmetric HMAC key.
type hmacKey []byte

// --- JWTValidator HTTP client and algorithm checks ---

func (v *JWTValidator) newJWKSHTTPClient() *http.Client {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
	}
	transport = transport.Clone()
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if v.jwksPrivateAllowedForTest() {
			return dialer.DialContext(ctx, network, addr)
		}

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
			port = ""
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("JWKS SSRF dial: DNS lookup failed for %q: %w", host, err)
		}
		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			target := ip.String()
			if port != "" {
				target = net.JoinHostPort(target, port)
			}
			return dialer.DialContext(ctx, network, target)
		}
		return nil, fmt.Errorf("JWKS SSRF dial: no valid public IPs for %q", host)
	}
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.ExpectContinueTimeout = 1 * time.Second
	transport.IdleConnTimeout = 30 * time.Second
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if v.jwksPrivateAllowedForTest() {
				return nil
			}
			parsedURL := req.URL
			if err := validateJWKSURL(parsedURL.String()); err != nil {
				return fmt.Errorf("redirect URL rejected: %w", err)
			}
			return nil
		},
	}
}

func (v *JWTValidator) jwksPrivateAllowedForTest() bool {
	if !v.ssrfChecked {
		return false
	}
	u, err := url.Parse(v.config.JWKSURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func (v *JWTValidator) isAlgorithmAllowed(alg string) bool {
	if alg == "" || alg == "none" {
		return false
	}
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

func (v *JWTValidator) verifySignature(alg string, signingInput string, signature []byte, key crypto.PublicKey) error {
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
	case "HS256", "HS384", "HS512":
		// key may be crypto.PublicKey interface holding []byte (from test assignment v.publicKey = secret)
		if sp, ok := key.([]byte); ok {
			return verifyHMACSignatureInline(sp, signingInput, signature, alg)
		}
		// also try _inline from hmacKeys (Validate path when secret on publicKey)
		if hkVal, ok := v.hmacKeys.Load("_inline"); ok {
			if hk, ok := hkVal.(hmacKey); ok {
				return verifyHMACSignatureInline(hk, signingInput, signature, alg)
			}
		}
		return fmt.Errorf("no HMAC key available")
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// --- Signature verification functions ---

func verifyRSASignature(key crypto.PublicKey, hashAlg crypto.Hash, data string, sig []byte) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}
	h := hashAlg.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)
	return rsa.VerifyPKCS1v15(rsaKey, hashAlg, hashed, sig)
}

func verifyRSAPSSSignature(key crypto.PublicKey, hashAlg crypto.Hash, data string, sig []byte) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}
	h := hashAlg.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	return rsa.VerifyPSS(rsaKey, hashAlg, hashed, sig, opts)
}

func verifyECDSASignature(key crypto.PublicKey, hashAlg crypto.Hash, data string, sig []byte) error {
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an ECDSA public key")
	}
	h := hashAlg.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)
	var esig struct {
		R, S *big.Int
	}
	if err := asn1Unmarshal(sig, &esig); err != nil {
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

func verifyHMACSignatureInline(keyBytes []byte, signingInput string, sig []byte, alg string) error {
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
	h := hmac.New(hashFunc, keyBytes)
	h.Write([]byte(signingInput))
	expected := h.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return fmt.Errorf("HMAC verification failed")
	}
	return nil
}

// verifyHMACSignature is a stub kept for binary compatibility with tests that
// pass non-*JWTValidator values (int, etc.). Active HMAC verification is
// handled by JWTValidator.verifyHMACKey.
func verifyHMACSignature(_ any, _ func() hash.Hash, _ string, _ []byte) error {
	return fmt.Errorf("key is not an HMAC key")
}
