package apisecurity

// Regression for audit F155: a JWKS refresh used to be purely additive, so a
// key the issuer rotated out or revoked kept validating tokens forever.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func jwksRotationToken(t *testing.T, kid string, k *rsa.PrivateKey) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	p, _ := json.Marshal(JWTClaims{Subject: "u", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestJWKSRefreshEvictsRevokedKeys(t *testing.T) {
	oldKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := func(kid string, k *rsa.PublicKey) map[string]string {
		return map[string]string{"kid": kid, "kty": "RSA",
			"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())}
	}
	type resp struct {
		status int
		body   any
	}
	var cur atomic.Pointer[resp]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r := cur.Load()
		w.WriteHeader(r.status)
		_ = json.NewEncoder(w).Encode(r.body)
	}))
	defer srv.Close()
	set := func(status int, keys ...map[string]string) {
		if keys == nil {
			keys = []map[string]string{}
		}
		cur.Store(&resp{status, map[string]any{"keys": keys}})
	}
	v := &JWTValidator{config: JWTConfig{JWKSURL: srv.URL, Algorithms: []string{"RS256"}},
		jwksCache: &sync.Map{}, hmacKeys: &sync.Map{}, client: srv.Client(), ssrfChecked: true}
	ok := func(kid string, k *rsa.PrivateKey) bool {
		_, err := v.Validate(jwksRotationToken(t, kid, k))
		return err == nil
	}
	octKey := map[string]string{"kid": "hs", "kty": "oct", "k": base64.RawURLEncoding.EncodeToString([]byte("secret-oct"))}

	set(200, jwk("old", &oldKey.PublicKey), octKey)
	v.fetchJWKS()
	if !ok("old", oldKey) {
		t.Fatal("old key should validate initially")
	}
	// Edge 1: repeated identical refresh keeps the key.
	v.fetchJWKS()
	if !ok("old", oldKey) {
		t.Fatal("repeated refresh dropped a still-published key")
	}
	// Edge 2: non-200 response (even with a JWKS-shaped body) changes nothing.
	set(500, jwk("new", &newKey.PublicKey))
	v.fetchJWKS()
	if !ok("old", oldKey) || ok("new", newKey) {
		t.Fatal("error response altered the key set")
	}
	// Edge 3: a 200 set with no usable keys is treated as malformed.
	set(200)
	v.fetchJWKS()
	if !ok("old", oldKey) {
		t.Fatal("empty key set revoked all keys")
	}
	// Core: rotation evicts the revoked kid (RSA and oct) and admits the new one.
	set(200, jwk("new", &newKey.PublicKey))
	v.fetchJWKS()
	if !ok("new", newKey) {
		t.Fatal("new key rejected")
	}
	if ok("old", oldKey) {
		t.Fatal("revoked kid still validates")
	}
	if _, found := v.hmacKeys.Load("hs"); found {
		t.Fatal("revoked oct kid still cached")
	}
}
