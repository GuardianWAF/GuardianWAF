// Package acme implements an ACME client (RFC 8555) for automatic TLS certificate
// provisioning from Let's Encrypt or compatible CAs. Zero external dependencies.
package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Well-known ACME directory URLs.
const (
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Client is an ACME client that can register accounts, create orders,
// complete HTTP-01 challenges, and fetch certificates.
type Client struct {
	directoryURL string
	directory    *directory
	accountKey   *ecdsa.PrivateKey
	accountURL   string // kid (key ID) after registration
	httpClient   *http.Client
	mu           sync.Mutex
	nonces       []string // replay nonce pool
}

// directory holds the ACME directory endpoints.
type directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

// order represents an ACME order.
type order struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
}

// authorization represents an ACME authorization.
type authorization struct {
	Identifier struct {
		Value string `json:"value"`
	} `json:"identifier"`
	Status     string      `json:"status"`
	Challenges []challenge `json:"challenges"`
}

// challenge represents a single ACME challenge.
type challenge struct {
	Type  string `json:"type"`
	URL   string `json:"url"`
	Token string `json:"token"`
}

// NewClient creates a new ACME client.
// directoryURL should be LetsEncryptProduction or LetsEncryptStaging.
func NewClient(directoryURL string) *Client {
	return &Client{
		directoryURL: directoryURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Init fetches the ACME directory and generates or loads the account key.
func (c *Client) Init(accountKeyPEM []byte) error {
	// Fetch directory
	dir, err := c.fetchDirectory()
	if err != nil {
		return fmt.Errorf("fetching directory: %w", err)
	}
	c.directory = dir

	// Load or generate account key
	if len(accountKeyPEM) > 0 {
		block, _ := pem.Decode(accountKeyPEM)
		if block == nil {
			return fmt.Errorf("failed to decode account key PEM")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing account key: %w", err)
		}
		c.accountKey = key
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generating account key: %w", err)
		}
		c.accountKey = key
	}

	return nil
}

// AccountKeyPEM returns the account key in PEM format for saving.
func (c *Client) AccountKeyPEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(c.accountKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// Register registers or retrieves an ACME account.
func (c *Client) Register(email string) error {
	payload := map[string]any{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:" + email},
	}

	resp, err := c.signedPost(c.directory.NewAccount, payload, true)
	if err != nil {
		return fmt.Errorf("registering account: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("account registration failed (%d): %s", resp.StatusCode, body)
	}

	c.accountURL = resp.Header.Get("Location")
	return nil
}

// ObtainCertificate requests a certificate for the given domains using HTTP-01.
// The challengeHandler must serve tokens at /.well-known/acme-challenge/<token>.
func (c *Client) ObtainCertificate(domains []string, challengeHandler *HTTP01Handler) (certPEM, keyPEM []byte, err error) {
	// 1. Create order
	orderResp, orderURL, err := c.createOrder(domains)
	if err != nil {
		return nil, nil, fmt.Errorf("creating order: %w", err)
	}

	// 2. Complete authorizations
	for _, authzURL := range orderResp.Authorizations {
		if err := c.completeAuthorization(authzURL, challengeHandler); err != nil {
			return nil, nil, fmt.Errorf("authorization: %w", err)
		}
	}

	// 3. Generate certificate key + CSR
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating cert key: %w", err)
	}

	csr, err := createCSR(certKey, domains)
	if err != nil {
		return nil, nil, fmt.Errorf("creating CSR: %w", err)
	}

	// 4. Finalize order
	if err := c.finalizeOrder(orderResp.Finalize, csr); err != nil {
		return nil, nil, fmt.Errorf("finalizing order: %w", err)
	}

	// 5. Poll for certificate
	certPEM, err = c.pollCertificate(orderURL)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching certificate: %w", err)
	}

	// 6. Marshal private key
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// --- Internal methods ---

func (c *Client) fetchDirectory() (*directory, error) {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.directoryURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var dir directory
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		return nil, err
	}
	return &dir, nil
}

func (c *Client) createOrder(domains []string) (*order, string, error) {
	identifiers := make([]map[string]string, len(domains))
	for i, d := range domains {
		identifiers[i] = map[string]string{"type": "dns", "value": d}
	}
	payload := map[string]any{"identifiers": identifiers}

	resp, err := c.signedPost(c.directory.NewOrder, payload, false)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("create order failed (%d): %s", resp.StatusCode, body)
	}

	var o order
	if err := json.NewDecoder(resp.Body).Decode(&o); err != nil {
		return nil, "", err
	}
	return &o, resp.Header.Get("Location"), nil
}

func (c *Client) completeAuthorization(authzURL string, handler *HTTP01Handler) error {
	resp, err := c.signedPost(authzURL, nil, false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var authz authorization
	if err := json.NewDecoder(resp.Body).Decode(&authz); err != nil {
		return err
	}

	if authz.Status == "valid" {
		return nil // already validated
	}

	// Find HTTP-01 challenge
	var httpChallenge *challenge
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == "http-01" {
			httpChallenge = &authz.Challenges[i]
			break
		}
	}
	if httpChallenge == nil {
		return fmt.Errorf("no http-01 challenge for %s", authz.Identifier.Value)
	}

	// Compute key authorization
	thumbprint, err := c.jwkThumbprint()
	if err != nil {
		return err
	}
	keyAuth := httpChallenge.Token + "." + thumbprint

	// Provision the challenge response
	handler.SetToken(httpChallenge.Token, keyAuth)
	defer handler.ClearToken(httpChallenge.Token)

	// Respond to challenge
	challengeResp, err := c.signedPost(httpChallenge.URL, map[string]any{}, false)
	if err != nil {
		return err
	}
	challengeResp.Body.Close()

	// Poll authorization until valid or invalid
	for range 30 {
		time.Sleep(2 * time.Second)

		pollResp, err := c.signedPost(authzURL, nil, false)
		if err != nil {
			return err
		}

		var pollAuthz authorization
		if err := json.NewDecoder(pollResp.Body).Decode(&pollAuthz); err != nil {
			pollResp.Body.Close()
			return fmt.Errorf("failed to decode authorization response: %w", err)
		}
		pollResp.Body.Close()

		if pollAuthz.Status == "valid" {
			return nil
		}
		if pollAuthz.Status == "invalid" {
			return fmt.Errorf("authorization invalid for %s", authz.Identifier.Value)
		}
	}

	return fmt.Errorf("authorization timeout for %s", authz.Identifier.Value)
}

func (c *Client) finalizeOrder(finalizeURL string, csr []byte) error {
	payload := map[string]any{
		"csr": base64.RawURLEncoding.EncodeToString(csr),
	}
	resp, err := c.signedPost(finalizeURL, payload, false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("finalize failed (%d): %s", resp.StatusCode, body)
	}
	return nil
}

func (c *Client) pollCertificate(orderURL string) ([]byte, error) {
	for range 30 {
		time.Sleep(2 * time.Second)

		resp, err := c.signedPost(orderURL, nil, false)
		if err != nil {
			return nil, err
		}

		var o order
		if err := json.NewDecoder(resp.Body).Decode(&o); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode order response: %w", err)
		}
		resp.Body.Close()

		if o.Status == "valid" && o.Certificate != "" {
			return c.fetchCertificateChain(o.Certificate)
		}
		if o.Status == "invalid" {
			return nil, fmt.Errorf("order became invalid")
		}
	}
	return nil, fmt.Errorf("certificate poll timeout")
}

func (c *Client) fetchCertificateChain(certURL string) ([]byte, error) {
	resp, err := c.signedPost(certURL, nil, false)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// --- JWS signing ---

func (c *Client) getNonce() (string, error) {
	c.mu.Lock()
	if len(c.nonces) > 0 {
		n := c.nonces[len(c.nonces)-1]
		c.nonces = c.nonces[:len(c.nonces)-1]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.directory.NewNonce, http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	return resp.Header.Get("Replay-Nonce"), nil
}

func (c *Client) saveNonce(resp *http.Response) {
	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		c.mu.Lock()
		c.nonces = append(c.nonces, n)
		c.mu.Unlock()
	}
}

func (c *Client) signedPost(url string, payload any, useJWK bool) (*http.Response, error) {
	nonce, err := c.getNonce()
	if err != nil {
		return nil, fmt.Errorf("getting nonce: %w", err)
	}

	// Protected header
	header := map[string]any{
		"alg":   "ES256",
		"nonce": nonce,
		"url":   url,
	}
	if useJWK {
		header["jwk"] = c.jwk()
	} else {
		header["kid"] = c.accountURL
	}

	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Payload
	var payloadB64 string
	if payload != nil {
		payloadJSON, _ := json.Marshal(payload)
		payloadB64 = base64.RawURLEncoding.EncodeToString(payloadJSON)
	} else {
		payloadB64 = "" // POST-as-GET
	}

	// Sign
	sigInput := headerB64 + "." + payloadB64
	hash := sha256.Sum256([]byte(sigInput))
	r, s, err := ecdsa.Sign(rand.Reader, c.accountKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	// Encode signature (R || S, each 32 bytes for P-256)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	// JWS body
	jws := map[string]string{
		"protected": headerB64,
		"payload":   payloadB64,
		"signature": sigB64,
	}
	body, _ := json.Marshal(jws)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	c.saveNonce(resp)
	return resp, nil
}

func (c *Client) jwk() map[string]string {
	pub := c.accountKey.PublicKey
	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
	}
}

func (c *Client) jwkThumbprint() (string, error) {
	jwk := c.jwk()
	// Canonical JSON per RFC 7638
	canonical := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`,
		jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	hash := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// --- CSR ---

func createCSR(key crypto.Signer, domains []string) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}
	return x509.CreateCertificateRequest(rand.Reader, template, key)
}

// --- Helpers ---

// SplitDomains splits a comma-separated domain list and trims whitespace.
func SplitDomains(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// SerialNumber generates a random serial number for certificates.
func SerialNumber() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return n
}
