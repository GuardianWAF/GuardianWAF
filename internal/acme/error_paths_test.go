package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func testErrorClient(t *testing.T, rt http.RoundTripper) *Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Client{
		accountKey: key,
		accountURL: "https://ca.test/account/1",
		directory: &directory{
			NewNonce:   "https://ca.test/nonce",
			NewAccount: "https://ca.test/account",
			NewOrder:   "https://ca.test/order",
		},
		httpClient:  &http.Client{Transport: rt},
		pollTimeout: time.Second,
		nonces:      []string{"nonce"},
	}
}

func response(status int, body io.Reader) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(body)}
}

func TestClientTransportErrorPaths(t *testing.T) {
	errTransport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport failed")
	})

	t.Run("register", func(t *testing.T) {
		c := testErrorClient(t, errTransport)
		if err := c.Register("ops@example.test"); err == nil {
			t.Fatal("expected register transport error")
		}
	})
	t.Run("create order", func(t *testing.T) {
		c := testErrorClient(t, errTransport)
		if _, _, err := c.createOrder([]string{"example.test"}); err == nil {
			t.Fatal("expected create order transport error")
		}
	})
	t.Run("signed post", func(t *testing.T) {
		c := testErrorClient(t, errTransport)
		if _, err := c.signedPost("https://ca.test/order", nil, false); err == nil {
			t.Fatal("expected signed post transport error")
		}
	})
}

func TestObtainCertificateWrappedErrorPaths(t *testing.T) {
	t.Run("authorization", func(t *testing.T) {
		calls := 0
		c := testErrorClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				r := response(http.StatusCreated, strings.NewReader(`{"status":"pending","authorizations":["https://ca.test/authz"],"finalize":"https://ca.test/finalize"}`))
				r.Header.Set("Location", "https://ca.test/order/1")
				r.Header.Set("Replay-Nonce", "next")
				return r, nil
			}
			return nil, errors.New("authorization transport failed")
		}))
		if _, _, err := c.ObtainCertificate([]string{"example.test"}, NewHTTP01Handler()); err == nil || !strings.Contains(err.Error(), "authorization") {
			t.Fatalf("expected wrapped authorization error, got %v", err)
		}
	})

	t.Run("certificate polling", func(t *testing.T) {
		calls := 0
		c := testErrorClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			var body string
			var status = http.StatusOK
			switch calls {
			case 1:
				status = http.StatusCreated
				body = `{"status":"pending","finalize":"https://ca.test/finalize"}`
			case 2:
				body = `{}`
			default:
				return nil, errors.New("poll transport failed")
			}
			r := response(status, strings.NewReader(body))
			r.Header.Set("Replay-Nonce", fmt.Sprintf("nonce-%d", calls))
			if calls == 1 {
				r.Header.Set("Location", "https://ca.test/order/1")
			}
			return r, nil
		}))
		old := acmePollInterval
		acmePollInterval = time.Nanosecond
		defer func() { acmePollInterval = old }()
		if _, _, err := c.ObtainCertificate([]string{"example.test"}, NewHTTP01Handler()); err == nil || !strings.Contains(err.Error(), "fetching certificate") {
			t.Fatalf("expected wrapped certificate error, got %v", err)
		}
	})
}

func TestAuthorizationPollingErrorPaths(t *testing.T) {
	tests := []struct {
		name string
		body io.Reader
		want string
	}{
		{name: "read", body: failingReader{}, want: "failed to decode authorization response"},
		{name: "decode", body: strings.NewReader("not json"), want: "failed to decode authorization response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			c := testErrorClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				var body io.Reader
				switch calls {
				case 1:
					body = strings.NewReader(`{"status":"pending","identifier":{"value":"example.test"},"challenges":[{"type":"http-01","url":"https://ca.test/challenge","token":"token"}]}`)
				case 2:
					body = strings.NewReader(`{}`)
				default:
					body = tt.body
				}
				r := response(http.StatusOK, body)
				r.Header.Set("Replay-Nonce", fmt.Sprintf("nonce-%d", calls))
				return r, nil
			}))
			old := acmePollInterval
			acmePollInterval = time.Nanosecond
			defer func() { acmePollInterval = old }()
			if err := c.completeAuthorization("https://ca.test/authz", NewHTTP01Handler()); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q, got %v", tt.want, err)
			}
		})
	}
}

func TestPollingTerminalFallthroughs(t *testing.T) {
	old := acmePollInterval
	acmePollInterval = time.Nanosecond
	defer func() { acmePollInterval = old }()

	t.Run("authorization", func(t *testing.T) {
		calls := 0
		c := testErrorClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			body := `{}`
			if calls == 1 {
				body = `{"status":"pending","identifier":{"value":"example.test"},"challenges":[{"type":"http-01","url":"https://ca.test/challenge","token":"token"}]}`
			}
			r := response(http.StatusOK, strings.NewReader(body))
			r.Header.Set("Replay-Nonce", fmt.Sprintf("nonce-%d", calls))
			return r, nil
		}))
		if err := c.completeAuthorization("https://ca.test/authz", NewHTTP01Handler()); err == nil || !strings.Contains(err.Error(), "authorization timeout for") {
			t.Fatalf("expected terminal authorization timeout, got %v", err)
		}
	})

	t.Run("certificate", func(t *testing.T) {
		c := testErrorClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			r := response(http.StatusOK, strings.NewReader(`{"status":"processing"}`))
			r.Header.Set("Replay-Nonce", "next")
			return r, nil
		}))
		if _, err := c.pollCertificate("https://ca.test/order/1"); err == nil || !strings.Contains(err.Error(), "certificate poll timeout") {
			t.Fatalf("expected terminal certificate timeout, got %v", err)
		}
	})
}

func TestStoreCertificateErrorPaths(t *testing.T) {
	var seamMu sync.Mutex
	seamMu.Lock()
	defer seamMu.Unlock()

	t.Run("new cert load", func(t *testing.T) {
		dir := t.TempDir()
		old := loadX509KeyPair
		calls := 0
		loadX509KeyPair = func(certFile, keyFile string) (tls.Certificate, error) {
			calls++
			return tls.Certificate{}, errors.New("load failed")
		}
		defer func() { loadX509KeyPair = old }()
		certPEM, keyPEM := generateSelfSignedCert(t, "new.example.test")
		// Use a client that will store the cert files
		httpClient := successfulObtainClient(t, certPEM, keyPEM)
		store := NewCertDiskStore(dir, httpClient, NewHTTP01Handler())
		if _, err := store.LoadOrObtain([]string{"new.example.test"}); err == nil {
			t.Fatalf("expected error, got nil (calls %d)", calls)
		}
	})
}

func successfulObtainClient(t *testing.T, certPEM, _ []byte) *Client {
	t.Helper()
	calls := 0
	return testErrorClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		status := http.StatusOK
		body := `{}`
		switch calls {
		case 1:
			status = http.StatusCreated
			body = `{"status":"pending","finalize":"https://ca.test/finalize"}`
		case 2:
			body = `{}`
		case 3:
			body = `{"status":"valid","certificate":"https://ca.test/cert"}`
		case 4:
			body = string(certPEM)
		}
		r := response(status, strings.NewReader(body))
		r.Header.Set("Replay-Nonce", fmt.Sprintf("nonce-%d", calls))
		if calls == 1 {
			r.Header.Set("Location", "https://ca.test/order/1")
		}
		return r, nil
	}))
}

func TestCertStatusIssuerWithoutComma(t *testing.T) {
	store := NewCertDiskStore(t.TempDir(), nil, nil)
	store.storeCert([]string{"issuer.example.test"}, &tls.Certificate{Leaf: &x509.Certificate{Issuer: pkixName("OnlyIssuer"), NotAfter: time.Now().Add(time.Hour)}})
	status := store.CertStatus()
	certs := status["certs"].([]map[string]any)
	if certs[0]["issuer_cn"] != "OnlyIssuer" {
		t.Fatalf("issuer_cn = %v", certs[0]["issuer_cn"])
	}
}

func pkixName(cn string) pkix.Name { return pkix.Name{CommonName: cn} }
