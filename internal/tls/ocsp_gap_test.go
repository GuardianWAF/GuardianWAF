package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func testIssuerCert(t *testing.T) *x509.Certificate {
	t.Helper()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "OCSP Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("creating issuer cert: %v", err)
	}

	issuerCert, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parsing issuer cert: %v", err)
	}

	return issuerCert
}

func TestNewOCSPHTTPClient_DefaultTransportFallback(t *testing.T) {
	oldDefaultTransport := http.DefaultTransport
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, nil
	})
	defer func() {
		http.DefaultTransport = oldDefaultTransport
	}()

	client := newOCSPHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.DialContext == nil {
		t.Fatal("expected fallback transport to configure DialContext")
	}
}

func TestOCSPPublicOnlyDialContext_DNSLookupFailure(t *testing.T) {
	dialContext := ocspPublicOnlyDialContext(&net.Dialer{})

	_, err := dialContext(context.Background(), "tcp", "nonexistent-ocsp-host.invalid:80")
	if err == nil {
		t.Fatal("expected DNS lookup failure")
	}
	if !strings.Contains(err.Error(), `DNS lookup failed for "nonexistent-ocsp-host.invalid"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOCSPPublicOnlyDialContext_NoValidPublicIPsWithoutPort(t *testing.T) {
	dialContext := ocspPublicOnlyDialContext(&net.Dialer{})

	_, err := dialContext(context.Background(), "tcp", "localhost")
	if err == nil {
		t.Fatal("expected localhost dial to be rejected")
	}
	if !strings.Contains(err.Error(), `no valid public IPs for "localhost"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOCSPPublicOnlyDialContext_PublicIPDialAttempt(t *testing.T) {
	dialContext := ocspPublicOnlyDialContext(&net.Dialer{Timeout: 50 * time.Millisecond})

	_, err := dialContext(context.Background(), "tcp", "1.1.1.1:0")
	if err == nil {
		t.Fatal("expected dial attempt to fail")
	}
	if strings.Contains(err.Error(), "DNS lookup failed") || strings.Contains(err.Error(), "no valid public IPs") {
		t.Fatalf("expected public-IP dial path error, got %v", err)
	}
}

func TestParseAIAOCSP_MalformedRemainingSequence(t *testing.T) {
	data := []byte{0x30, 0x03, 0xff, 0xff, 0xff}
	if got := parseAIAOCSP(data); got != "" {
		t.Fatalf("expected empty result for malformed sequence, got %q", got)
	}
}

func TestBuildOCSPRequest_NilSerialNumber(t *testing.T) {
	issuer := testIssuerCert(t)
	leaf := &x509.Certificate{SerialNumber: nil}

	_, err := buildOCSPRequest(issuer, leaf)
	if err == nil {
		t.Fatal("expected buildOCSPRequest to fail for nil serial number")
	}
}

func TestParseAIAOCSP_PrimarySequencePath(t *testing.T) {
	want := "http://ocsp.primary.example"
	if got := parseAIAOCSP(extraBuildAIADescription(want)); got != want {
		t.Fatalf("parseAIAOCSP() = %q, want %q", got, want)
	}
}

func TestParseAIAOCSP_NonOCSPDescription(t *testing.T) {
	caIssuersOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
	name := asn1.RawValue{FullBytes: []byte{0x86, 0x16, 'h', 't', 't', 'p', ':', '/', '/', 'n', 'o', 't', '-', 'o', 'c', 's', 'p', '.', 't', 'e', 's', 't'}}
	desc := struct {
		OID  asn1.ObjectIdentifier
		Name asn1.RawValue
	}{
		OID:  caIssuersOID,
		Name: name,
	}
	descBytes, err := asn1.Marshal(desc)
	if err != nil {
		t.Fatalf("marshal access description: %v", err)
	}
	data, err := asn1.Marshal([]asn1.RawValue{{FullBytes: descBytes}})
	if err != nil {
		t.Fatalf("marshal AIA sequence: %v", err)
	}

	if got := parseAIAOCSP(data); got != "" {
		t.Fatalf("expected empty result for non-OCSP description, got %q", got)
	}
}
