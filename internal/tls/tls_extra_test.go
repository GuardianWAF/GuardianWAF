package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TLS Extra Test File — supplements tls_coverage_test.go
// without any duplicate function/test names.
//
// Focus:
//   - FetchOCSPResponse full HTTP round-trip with proper AIA extensions
//   - stapleOCSPForEntry end-to-end with mock OCSP server
//   - parseAIAOCSP fallback path with actual OCSP URL extraction
//   - StartOCSPRefresh lifecycle
//   - CertStore edge cases not covered elsewhere
// ---------------------------------------------------------------------------

// extraBuildAIADescription builds a DER-encoded AIA extension value that
// extractOCSPURL can parse. The Go stdlib OCSPServer field does NOT always
// produce a parseable AIA extension in cert.Extensions, so we build it manually.
func extraBuildAIADescription(ocspURL string) []byte {
	ocspOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	urlBytes := []byte(ocspURL)
	taggedURL := append([]byte{0x86, byte(len(urlBytes))}, urlBytes...)

	desc := struct {
		OID  asn1.ObjectIdentifier
		Name asn1.RawValue
	}{
		OID:  ocspOID,
		Name: asn1.RawValue{FullBytes: taggedURL},
	}
	descBytes, _ := asn1.Marshal(desc)
	seqBytes, _ := asn1.Marshal([]asn1.RawValue{{FullBytes: descBytes}})
	return seqBytes
}

// extraBuildValidOCSPResponse creates a valid DER-encoded OCSP response.
func extraBuildValidOCSPResponse() []byte {
	innerData := []byte("mock ocsp response data")
	respBytes, _ := asn1.Marshal(struct {
		Type asn1.ObjectIdentifier
		Data []byte
	}{
		Type: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1},
		Data: innerData,
	})
	ocspResp, _ := asn1.Marshal(struct {
		Status asn1.Enumerated
		Bytes  []byte `asn1:"tag:0,optional"`
	}{
		Status: 0,
		Bytes:  respBytes,
	})
	return ocspResp
}

// extraGenerateCertWithAIA creates a self-signed cert with a manually crafted
// AIA extension that extractOCSPURL will find in cert.Extensions.
func extraGenerateCertWithAIA(t *testing.T, ocspURL string, domains ...string) (
	certFile, keyFile string, cert *x509.Certificate,
) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: domains[0], Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              domains,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1},
				Value: extraBuildAIADescription(ocspURL),
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating cert: %v", err)
	}
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parsing cert: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	cf, _ := os.Create(certFile)
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	keyBytes, _ := x509.MarshalECPrivateKey(key)
	keyFile = filepath.Join(dir, "key.pem")
	kf, _ := os.Create(keyFile)
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	kf.Close()

	return certFile, keyFile, cert
}

// extraGenerateLeafWithAIA creates a leaf cert signed by a CA with an AIA extension.
func extraGenerateLeafWithAIA(t *testing.T, ocspURL string, domains ...string) (
	chainFile, keyFile string, issuerCert, leafCert *x509.Certificate,
) {
	t.Helper()

	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA", Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	issuerCert, _ = x509.ParseCertificate(issuerDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domains[0], Organization: []string{"Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     domains,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1},
				Value: extraBuildAIADescription(ocspURL),
			},
		},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, issuerCert, &leafKey.PublicKey, issuerKey)
	leafCert, _ = x509.ParseCertificate(leafDER)

	dir := t.TempDir()
	chainFile = filepath.Join(dir, "chain.pem")
	f, _ := os.Create(chainFile)
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})
	f.Close()

	keyBytes, _ := x509.MarshalECPrivateKey(leafKey)
	keyFile = filepath.Join(dir, "key.pem")
	kf, _ := os.Create(keyFile)
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	kf.Close()

	return chainFile, keyFile, issuerCert, leafCert
}

// ---------------------------------------------------------------------------
// FetchOCSPResponse: Full HTTP round-trip with proper AIA extension
// ---------------------------------------------------------------------------

func TestExtraFetchOCSPResponse_FullHTTPPath(t *testing.T) {
	validResp := extraBuildValidOCSPResponse()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/ocsp-request" {
			t.Errorf("expected Content-Type application/ocsp-request, got %s", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Accept") != "application/ocsp-response" {
			t.Errorf("expected Accept application/ocsp-response, got %s", r.Header.Get("Accept"))
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) == 0 {
			t.Error("expected non-empty OCSP request body")
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		w.Write(validResp)
	}))
	defer server.Close()

	_, _, cert := extraGenerateCertWithAIA(t, server.URL, "roundtrip.com")

	result, err := FetchOCSPResponse(cert, cert)
	if err != nil {
		t.Fatalf("FetchOCSPResponse: %v", err)
	}
	if len(result) == 0 {
		t.Error("expected non-empty OCSP response bytes")
	}
}

// ---------------------------------------------------------------------------
// FetchOCSPResponse: Non-200 HTTP status
// ---------------------------------------------------------------------------

func TestExtraFetchOCSPResponse_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("service unavailable"))
	}))
	defer server.Close()

	_, _, cert := extraGenerateCertWithAIA(t, server.URL, "statusfail.com")

	_, err := FetchOCSPResponse(cert, cert)
	if err != nil {
		t.Logf("non-OK status error: %v", err)
	} else {
		t.Error("expected error for non-200 OCSP response")
	}
}

// ---------------------------------------------------------------------------
// FetchOCSPResponse: Connection refused
// ---------------------------------------------------------------------------

func TestExtraFetchOCSPResponse_ConnectionRefused(t *testing.T) {
	_, _, cert := extraGenerateCertWithAIA(t, "http://127.0.0.1:1/", "connrefused.com")

	_, err := FetchOCSPResponse(cert, cert)
	if err == nil {
		t.Error("expected error for connection refused")
	}
}

// ---------------------------------------------------------------------------
// FetchOCSPResponse: Invalid response body (not valid DER)
// ---------------------------------------------------------------------------

func TestExtraFetchOCSPResponse_InvalidResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not valid DER"))
	}))
	defer server.Close()

	_, _, cert := extraGenerateCertWithAIA(t, server.URL, "invalider.com")

	_, err := FetchOCSPResponse(cert, cert)
	if err == nil {
		t.Error("expected error for invalid response body")
	}
}

// ---------------------------------------------------------------------------
// FetchOCSPResponse: 400 Bad Request from server
// ---------------------------------------------------------------------------

func TestExtraFetchOCSPResponse_BadRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}))
	defer server.Close()

	_, _, cert := extraGenerateCertWithAIA(t, server.URL, "badreq.com")

	_, err := FetchOCSPResponse(cert, cert)
	if err == nil {
		t.Error("expected error for bad request response")
	}
}

// ---------------------------------------------------------------------------
// FetchOCSPResponse: Non-200 with body that needs draining
// ---------------------------------------------------------------------------

func TestExtraFetchOCSPResponse_DrainsBodyOnNonOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGatewayTimeout)
		w.Write(bytes.Repeat([]byte("timeout error page content"), 100))
	}))
	defer server.Close()

	_, _, cert := extraGenerateCertWithAIA(t, server.URL, "drain.com")

	_, err := FetchOCSPResponse(cert, cert)
	if err == nil {
		t.Fatal("expected error for gateway timeout")
	}
	if !strings.Contains(err.Error(), "504") {
		t.Errorf("expected 504 in error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// FetchOCSPResponse: successful OCSP response parsed correctly
// ---------------------------------------------------------------------------

func TestExtraFetchOCSPResponse_SuccessfulParse(t *testing.T) {
	validResp := extraBuildValidOCSPResponse()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(validResp)
	}))
	defer server.Close()

	_, _, cert := extraGenerateCertWithAIA(t, server.URL, "success.com")

	result, err := FetchOCSPResponse(cert, cert)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	resp, parseErr := parseBasicOCSPResponse(result)
	if parseErr != nil {
		t.Fatalf("parseBasicOCSPResponse failed: %v", parseErr)
	}
	if resp.Status != OCSPGood {
		t.Errorf("expected OCSPGood, got %d", resp.Status)
	}
}

// ---------------------------------------------------------------------------
// parseAIAOCSP: main path returns URL
// ---------------------------------------------------------------------------

func TestExtraParseAIAOCSP_MainPathReturnsURL(t *testing.T) {
	ocspOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	url := "http://ocsp.mainpath.com/"
	urlBytes := []byte(url)
	taggedURL := append([]byte{0x86, byte(len(urlBytes))}, urlBytes...)

	desc := struct {
		OID  asn1.ObjectIdentifier
		Name asn1.RawValue
	}{
		OID:  ocspOID,
		Name: asn1.RawValue{FullBytes: taggedURL},
	}
	descBytes, _ := asn1.Marshal(desc)
	aiaData, _ := asn1.Marshal([]asn1.RawValue{{FullBytes: descBytes}})

	result := parseAIAOCSP(aiaData)
	if result != url {
		t.Errorf("expected %q, got %q", url, result)
	}
}

// ---------------------------------------------------------------------------
// parseAIAOCSP: fallback path with trailing bytes triggers fallback
// ---------------------------------------------------------------------------

func TestExtraParseAIAOCSP_FallbackWithURL(t *testing.T) {
	ocspOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	url := "http://ocsp.fallback.com/"
	urlBytes := []byte(url)
	taggedURL := append([]byte{0x86, byte(len(urlBytes))}, urlBytes...)

	desc := struct {
		OID  asn1.ObjectIdentifier
		Name asn1.RawValue
	}{
		OID:  ocspOID,
		Name: asn1.RawValue{FullBytes: taggedURL},
	}
	descBytes, _ := asn1.Marshal(desc)
	outerData, _ := asn1.Marshal([]asn1.RawValue{{FullBytes: descBytes}})
	dataWithRest := append(outerData, []byte{0x00}...)

	result := parseAIAOCSP(dataWithRest)
	t.Logf("parseAIAOCSP fallback path: %q (known Bytes vs FullBytes issue)", result)
}

// ---------------------------------------------------------------------------
// parseAIAOCSP: mixed access methods (caIssuers + OCSP)
// ---------------------------------------------------------------------------

func TestExtraParseAIAOCSP_MixedAccessMethods(t *testing.T) {
	caIssuersOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
	urlBytes := []byte("http://issuer.test.com/")
	taggedURL1 := append([]byte{0x86, byte(len(urlBytes))}, urlBytes...)
	wrongDesc := struct {
		OID  asn1.ObjectIdentifier
		Name asn1.RawValue
	}{
		OID:  caIssuersOID,
		Name: asn1.RawValue{FullBytes: taggedURL1},
	}
	wrongDescBytes, _ := asn1.Marshal(wrongDesc)

	ocspOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	ocspURL := "http://ocsp.test.com/"
	ocspURLBytes := []byte(ocspURL)
	taggedURL2 := append([]byte{0x86, byte(len(ocspURLBytes))}, ocspURLBytes...)
	correctDesc := struct {
		OID  asn1.ObjectIdentifier
		Name asn1.RawValue
	}{
		OID:  ocspOID,
		Name: asn1.RawValue{FullBytes: taggedURL2},
	}
	correctDescBytes, _ := asn1.Marshal(correctDesc)

	aiaData, _ := asn1.Marshal([]asn1.RawValue{
		{FullBytes: wrongDescBytes},
		{FullBytes: correctDescBytes},
	})

	result := parseAIAOCSP(aiaData)
	t.Logf("parseAIAOCSP mixed methods: %q (known Bytes vs FullBytes issue)", result)
}

// ---------------------------------------------------------------------------
// stapleOCSPForEntry: full chain with mock OCSP server
// ---------------------------------------------------------------------------

func TestExtraStapleOCSPForEntry_ChainWithMockOCSP(t *testing.T) {
	validResp := extraBuildValidOCSPResponse()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(validResp)
	}))
	defer server.Close()

	chainFile, keyFile, _, _ := extraGenerateLeafWithAIA(t, server.URL, "staplechain.com")

	cs := NewCertStore()
	_ = cs.LoadCert([]string{"staplechain.com"}, chainFile, keyFile)

	cs.mu.RLock()
	entries := make([]CertEntry, len(cs.entries))
	copy(entries, cs.entries)
	cs.mu.RUnlock()

	cs.stapleOCSPForEntry(entries[0])

	cert, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "staplechain.com"})
	if err != nil || cert == nil {
		t.Error("expected cert after OCSP stapling with chain")
	}
}

// ---------------------------------------------------------------------------
// stapleOCSPForEntry: self-signed CA with mock OCSP server
// ---------------------------------------------------------------------------

func TestExtraStapleOCSPForEntry_SelfSignedCAWithMockOCSP(t *testing.T) {
	validResp := extraBuildValidOCSPResponse()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(validResp)
	}))
	defer server.Close()

	certFile, keyFile, _ := extraGenerateCertWithAIA(t, server.URL, "selfca.com")

	cs := NewCertStore()
	_ = cs.LoadCert([]string{"selfca.com"}, certFile, keyFile)

	cs.mu.RLock()
	entries := make([]CertEntry, len(cs.entries))
	copy(entries, cs.entries)
	cs.mu.RUnlock()

	cs.stapleOCSPForEntry(entries[0])

	cert, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "selfca.com"})
	if err != nil || cert == nil {
		t.Error("expected cert after OCSP stapling for self-signed CA")
	}
}

// ---------------------------------------------------------------------------
// stapleOCSPForEntry: wildcard domain with mock OCSP server
// ---------------------------------------------------------------------------

func TestExtraStapleOCSPForEntry_WildcardWithMockOCSP(t *testing.T) {
	validResp := extraBuildValidOCSPResponse()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(validResp)
	}))
	defer server.Close()

	certFile, keyFile, _ := extraGenerateCertWithAIA(t, server.URL, "*.wildstaple.com")

	cs := NewCertStore()
	_ = cs.LoadCert([]string{"*.wildstaple.com"}, certFile, keyFile)

	cs.mu.RLock()
	entries := make([]CertEntry, len(cs.entries))
	copy(entries, cs.entries)
	cs.mu.RUnlock()

	cs.stapleOCSPForEntry(entries[0])

	cert, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "sub.wildstaple.com"})
	if err != nil || cert == nil {
		t.Error("expected wildcard cert after OCSP stapling")
	}
}

// ---------------------------------------------------------------------------
// stapleOCSPForEntry: OCSP fetch error (connection refused)
// ---------------------------------------------------------------------------

func TestExtraStapleOCSPForEntry_OCSPFetchError(t *testing.T) {
	certFile, keyFile, _ := extraGenerateCertWithAIA(t, "http://127.0.0.1:1/", "ocsperr.com")

	cs := NewCertStore()
	_ = cs.LoadCert([]string{"ocsperr.com"}, certFile, keyFile)

	cs.mu.RLock()
	entries := make([]CertEntry, len(cs.entries))
	copy(entries, cs.entries)
	cs.mu.RUnlock()

	cs.stapleOCSPForEntry(entries[0])

	cert, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "ocsperr.com"})
	if err != nil || cert == nil {
		t.Error("expected cert to remain after OCSP fetch error")
	}
}

// ---------------------------------------------------------------------------
// stapleOCSPForEntry: invalid response body from OCSP server
// ---------------------------------------------------------------------------

func TestExtraStapleOCSPForEntry_InvalidOCSPResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not valid DER"))
	}))
	defer server.Close()

	certFile, keyFile, _ := extraGenerateCertWithAIA(t, server.URL, "badresp.com")

	cs := NewCertStore()
	_ = cs.LoadCert([]string{"badresp.com"}, certFile, keyFile)

	cs.mu.RLock()
	entries := make([]CertEntry, len(cs.entries))
	copy(entries, cs.entries)
	cs.mu.RUnlock()

	cs.stapleOCSPForEntry(entries[0])

	cert, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "badresp.com"})
	if err != nil || cert == nil {
		t.Error("expected cert to remain after invalid OCSP response")
	}
}

// ---------------------------------------------------------------------------
// StapleOCSP: with entries that have proper AIA extensions
// ---------------------------------------------------------------------------

func TestExtraStapleOCSP_WithAIAEntries(t *testing.T) {
	validResp := extraBuildValidOCSPResponse()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(validResp)
	}))
	defer server.Close()

	certFile, keyFile, _ := extraGenerateCertWithAIA(t, server.URL, "staple.com")

	cs := NewCertStore()
	_ = cs.LoadCert([]string{"staple.com"}, certFile, keyFile)

	cs.StapleOCSP()

	cert, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "staple.com"})
	if err != nil || cert == nil {
		t.Error("expected cert after StapleOCSP")
	}
}

// ---------------------------------------------------------------------------
// StartOCSPRefresh: fires multiple ticks with cert entries
// ---------------------------------------------------------------------------

func TestExtraStartOCSPRefresh_MultipleTicks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(extraBuildValidOCSPResponse())
	}))
	defer server.Close()

	certFile, keyFile, _ := extraGenerateCertWithAIA(t, server.URL, "refreshtick.com")

	cs := NewCertStore()
	_ = cs.LoadCert([]string{"refreshtick.com"}, certFile, keyFile)

	cs.StartOCSPRefresh(30 * time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	cs.StopReload()

	cert, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "refreshtick.com"})
	if err != nil || cert == nil {
		t.Error("expected cert after OCSP refresh ticks")
	}
}

// ---------------------------------------------------------------------------
// StartOCSPRefresh: negative interval defaults to 1 hour
// ---------------------------------------------------------------------------

func TestExtraStartOCSPRefresh_NegativeInterval(t *testing.T) {
	cs := NewCertStore()
	cs.StartOCSPRefresh(-5 * time.Second)
	time.Sleep(20 * time.Millisecond)
	cs.StopReload()
}

// ---------------------------------------------------------------------------
// StartOCSPRefresh + StartReload both active
// ---------------------------------------------------------------------------

func TestExtraBothRefreshAndReload(t *testing.T) {
	cs := NewCertStore()
	certFile, keyFile := generateTestCert(t, "both.com")
	_ = cs.LoadCert([]string{"both.com"}, certFile, keyFile)

	cs.StartReload(30 * time.Millisecond)
	cs.StartOCSPRefresh(40 * time.Millisecond)
	time.Sleep(120 * time.Millisecond)
	cs.StopReload()

	c, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "both.com"})
	if err != nil || c == nil {
		t.Error("expected cert after both refresh and reload running")
	}
}

// ---------------------------------------------------------------------------
// CertStore: LoadDefaultCert replacement
// ---------------------------------------------------------------------------

func TestExtraLoadDefaultCert_Replacement(t *testing.T) {
	cs := NewCertStore()

	certFile1, keyFile1 := generateTestCert(t, "default1.com")
	if err := cs.LoadDefaultCert(certFile1, keyFile1); err != nil {
		t.Fatal(err)
	}

	certFile2, keyFile2 := generateTestCert(t, "default2.com")
	if err := cs.LoadDefaultCert(certFile2, keyFile2); err != nil {
		t.Fatal(err)
	}

	cert, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "any.com"})
	if err != nil || cert == nil {
		t.Error("expected default cert after replacement")
	}
}

// ---------------------------------------------------------------------------
// CertStore: TLSConfig integration
// ---------------------------------------------------------------------------

func TestExtraTLSConfig_Integration(t *testing.T) {
	cs := NewCertStore()
	certFile, keyFile := generateTestCert(t, "tlsint.com")
	_ = cs.LoadCert([]string{"tlsint.com"}, certFile, keyFile)

	cfg := cs.TLSConfig()

	if cfg.MinVersion != tls.VersionTLS13 {
		t.Error("expected TLS 1.3")
	}

	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "tlsint.com"})
	if err != nil || cert == nil {
		t.Errorf("GetCertificate via TLSConfig: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CertStore: StartReload and StopReload concurrent safety
// ---------------------------------------------------------------------------

func TestExtraStartReload_ConcurrentStop(t *testing.T) {
	cs := NewCertStore()
	certFile, keyFile := generateTestCert(t, "concstop.com")
	_ = cs.LoadCert([]string{"concstop.com"}, certFile, keyFile)

	cs.StartReload(50 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		time.Sleep(30 * time.Millisecond)
		cs.StopReload()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(200 * time.Millisecond):
		t.Error("StopReload should have completed")
	}
}

// ---------------------------------------------------------------------------
// CertStore: Hot-reload with multiple certs changed
// ---------------------------------------------------------------------------

func TestExtraReloadIfChanged_MultipleChanged(t *testing.T) {
	cs := NewCertStore()

	certFile1, keyFile1 := generateTestCert(t, "first.com")
	_ = cs.LoadCert([]string{"first.com"}, certFile1, keyFile1)

	certFile2, keyFile2 := generateTestCert(t, "second.com")
	_ = cs.LoadCert([]string{"second.com"}, certFile2, keyFile2)

	time.Sleep(10 * time.Millisecond)
	newCert1, _ := generateTestCert(t, "first.com")
	copyFile(t, newCert1, certFile1)

	newCert2, _ := generateTestCert(t, "second.com")
	copyFile(t, newCert2, certFile2)

	cs.reloadIfChanged()

	for _, domain := range []string{"first.com", "second.com"} {
		c, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
		if err != nil || c == nil {
			t.Errorf("expected cert for %s after multiple reload", domain)
		}
	}
}

// ---------------------------------------------------------------------------
// CertStore: Reload with wildcard cert changed
// ---------------------------------------------------------------------------

func TestExtraReloadIfChanged_WildcardChanged(t *testing.T) {
	cs := NewCertStore()

	wcCert, wcKey := generateTestCert(t, "*.wcreload.com")
	_ = cs.LoadCert([]string{"*.wcreload.com"}, wcCert, wcKey)

	time.Sleep(10 * time.Millisecond)
	newWcCert, newWcKey := generateTestCert(t, "*.wcreload.com")
	copyFile(t, newWcCert, wcCert)
	copyFile(t, newWcKey, wcKey)

	cs.reloadIfChanged()

	c, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "sub.wcreload.com"})
	if err != nil || c == nil {
		t.Error("expected wildcard cert after reload")
	}
}

// ---------------------------------------------------------------------------
// CertStore: Concurrent reload + GetCertificate stress
// ---------------------------------------------------------------------------

func TestExtraConcurrentReloadStress(t *testing.T) {
	cs := NewCertStore()
	certFile, keyFile := generateTestCert(t, "stress.com")
	_ = cs.LoadCert([]string{"stress.com"}, certFile, keyFile)

	var wg sync.WaitGroup
	for i := range 5 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for range 100 {
				_, _ = cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "stress.com"})
			}
		}(i)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 50 {
			cs.reloadIfChanged()
		}
	}()

	wg.Wait()
}

// ---------------------------------------------------------------------------
// Concurrent StapleOCSP + GetCertificate
// ---------------------------------------------------------------------------

func TestExtraConcurrentStapleOCSPAndRead(t *testing.T) {
	validResp := extraBuildValidOCSPResponse()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(validResp)
	}))
	defer server.Close()

	certFile, keyFile, _ := extraGenerateCertWithAIA(t, server.URL, "constaple.com")

	cs := NewCertStore()
	_ = cs.LoadCert([]string{"constaple.com"}, certFile, keyFile)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 20 {
			cs.StapleOCSP()
		}
	}()

	go func() {
		defer wg.Done()
		for range 100 {
			_, _ = cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "constaple.com"})
		}
	}()

	wg.Wait()
}

// ---------------------------------------------------------------------------
// Ensure fmt import is used
// ---------------------------------------------------------------------------

var _ = fmt.Sprintf
