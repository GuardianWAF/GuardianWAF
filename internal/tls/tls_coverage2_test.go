package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
	"time"
)

// =============================================================================
// buildOCSPRequest: was 0%
// =============================================================================

func TestCoverage_BuildOCSPRequest(t *testing.T) {
	// Generate issuer and leaf certificates
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
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

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.com"},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuerCert, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("creating leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parsing leaf cert: %v", err)
	}

	reqData, err := buildOCSPRequest(issuerCert, leafCert)
	if err != nil {
		t.Fatalf("buildOCSPRequest: %v", err)
	}
	if len(reqData) == 0 {
		t.Error("expected non-empty OCSP request data")
	}
}

// =============================================================================
// buildCertID: was 0%
// =============================================================================

func TestCoverage_BuildCertID(t *testing.T) {
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "CertID CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	issuerCert, _ := x509.ParseCertificate(issuerDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "certid.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"certid.com"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, issuerCert, &leafKey.PublicKey, issuerKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	certID, err := buildCertID(issuerCert, leafCert)
	if err != nil {
		t.Fatalf("buildCertID: %v", err)
	}

	// Verify fields
	sha1OID := asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	if !certID.HashAlgorithm.Equal(sha1OID) {
		t.Errorf("expected SHA1 OID, got %v", certID.HashAlgorithm)
	}
	if len(certID.IssuerNameHash) == 0 {
		t.Error("expected non-empty issuer name hash")
	}
	if len(certID.IssuerKeyHash) == 0 {
		t.Error("expected non-empty issuer key hash")
	}
	if certID.SerialNumber == nil {
		t.Error("expected non-nil serial number")
	}
	if certID.SerialNumber.Int64() != 200 {
		t.Errorf("expected serial 200, got %d", certID.SerialNumber.Int64())
	}
}

// =============================================================================
// FetchOCSPResponse: missing certificate data
// =============================================================================

func TestCoverage_FetchOCSPResponse_MissingData(t *testing.T) {
	emptyCert := &x509.Certificate{}
	_, err := FetchOCSPResponse(emptyCert, emptyCert)
	if err == nil {
		t.Error("expected error for missing certificate data")
	}
}

// =============================================================================
// FetchOCSPResponse: no OCSP URL in certificate
// =============================================================================

func TestCoverage_FetchOCSPResponse_NoOCSPURL(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "noocsp.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	_, err := FetchOCSPResponse(cert, cert)
	if err == nil {
		t.Error("expected error for no OCSP URL")
	}
	if err != nil && !containsStr(err.Error(), "no OCSP responder") {
		t.Errorf("expected 'no OCSP responder' error, got: %v", err)
	}
}

// =============================================================================
// extractOCSPURL: certificate without AIA extension
// =============================================================================

func TestCoverage_ExtractOCSPURL_NoAIA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "noaia.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	result := extractOCSPURL(cert)
	if result != "" {
		t.Errorf("expected empty URL for cert without AIA, got %q", result)
	}
}

// =============================================================================
// parseBasicOCSPResponse: non-zero status
// =============================================================================

func TestCoverage_ParseBasicOCSPResponse_NonZeroStatus(t *testing.T) {
	resp, _ := asn1.Marshal(struct {
		Status asn1.Enumerated
		Bytes  []byte `asn1:"tag:0,optional"`
	}{
		Status: 2, // unknown
	})

	result, err := parseBasicOCSPResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != OCSPUnknown {
		t.Errorf("expected OCSPUnknown, got %d", result.Status)
	}
}

// =============================================================================
// parseBasicOCSPResponse: success status but no bytes
// =============================================================================

func TestCoverage_ParseBasicOCSPResponse_NoBytes(t *testing.T) {
	resp, _ := asn1.Marshal(struct {
		Status asn1.Enumerated
		Bytes  []byte `asn1:"tag:0,optional"`
	}{
		Status: 0,
	})

	_, err := parseBasicOCSPResponse(resp)
	if err == nil {
		t.Error("expected error for OCSP response with no bytes")
	}
}

// =============================================================================
// parseBasicOCSPResponse: invalid DER
// =============================================================================

func TestCoverage_ParseBasicOCSPResponse_InvalidDER(t *testing.T) {
	_, err := parseBasicOCSPResponse([]byte("not valid DER"))
	if err == nil {
		t.Error("expected error for invalid DER")
	}
}

// =============================================================================
// parseAIAOCSP: empty data
// =============================================================================

func TestCoverage_ParseAIAOCSP_EmptyData(t *testing.T) {
	result := parseAIAOCSP(nil)
	if result != "" {
		t.Errorf("expected empty for nil data, got %q", result)
	}

	result = parseAIAOCSP([]byte{})
	if result != "" {
		t.Errorf("expected empty for empty data, got %q", result)
	}
}

// =============================================================================
// parseAIAOCSP: invalid DER
// =============================================================================

func TestCoverage_ParseAIAOCSP_InvalidDER(t *testing.T) {
	result := parseAIAOCSP([]byte{0xFF, 0xFF, 0xFF})
	if result != "" {
		t.Errorf("expected empty for invalid DER, got %q", result)
	}
}

// =============================================================================
// parseAccessDescription: too few elements
// =============================================================================

func TestCoverage_ParseAccessDescription_TooFewElements(t *testing.T) {
	// Pass invalid data that unmarshals to fewer than 2 elements
	result := parseAccessDescription([]byte{0x30, 0x02, 0x05, 0x00})
	if result != "" {
		t.Errorf("expected empty for too few elements, got %q", result)
	}
}

// =============================================================================
// parseAccessDescription: wrong tag on name
// =============================================================================

func TestCoverage_ParseAccessDescription_WrongTag(t *testing.T) {
	ocspOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	// Tag 0x85 is not tag 6 (uniformResourceIdentifier)
	wrongName := []byte{0x85, 0x03, 'a', 'b', 'c'}

	desc := struct {
		OID  asn1.ObjectIdentifier
		Name asn1.RawValue
	}{
		OID:  ocspOID,
		Name: asn1.RawValue{FullBytes: wrongName},
	}
	descBytes, _ := asn1.Marshal(desc)

	result := parseAccessDescription(descBytes)
	if result != "" {
		t.Errorf("expected empty for wrong tag, got %q", result)
	}
}

// =============================================================================
// StartReload: zero interval defaults
// =============================================================================

func TestCoverage_StartReload_NegativeInterval(t *testing.T) {
	cs := NewCertStore()
	certFile, keyFile := generateTestCert(t, "reloadneg.com")
	_ = cs.LoadCert([]string{"reloadneg.com"}, certFile, keyFile)

	cs.StartReload(-1 * time.Second)
	time.Sleep(50 * time.Millisecond)
	cs.StopReload()
}

// =============================================================================
// StartReload: with modified cert file triggers reload
// =============================================================================

func TestCoverage_StartReload_ModifiedCertFile(t *testing.T) {
	cs := NewCertStore()
	certFile, keyFile := generateTestCert(t, "reloadmod.com")
	_ = cs.LoadCert([]string{"reloadmod.com"}, certFile, keyFile)

	time.Sleep(10 * time.Millisecond)

	// Write new cert data (different cert)
	newCertFile, newKeyFile := generateTestCert(t, "reloadmod.com")
	copyFileHelper(t, newCertFile, certFile)
	copyFileHelper(t, newKeyFile, keyFile)

	cs.StartReload(20 * time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	cs.StopReload()

	// Cert should still be accessible
	cert, err := cs.GetCertificate(&cryptotls.ClientHelloInfo{ServerName: "reloadmod.com"})
	if err != nil || cert == nil {
		t.Error("expected cert to be reloaded and accessible")
	}
}

// =============================================================================
// Helper: containsStr for error message checks
// =============================================================================

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Helper: copyFileHelper copies src to dst
func copyFileHelper(t *testing.T, src, dst string) {
	t.Helper()
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("reading %s: %v", src, err)
	}
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		t.Fatalf("writing %s: %v", dst, err)
	}
}
