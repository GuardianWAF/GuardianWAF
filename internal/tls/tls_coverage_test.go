package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ===========================================================================
// parseAccessDescription: comprehensive coverage (was 22.2%)
// ===========================================================================

func TestPAD_CorrectOIDAndURL(t *testing.T) {
	ocspOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	url := "http://ocsp.correct.com/"
	ad := struct {
		OID  asn1.ObjectIdentifier
		Name asn1.RawValue
	}{
		OID:  ocspOID,
		Name: asn1.RawValue{FullBytes: buildAIAURLManual(url)},
	}
	adDER, _ := asn1.Marshal(ad)
	result := parseAccessDescription(adDER)
	if result != url {
		t.Errorf("expected %q, got %q", url, result)
	}
}

func TestPAD_WrongOID(t *testing.T) {
	ad := struct {
		OID  asn1.ObjectIdentifier
		Name asn1.RawValue
	}{
		OID:  asn1.ObjectIdentifier{1, 2, 3, 4},
		Name: asn1.RawValue{FullBytes: buildAIAURLManual("http://test.com/")},
	}
	adDER, _ := asn1.Marshal(ad)
	if r := parseAccessDescription(adDER); r != "" {
		t.Errorf("expected empty for wrong OID, got %q", r)
	}
}

func TestPAD_CorrectOID_WrongTag(t *testing.T) {
	ocspOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	nameBytes, _ := asn1.MarshalWithParams("not-a-url", "tag:4")
	ad := struct {
		OID  asn1.ObjectIdentifier
		Name asn1.RawValue
	}{
		OID:  ocspOID,
		Name: asn1.RawValue{FullBytes: nameBytes},
	}
	adDER, _ := asn1.Marshal(ad)
	if r := parseAccessDescription(adDER); r != "" {
		t.Errorf("expected empty for non-URL tag, got %q", r)
	}
}

func TestPAD_Empty(t *testing.T) {
	if r := parseAccessDescription([]byte{}); r != "" {
		t.Errorf("expected empty, got %q", r)
	}
}

func TestPAD_ShortData(t *testing.T) {
	if r := parseAccessDescription([]byte{0x30, 0x01, 0x00}); r != "" {
		t.Errorf("expected empty for short data, got %q", r)
	}
}

func TestPAD_SingleElement(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidBytes, _ := asn1.Marshal(oid)
	single, _ := asn1.Marshal([]asn1.RawValue{{FullBytes: oidBytes}})
	if r := parseAccessDescription(single); r != "" {
		t.Errorf("expected empty for single element, got %q", r)
	}
}

func TestPAD_MalformedSecondElement(t *testing.T) {
	ocspOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	ad := struct {
		OID  asn1.ObjectIdentifier
		Name asn1.RawValue
	}{
		OID:  ocspOID,
		Name: asn1.RawValue{FullBytes: []byte{0xFF, 0x02, 0x00, 0x00}},
	}
	adDER, _ := asn1.Marshal(ad)
	result := parseAccessDescription(adDER)
	t.Logf("malformed second element: %q", result)
}

func TestPAD_MalformedOID(t *testing.T) {
	ad := struct {
		OID  asn1.RawValue
		Name asn1.RawValue
	}{
		OID:  asn1.RawValue{FullBytes: []byte{0x06, 0x01, 0xFF}},
		Name: asn1.RawValue{FullBytes: buildAIAURLManual("http://test.com/")},
	}
	adDER, _ := asn1.Marshal(ad)
	result := parseAccessDescription(adDER)
	t.Logf("malformed OID: %q", result)
}

// ===========================================================================
// parseBasicOCSPResponse: comprehensive coverage (was 36.4%)
// ===========================================================================

func TestPBOR_SuccessWithBytes(t *testing.T) {
	respBytes, _ := asn1.Marshal(struct {
		Type asn1.ObjectIdentifier
		Data []byte
	}{
		Type: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1},
		Data: []byte("mock"),
	})
	fullResp, _ := asn1.Marshal(struct {
		Status asn1.Enumerated
		Bytes  []byte `asn1:"tag:0,optional"`
	}{Status: 0, Bytes: respBytes})

	resp, err := parseBasicOCSPResponse(fullResp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != OCSPGood {
		t.Errorf("expected OCSPGood, got %d", resp.Status)
	}
	if len(resp.Raw) == 0 {
		t.Error("expected non-empty raw bytes")
	}
}

func TestPBOR_NonZeroStatus(t *testing.T) {
	for _, status := range []int{1, 2, 5} {
		fullResp, _ := asn1.Marshal(struct {
			Status asn1.Enumerated
			Bytes  []byte `asn1:"tag:0,optional"`
		}{Status: asn1.Enumerated(status)})
		resp, err := parseBasicOCSPResponse(fullResp)
		if err != nil {
			t.Errorf("status %d: unexpected error %v", status, err)
		}
		if resp.Status != OCSPUnknown {
			t.Errorf("status %d: expected OCSPUnknown, got %d", status, resp.Status)
		}
	}
}

func TestPBOR_Status0NoBytes(t *testing.T) {
	fullResp, _ := asn1.Marshal(struct {
		Status asn1.Enumerated
		Bytes  []byte `asn1:"tag:0,optional"`
	}{Status: 0})
	_, err := parseBasicOCSPResponse(fullResp)
	if err == nil {
		t.Error("expected error")
	}
	if !strings.Contains(err.Error(), "no response bytes") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPBOR_InvalidDER(t *testing.T) {
	_, err := parseBasicOCSPResponse([]byte{0xFF, 0xFF})
	if err == nil {
		t.Error("expected error")
	}
}

func TestPBOR_InvalidResponseBytes(t *testing.T) {
	fullResp, _ := asn1.Marshal(struct {
		Status asn1.Enumerated
		Bytes  []byte `asn1:"tag:0,optional"`
	}{Status: 0, Bytes: []byte{0xFF, 0xFF}})
	_, err := parseBasicOCSPResponse(fullResp)
	if err == nil {
		t.Error("expected error")
	}
}

// ===========================================================================
// FetchOCSPResponse: comprehensive coverage
// ===========================================================================

func TestFOR_MissingData(t *testing.T) {
	_, err := FetchOCSPResponse(&x509.Certificate{}, &x509.Certificate{})
	if err == nil {
		t.Error("expected error")
	}
	if !strings.Contains(err.Error(), "missing certificate data") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestFOR_OnlyIssuerHasRaw(t *testing.T) {
	_, err := FetchOCSPResponse(&x509.Certificate{Raw: []byte{1}}, &x509.Certificate{})
	if err == nil {
		t.Error("expected error")
	}
}

func TestFOR_NoOCSPURL(t *testing.T) {
	_, err := FetchOCSPResponse(&x509.Certificate{Raw: []byte{1}}, &x509.Certificate{Raw: []byte{2}})
	if err == nil {
		t.Error("expected error")
	}
	if !strings.Contains(err.Error(), "no OCSP responder URL") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestFOR_MockServer(t *testing.T) {
	respBytes, _ := asn1.Marshal(struct {
		Type asn1.ObjectIdentifier
		Data []byte
	}{
		Type: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1},
		Data: []byte("mock"),
	})
	ocspRespDER, _ := asn1.Marshal(struct {
		Status asn1.Enumerated
		Bytes  []byte `asn1:"tag:0,optional"`
	}{Status: 0, Bytes: respBytes})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(ocspRespDER)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		OCSPServer:            []string{server.URL},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	result, err := FetchOCSPResponse(cert, cert)
	t.Logf("FOR mock: err=%v len=%d", err, len(result))
}

func TestFOR_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		OCSPServer:            []string{server.URL},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	_, err := FetchOCSPResponse(cert, cert)
	t.Logf("FOR server error: %v", err)
}

func TestFOR_InvalidBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("garbage"))
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		OCSPServer:            []string{server.URL},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	_, err := FetchOCSPResponse(cert, cert)
	t.Logf("FOR invalid body: %v", err)
}

func TestFOR_LargeBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(bytes.Repeat([]byte("x"), 2*1024*1024))
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		OCSPServer:            []string{server.URL},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	_, err := FetchOCSPResponse(cert, cert)
	t.Logf("FOR large body: %v", err)
}

// ===========================================================================
// extractOCSPURL
// ===========================================================================

func TestEOCU_WithAIA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		OCSPServer:            []string{"http://ocsp.example.com/"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	url := extractOCSPURL(cert)
	t.Logf("extractOCSPURL: %q", url)
}

// ===========================================================================
// stapleOCSPForEntry: additional paths
// ===========================================================================

func TestSOSE_Chain(t *testing.T) {
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Chain CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "chain.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"chain.com"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, issuerTmpl, &leafKey.PublicKey, issuerKey)

	dir := t.TempDir()
	chainFile := filepath.Join(dir, "chain.pem")
	f, _ := os.Create(chainFile)
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})
	f.Close()

	keyBytes, _ := x509.MarshalECPrivateKey(leafKey)
	keyFile := filepath.Join(dir, "key.pem")
	kf, _ := os.Create(keyFile)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	kf.Close()

	cs := NewCertStore()
	_ = cs.LoadCert([]string{"chain.com"}, chainFile, keyFile)
	cs.stapleOCSPForEntry(CertEntry{Domains: []string{"chain.com"}, CertFile: chainFile, KeyFile: keyFile})
}

func TestSOSE_SelfSignedCA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "selfca.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"selfca.com"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	cf, _ := os.Create(certFile)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	keyBytes, _ := x509.MarshalECPrivateKey(key)
	keyFile := filepath.Join(dir, "key.pem")
	kf, _ := os.Create(keyFile)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	kf.Close()

	cs := NewCertStore()
	_ = cs.LoadCert([]string{"selfca.com"}, certFile, keyFile)
	cs.stapleOCSPForEntry(CertEntry{Domains: []string{"selfca.com"}, CertFile: certFile, KeyFile: keyFile})
}

func TestSOSE_BadIssuerInChain(t *testing.T) {
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Bad Issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	_, _ = x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "badissuer.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"badissuer.com"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, issuerTmpl, &leafKey.PublicKey, issuerKey)

	dir := t.TempDir()
	chainFile := filepath.Join(dir, "chain.pem")
	f, _ := os.Create(chainFile)
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: []byte("not real DER")})
	f.Close()

	keyBytes, _ := x509.MarshalECPrivateKey(leafKey)
	keyFile := filepath.Join(dir, "key.pem")
	kf, _ := os.Create(keyFile)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	kf.Close()

	cs := NewCertStore()
	_ = cs.LoadCert([]string{"badissuer.com"}, chainFile, keyFile)
	cs.stapleOCSPForEntry(CertEntry{Domains: []string{"badissuer.com"}, CertFile: chainFile, KeyFile: keyFile})
}

// ===========================================================================
// Additional certstore tests
// ===========================================================================

func TestLC_SANDomains(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "primary.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"primary.com", "secondary.com"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	cf, _ := os.Create(certFile)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	keyBytes, _ := x509.MarshalECPrivateKey(key)
	keyFile := filepath.Join(dir, "key.pem")
	kf, _ := os.Create(keyFile)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	kf.Close()

	cs := NewCertStore()
	err := cs.LoadCert([]string{"primary.com", "secondary.com"}, certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"primary.com", "secondary.com"} {
		c, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: d})
		if err != nil || c == nil {
			t.Errorf("expected cert for %s", d)
		}
	}
}

func TestHotReload_Concurrent(t *testing.T) {
	cs := NewCertStore()
	certFile, keyFile := generateTestCert(t, "concurrent2.com")
	_ = cs.LoadCert([]string{"concurrent2.com"}, certFile, keyFile)

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				_, _ = cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "concurrent2.com"})
			}
		}()
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

func TestConcurrentStapleAndReload(t *testing.T) {
	cs := NewCertStore()
	certFile, keyFile := generateTestCert(t, "cstaple2.com")
	_ = cs.LoadCert([]string{"cstaple2.com"}, certFile, keyFile)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for range 50 {
			cs.reloadIfChanged()
		}
	}()
	go func() {
		defer wg.Done()
		for range 50 {
			cs.StapleOCSP()
		}
	}()
	go func() {
		defer wg.Done()
		for range 50 {
			_, _ = cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "cstaple2.com"})
		}
	}()
	wg.Wait()
}

// ===========================================================================
// Constants and types
// ===========================================================================

func TestConstants(t *testing.T) {
	if OCSPGood != 0 || OCSPRevoked != 1 || OCSPUnknown != 2 {
		t.Errorf("bad OCSP constants: %d %d %d", OCSPGood, OCSPRevoked, OCSPUnknown)
	}
	_ = crypto.SHA1
	_ = oidAuthorityInfoAccess
	_ = CertEntry{Domains: []string{"x"}, CertFile: "/a", KeyFile: "/b"}
	_ = OCSPResponse{Status: OCSPGood, Raw: []byte{1}}
}

// ===========================================================================
// TLSConfig integration
// ===========================================================================

func TestTLSConfigIntegration(t *testing.T) {
	cs := NewCertStore()
	certFile, keyFile := generateTestCert(t, "tlsinteg.com")
	_ = cs.LoadCert([]string{"tlsinteg.com"}, certFile, keyFile)

	cfg := cs.TLSConfig()
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "tlsinteg.com"})
	if err != nil || cert == nil {
		t.Errorf("GetCertificate via TLSConfig: %v", err)
	}
}

// ===========================================================================
// StartReload/StartOCSPRefresh ticker fire
// ===========================================================================

func TestStartReloadTickerFires(t *testing.T) {
	cs := NewCertStore()
	certFile, keyFile := generateTestCert(t, "tick2.com")
	_ = cs.LoadCert([]string{"tick2.com"}, certFile, keyFile)
	cs.StartReload(20 * time.Millisecond)
	time.Sleep(80 * time.Millisecond)
	cs.StopReload()
}

func TestStartOCSPRefreshTickerFires(t *testing.T) {
	cs := NewCertStore()
	certFile, keyFile := generateTestCert(t, "ocsptick2.com")
	_ = cs.LoadCert([]string{"ocsptick2.com"}, certFile, keyFile)
	cs.StartOCSPRefresh(20 * time.Millisecond)
	time.Sleep(80 * time.Millisecond)
	cs.StopReload()
}

// ===========================================================================
// parseAIAOCSP additional paths
// ===========================================================================

func TestPAIA_MainPath(t *testing.T) {
	ocspOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	ad := struct {
		OID  asn1.ObjectIdentifier
		Name asn1.RawValue
	}{
		OID:  ocspOID,
		Name: asn1.RawValue{FullBytes: buildAIAURLManual("http://ocsp.test.com/")},
	}
	adBytes, _ := asn1.Marshal(ad)
	aiaData, _ := asn1.Marshal([]asn1.RawValue{{FullBytes: adBytes}})
	result := parseAIAOCSP(aiaData)
	t.Logf("parseAIAOCSP main: %q", result)
}

func TestPAIA_NonSequenceContent(t *testing.T) {
	data, _ := asn1.Marshal([]byte("bytes"))
	result := parseAIAOCSP(data)
	t.Logf("parseAIAOCSP non-seq: %q", result)
}

func TestPAIA_InvalidDER(t *testing.T) {
	if r := parseAIAOCSP([]byte{0xFF, 0xFF}); r != "" {
		t.Errorf("expected empty: %q", r)
	}
}

func TestPAIA_Empty(t *testing.T) {
	if r := parseAIAOCSP([]byte{}); r != "" {
		t.Errorf("expected empty: %q", r)
	}
}

// ===========================================================================
// Wildcard case insensitivity
// ===========================================================================

func TestWildcardCaseInsensitive(t *testing.T) {
	cs := NewCertStore()
	certFile, keyFile := generateTestCert(t, "*.EXAMPLE.COM")
	_ = cs.LoadCert([]string{"*.EXAMPLE.COM"}, certFile, keyFile)

	cert, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "sub.example.com"})
	if err != nil || cert == nil {
		t.Error("expected case-insensitive wildcard match")
	}
}

// ===========================================================================
// LoadDefaultCert replacement
// ===========================================================================

func TestLoadDefaultCertReplace(t *testing.T) {
	cs := NewCertStore()
	c1, k1 := generateTestCert(t, "default1.com")
	_ = cs.LoadDefaultCert(c1, k1)
	c2, k2 := generateTestCert(t, "default2.com")
	_ = cs.LoadDefaultCert(c2, k2)

	cert, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "any.com"})
	if err != nil || cert == nil {
		t.Error("expected default cert after replacement")
	}
}
