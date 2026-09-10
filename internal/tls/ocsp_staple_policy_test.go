package tls

// Staple-policy regression tests (hardening follow-up): stapleOCSPForEntry
// must staple only responses asserting the certificate is GOOD and still
// within their validity window — revoked or expired responses are refused
// (they would hand browsers revocation/expiry evidence for the very
// certificate we terminate).

import (
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func staplePolicyServer(t *testing.T, respDER []byte) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respDER)
	}))
	t.Cleanup(server.Close)
	return server
}

func staplePolicySetup(t *testing.T, respDER []byte, domain string) (*CertStore, CertEntry) {
	t.Helper()
	server := staplePolicyServer(t, respDER)
	_ = server
	chainFile, keyFile, _ := extraGenerateCertWithAIA(t, server.URL, domain)
	cs := NewCertStore()
	if err := cs.LoadCert([]string{domain}, chainFile, keyFile); err != nil {
		t.Fatalf("LoadCert: %v", err)
	}
	entry := CertEntry{Domains: []string{domain}, CertFile: chainFile, KeyFile: keyFile}
	return cs, entry
}

func stapledBytes(cs *CertStore, domain string) []byte {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	cert := cs.certs[domain]
	if cert == nil {
		return nil
	}
	return cert.OCSPStaple
}

func TestStaplePolicy_GoodUnexpiredStapled(t *testing.T) {
	now := time.Now()
	regCA, _ := regGenCA(t)
	validResp := buildRegResponse(t, regCA, big.NewInt(0x42), 0, nil, now.Add(-time.Hour), now.Add(time.Hour), regOIDBasic)
	cs, entry := staplePolicySetup(t, validResp, "staplegood.com")

	cs.stapleOCSPForEntry(entry)

	if stapled := stapledBytes(cs, "staplegood.com"); len(stapled) == 0 {
		t.Errorf("FAIL: good unexpired response was not stapled")
	}
}

func TestStaplePolicy_RevokedRefused(t *testing.T) {
	now := time.Now()
	regCA, _ := regGenCA(t)
	genTLV := regGenTime(now.Add(-2 * time.Hour))
	revInfo := regTLV(0, 16, true, genTLV) // RevokedInfo ::= SEQUENCE { revocationTime }
	revokedResp := buildRegResponse(t, regCA, big.NewInt(0x42), 1, revInfo, now.Add(-48*time.Hour), now.Add(time.Hour), regOIDBasic)
	cs, entry := staplePolicySetup(t, revokedResp, "staplerevoked.com")

	cs.stapleOCSPForEntry(entry)

	if stapled := stapledBytes(cs, "staplerevoked.com"); len(stapled) != 0 {
		t.Errorf("FAIL: revoked response was stapled (%d bytes)", len(stapled))
	}
}

func TestStaplePolicy_ExpiredRefused(t *testing.T) {
	now := time.Now()
	regCA, _ := regGenCA(t)
	expiredResp := buildRegResponse(t, regCA, big.NewInt(0x42), 0, nil, now.Add(-48*time.Hour), now.Add(-time.Hour), regOIDBasic)
	cs, entry := staplePolicySetup(t, expiredResp, "stapleexpired.com")

	cs.stapleOCSPForEntry(entry)

	if stapled := stapledBytes(cs, "stapleexpired.com"); len(stapled) != 0 {
		t.Errorf("FAIL: expired response was stapled (%d bytes)", len(stapled))
	}
}
