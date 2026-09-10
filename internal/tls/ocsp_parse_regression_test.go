package tls

// OCSP sweep proof (fix-round regression suite (promoted from the sweep proof)): parseBasicOCSPResponse never parses
// the BasicOCSPResponse body, so (1) certStatus is invisible — a REVOKED
// response is reported OCSPGood; (2) ThisUpdate/NextUpdate are never
// populated, so an expired response is undetectable by contract; (3) the
// responseType OID is never checked; and (4) buildOCSPRequest emits
// requestList as SET OF (0x31) where RFC 6960 requires SEQUENCE OF (0x30).
// This test asserts the CORRECT contract, so it is expected to FAIL against
// the unfixed code. Controls pin today's working behavior so the harness
// proves it exercises the real path.
//
// DER assembly is fully manual (regTLV) because encoding/asn1.Marshal on a
// RawValue with nil FullBytes emits an empty TLV.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

var (
	regOIDSHA1      = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	regOIDBasic     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	regOIDNotBasic  = asn1.ObjectIdentifier{2, 5, 4, 3} // commonName — not an OCSP response type
	regOIDSHA256RSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
)

// regTLV builds a complete DER TLV with short- or long-form length.
func regTLV(class, tag int, compound bool, content []byte) []byte {
	b0 := byte(class) << 6
	if compound {
		b0 |= 0x20
	}
	b0 |= byte(tag)
	out := []byte{b0}
	if l := len(content); l < 0x80 {
		out = append(out, byte(l))
	} else {
		var lenBytes []byte
		for n := l; n > 0; n >>= 8 {
			lenBytes = append([]byte{byte(n)}, lenBytes...)
		}
		out = append(out, byte(0x80|len(lenBytes)))
		out = append(out, lenBytes...)
	}
	return append(out, content...)
}

func regConcat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func regGenTime(t time.Time) []byte {
	// NOTE: seconds in Go layouts are "05" — "07" would be emitted literally,
	// pinning every encoded timestamp's seconds to :07.
	return regTLV(0, 24, false, []byte(t.UTC().Format("20060102150405Z")))
}

type regCertID struct {
	Alg      pkix.AlgorithmIdentifier
	NameHash []byte
	KeyHash  []byte
	Serial   *big.Int
}

type regSingle struct {
	CertID     regCertID
	CertStatus asn1.RawValue
	ThisUpdate asn1.RawValue
	NextUpdate asn1.RawValue
}

type regRespData struct {
	ResponderID asn1.RawValue
	ProducedAt  asn1.RawValue
	Responses   []regSingle
}

type regRespBytes struct {
	Type     asn1.ObjectIdentifier
	Response []byte
}

func regGenCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "proof-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return cert, key
}

func regGenLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x17),
		Subject:      pkix.Name{CommonName: "proof-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert
}

// buildRegResponse hand-builds an RFC 6960-shaped OCSPResponse whose single
// response carries the requested certStatus and validity window. The inner
// BasicOCSPResponse is structurally real (ResponseData → SingleResponse →
// CertID/certStatus/thisUpdate/nextUpdate) so a correct parser could extract
// every field; the signature is a dummy BIT STRING because the function under
// test does not verify signatures.
// buildRegBasicBody returns a well-formed BasicOCSPResponse TLV (the inner
// OCTET STRING body of an OCSP response) with the requested certStatus and
// validity window.
func buildRegBasicBody(t *testing.T, ca *x509.Certificate, serial *big.Int, statusTag int, statusContent []byte, thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()

	h := sha1.New()
	h.Write(ca.RawSubject)
	nameHash := h.Sum(nil)
	h.Reset()
	h.Write(ca.RawSubjectPublicKeyInfo)
	keyHash := h.Sum(nil)

	single := regSingle{
		CertID: regCertID{
			Alg:      pkix.AlgorithmIdentifier{Algorithm: regOIDSHA1, Parameters: asn1.NullRawValue},
			NameHash: nameHash,
			KeyHash:  keyHash,
			Serial:   serial,
		},
		CertStatus: asn1.RawValue{FullBytes: regTLV(2, statusTag, statusContent != nil, statusContent)},
		ThisUpdate: asn1.RawValue{FullBytes: regGenTime(thisUpdate)},
		NextUpdate: asn1.RawValue{FullBytes: regGenTime(nextUpdate)},
	}

	respData := regRespData{
		ResponderID: asn1.RawValue{FullBytes: regTLV(2, 2, false, keyHash)}, // byKeyHash [2]
		ProducedAt:  asn1.RawValue{FullBytes: regGenTime(time.Now().Add(-time.Minute))},
		Responses:   []regSingle{single},
	}
	tbsDER, err := asn1.Marshal(respData)
	if err != nil {
		t.Fatalf("marshal ResponseData: %v", err)
	}

	sigAlgDER, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: regOIDSHA256RSA, Parameters: asn1.NullRawValue})
	if err != nil {
		t.Fatalf("marshal sig alg: %v", err)
	}
	sigTLV := regTLV(0, 3, false, append([]byte{0x00}, make([]byte, 32)...)) // BIT STRING, 0 unused bits
	return regTLV(0, 16, true, regConcat(tbsDER, sigAlgDER, sigTLV))
}

// buildRegResponse wraps a BasicOCSPResponse body in the OCSPResponse
// envelope (responseStatus = successful).
func buildRegResponse(t *testing.T, ca *x509.Certificate, serial *big.Int, statusTag int, statusContent []byte, thisUpdate, nextUpdate time.Time, responseType asn1.ObjectIdentifier) []byte {
	t.Helper()
	basicDER := buildRegBasicBody(t, ca, serial, statusTag, statusContent, thisUpdate, nextUpdate)
	rbDER, err := asn1.Marshal(regRespBytes{Type: responseType, Response: basicDER})
	if err != nil {
		t.Fatalf("marshal ResponseBytes: %v", err)
	}

	// OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED(0), [0] EXPLICIT ResponseBytes }
	ocspContent := regConcat([]byte{0x0a, 0x01, 0x00}, regTLV(2, 0, true, rbDER))
	return regTLV(0, 16, true, ocspContent)
}

func TestOCSPResponseParseRegression(t *testing.T) {
	ca, caKey := regGenCA(t)
	leaf := regGenLeaf(t, ca, caKey)
	now := time.Now()
	past := now.Add(-1 * time.Hour) // nextUpdate in the past = EXPIRED response

	// --- Attack A: REVOKED certificate, EXPIRED nextUpdate ---
	genTLV := regGenTime(now.Add(-2 * time.Hour))
	revInfo := regTLV(0, 16, true, genTLV) // RevokedInfo ::= SEQUENCE { revocationTime }
	revokedDER := buildRegResponse(t, ca, big.NewInt(0x17), 1, revInfo, now.Add(-48*time.Hour), past, regOIDBasic)
	resp, err := parseBasicOCSPResponse(revokedDER)
	if err != nil {
		t.Errorf("FAIL A1 response-rejection: successful OCSP response rejected (encoding/asn1 drops constructed [0] content into a []byte field): %v", err)
	} else {
		if resp.Status != OCSPRevoked {
			t.Errorf("FAIL A2 revocation-blindness: Status = %v, want OCSPRevoked (certStatus never parsed)", resp.Status)
		}
		if !resp.NextUpdate.Equal(past.Truncate(time.Second)) {
			t.Errorf("FAIL A3 status-timing: NextUpdate = %v, want %v (expired response undetectable)", resp.NextUpdate, past)
		}
		if resp.ThisUpdate.IsZero() {
			t.Errorf("FAIL A3 status-timing: ThisUpdate = zero (never extracted)")
		}
	}

	// --- Attack B: wrong responseType (not id-pkix-ocsp-basic) ---
	wrongDER := buildRegResponse(t, ca, big.NewInt(0x17), 0, nil, now.Add(-48*time.Hour), now.Add(time.Hour), regOIDNotBasic)
	resp2, err2 := parseBasicOCSPResponse(wrongDER)
	if err2 == nil && resp2 != nil && resp2.Status == OCSPGood {
		t.Errorf("FAIL responseType: non-basic response accepted as OCSPGood (OID never validated)")
	}

	// --- Attack C: requestList must be SEQUENCE OF (0x30), not SET OF (0x31) ---
	reqDER, err := buildOCSPRequest(ca, leaf)
	if err != nil {
		t.Fatalf("buildOCSPRequest: %v", err)
	}
	var ocspReq asn1.RawValue
	if _, err := asn1.Unmarshal(reqDER, &ocspReq); err != nil {
		t.Fatalf("unmarshal OCSPRequest: %v", err)
	}
	var tbs asn1.RawValue
	if _, err := asn1.Unmarshal(ocspReq.Bytes, &tbs); err != nil {
		t.Fatalf("unmarshal TBSRequest: %v", err)
	}
	if len(tbs.Bytes) == 0 {
		t.Fatalf("TBSRequest has no content")
	}
	if tag := tbs.Bytes[0]; tag != 0x30 {
		t.Errorf("FAIL request wire format: requestList tag = 0x%02X, want 0x30 (SEQUENCE OF per RFC 6960)", tag)
	}

	// --- Controls (must pass before and after any fix) ---
	unknownDER := []byte{0x30, 0x03, 0x0a, 0x01, 0x02} // SEQUENCE { ENUMERATED 2 }
	respU, errU := parseBasicOCSPResponse(unknownDER)
	if errU != nil || respU.Status != OCSPUnknown {
		t.Errorf("control: responseStatus=2 should yield OCSPUnknown (err=%v, status=%v)", errU, respU.Status)
	}
	goodDER := buildRegResponse(t, ca, big.NewInt(0x18), 0, nil, now.Add(-48*time.Hour), now.Add(time.Hour), regOIDBasic)
	if _, errG := parseBasicOCSPResponse(goodDER); errG != nil {
		t.Errorf("control: well-formed good response rejected: %v", errG)
	}
}
