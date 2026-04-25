package tls

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// OCSPStatus represents the OCSP response status.
type OCSPStatus int

const (
	OCSPGood    OCSPStatus = 0
	OCSPRevoked OCSPStatus = 1
	OCSPUnknown OCSPStatus = 2
)

// OCSPResponse holds a parsed OCSP response.
type OCSPResponse struct {
	Status     OCSPStatus
	ThisUpdate time.Time
	NextUpdate time.Time
	Raw        []byte // Raw DER-encoded response for stapling
}

// oidAuthorityInfoAccess is the OID for Authority Information Access.
var oidAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}

// FetchOCSPResponse fetches an OCSP response for the given certificate from its
// OCSP responder. Returns the raw DER-encoded response suitable for TLS stapling.

// ocspHTTPClient is a shared HTTP client for OCSP lookups.
var ocspHTTPClient = &http.Client{Timeout: 10 * time.Second}

func FetchOCSPResponse(issuer, leaf *x509.Certificate) ([]byte, error) {
	if len(issuer.Raw) == 0 || len(leaf.Raw) == 0 {
		return nil, fmt.Errorf("missing certificate data")
	}

	ocspURL := extractOCSPURL(leaf)
	if ocspURL == "" {
		return nil, fmt.Errorf("no OCSP responder URL in certificate")
	}

	// Build OCSP request (DER-encoded)
	reqData, err := buildOCSPRequest(issuer, leaf)
	if err != nil {
		return nil, fmt.Errorf("building OCSP request: %w", err)
	}

	// Send OCSP request via HTTP
	httpReq, err := http.NewRequest("POST", ocspURL, bytes.NewReader(reqData))
	if err != nil {
		return nil, fmt.Errorf("creating OCSP HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpReq.Header.Set("Accept", "application/ocsp-response")

	resp, err := ocspHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("OCSP HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("OCSP responder returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading OCSP response: %w", err)
	}

	// Try to decode the response to validate it
	if _, err := parseBasicOCSPResponse(body); err != nil {
		return nil, fmt.Errorf("parsing OCSP response: %w", err)
	}

	return body, nil
}

// extractOCSPURL extracts the OCSP responder URL from a certificate's
// Authority Information Access extension.
func extractOCSPURL(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidAuthorityInfoAccess) {
			return parseAIAOCSP(ext.Value)
		}
	}
	return ""
}

// parseAIAOCSP parses the AIA extension value to find the OCSP URL.
func parseAIAOCSP(data []byte) string {
	// AIA is a SEQUENCE of AccessDescription
	// AccessDescription ::= SEQUENCE {
	//   accessMethod  OBJECT IDENTIFIER,
	//   accessLocation GeneralName
	// }
	// We look for accessMethod = id-ad-ocsp (1.3.6.1.5.5.7.48.1)
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(data, &seq)
	if err != nil || len(rest) > 0 {
		// Try unwrapping outer sequence first
		var outer []asn1.RawValue
		rest2, err2 := asn1.Unmarshal(data, &outer)
		if err2 != nil || len(rest2) > 0 {
			return ""
		}
		for _, item := range outer {
			url := parseAccessDescription(item.FullBytes)
			if url != "" {
				return url
			}
		}
		return ""
	}

	// seq is the SEQUENCE of AccessDescriptions
	var descs []asn1.RawValue
	_, err = asn1.Unmarshal(seq.Bytes, &descs)
	if err != nil {
		return ""
	}

	for _, desc := range descs {
		url := parseAccessDescription(desc.FullBytes)
		if url != "" {
			return url
		}
	}
	return ""
}

func parseAccessDescription(data []byte) string {
	// SEQUENCE { OID, GeneralName }
	var desc []asn1.RawValue
	rest, err := asn1.Unmarshal(data, &desc)
	if err != nil || len(rest) > 0 || len(desc) < 2 {
		return ""
	}

	// Check if OID is id-ad-ocsp (1.3.6.1.5.5.7.48.1)
	var oid asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(desc[0].FullBytes, &oid)
	if err != nil {
		return ""
	}
	ocspOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	if !oid.Equal(ocspOID) {
		return ""
	}

	// GeneralName with tag [6] (uniformResourceIdentifier)
	var name asn1.RawValue
	_, err = asn1.Unmarshal(desc[1].FullBytes, &name)
	if err != nil {
		return ""
	}
	if name.Tag == 6 { // uniformResourceIdentifier
		return string(name.Bytes)
	}
	return ""
}

// buildOCSPRequest builds a minimal DER-encoded OCSP request.
func buildOCSPRequest(issuer, leaf *x509.Certificate) ([]byte, error) {
	// OCSP Request ::= SEQUENCE {
	//   tbsRequest  TBSCertID,
	//   signature   [0] EXPLICIT Signature OPTIONAL
	// }
	certID, err := buildCertID(issuer, leaf)
	if err != nil {
		return nil, err
	}

	// Build the inner CertID
	certIDBytes, err := asn1.Marshal(*certID)
	if err != nil {
		return nil, err
	}

	// Request ::= SEQUENCE { certID }
	// TBSRequest ::= SEQUENCE { version [0] INTEGER, requestList SEQUENCE OF Request }
	request := struct {
		CertID asn1.RawValue
	}{
		CertID: asn1.RawValue{FullBytes: certIDBytes},
	}

	reqBytes, err := asn1.Marshal(request)
	if err != nil {
		return nil, err
	}

	// Wrap in SEQUENCE OF
	tbsRequest := struct {
		Requests []asn1.RawValue `asn1:"set"`
	}{
		Requests: []asn1.RawValue{
			{FullBytes: reqBytes},
		},
	}

	tbsBytes, err := asn1.Marshal(tbsRequest)
	if err != nil {
		return nil, err
	}

	// OCSP Request ::= SEQUENCE { tbsRequest }
	ocspRequest := struct {
		TBSRequest asn1.RawValue
	}{
		TBSRequest: asn1.RawValue{FullBytes: tbsBytes},
	}

	return asn1.Marshal(ocspRequest)
}

// certIDData holds the fields needed to build an OCSP CertID.
type certIDData struct {
	HashAlgorithm  asn1.ObjectIdentifier
	HashAlgorithmParameters asn1.RawValue `asn1:"optional"`
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

func buildCertID(issuer, leaf *x509.Certificate) (*certIDData, error) {
	// SHA-1 hash of issuer's DER-encoded Subject
	h := sha1.New()
	h.Write(issuer.RawSubject)
	issuerNameHash := h.Sum(nil)

	// SHA-1 hash of issuer's public key DER value
	h.Reset()
	h.Write(issuer.RawSubjectPublicKeyInfo)
	issuerKeyHash := h.Sum(nil)

	// SHA-1 OID
	sha1OID := asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

	return &certIDData{
		HashAlgorithm:           sha1OID,
		HashAlgorithmParameters: asn1.NullRawValue,
		IssuerNameHash:          issuerNameHash,
		IssuerKeyHash:           issuerKeyHash,
		SerialNumber:            leaf.SerialNumber,
	}, nil
}

// parseBasicOCSPResponse does a minimal parse to verify the response is valid.
func parseBasicOCSPResponse(data []byte) (*OCSPResponse, error) {
	// OCSPResponse ::= SEQUENCE {
	//   responseStatus  ENUMERATED,
	//   responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL
	// }
	var resp struct {
		Status asn1.Enumerated
		Bytes  []byte `asn1:"tag:0,optional"`
	}
	if _, err := asn1.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshaling OCSP response: %w", err)
	}

	if resp.Status != 0 {
		return &OCSPResponse{Status: OCSPUnknown, Raw: data}, nil
	}

	if len(resp.Bytes) == 0 {
		return nil, fmt.Errorf("OCSP response has no response bytes")
	}

	// ResponseBytes ::= SEQUENCE {
	//   responseType  OID,
	//   response      OCTET STRING
	// }
	var respBytes struct {
		Type asn1.ObjectIdentifier
		Data []byte
	}
	if _, err := asn1.Unmarshal(resp.Bytes, &respBytes); err != nil {
		return nil, fmt.Errorf("unmarshaling response bytes: %w", err)
	}

	// For BasicOCSPResponse, do a minimal check — we primarily need the raw bytes for stapling
	return &OCSPResponse{
		Status: OCSPGood,
		Raw:    data,
	}, nil
}

// StapleOCSP fetches and staples OCSP responses for all certificates in the CertStore.
// Should be called periodically (e.g., every hour) to refresh stapled responses.
func (cs *CertStore) StapleOCSP() {
	cs.mu.RLock()
	entries := make([]CertEntry, len(cs.entries))
	copy(entries, cs.entries)

	var _ *CertEntry // placeholder for future default cert check
	// Check if any entry matches the default cert
	cs.mu.RUnlock()

	for _, entry := range entries {
		cs.stapleOCSPForEntry(entry)
	}
}

func (cs *CertStore) stapleOCSPForEntry(entry CertEntry) {
	cert, err := tls.LoadX509KeyPair(entry.CertFile, entry.KeyFile)
	if err != nil {
		return
	}
	if cert.Leaf == nil {
		// Parse the leaf certificate
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return
		}
	}

	// Need the issuer certificate — try to find it in the cert chain
	var issuerCert *x509.Certificate
	if len(cert.Certificate) > 1 {
		issuerCert, err = x509.ParseCertificate(cert.Certificate[1])
		if err != nil {
			return
		}
	} else {
		// No issuer in chain — try using the cert itself (self-signed case)
		// or skip OCSP for this cert
		if !cert.Leaf.IsCA {
			return
		}
		issuerCert = cert.Leaf
	}

	ocspResp, err := FetchOCSPResponse(issuerCert, cert.Leaf)
	if err != nil {
		return
	}

	cert.OCSPStaple = ocspResp

	// Build a lookup set of this entry's domains for targeted update
	domainSet := make(map[string]bool, len(entry.Domains))
	for _, d := range entry.Domains {
		domainSet[strings.ToLower(d)] = true
	}

	// Update the stored certificate with OCSP staple — only matching domains
	cs.mu.Lock()
	defer cs.mu.Unlock()

	for _, domain := range entry.Domains {
		lower := strings.ToLower(domain)
		if strings.HasPrefix(lower, "*.") {
			suffix := lower[1:]
			for i, wc := range cs.wildcards {
				if wc.suffix == suffix {
					cs.wildcards[i].cert = &cert
					break
				}
			}
		} else {
			if _, ok := cs.certs[lower]; ok {
				cs.certs[lower] = &cert
			}
		}
	}
}

// StartOCSPRefresh begins periodic OCSP staple refresh.
func (cs *CertStore) StartOCSPRefresh(interval time.Duration) {
	if interval <= 0 {
		interval = 1 * time.Hour
	}
	cs.wg.Add(1)
	go func() {
		defer cs.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("[ERROR] OCSP refresh panic: %v\n", r)
			}
		}()
		tickerInterval := interval
		if tickerInterval <= 0 {
			tickerInterval = 1 * time.Hour
		}
		ticker := time.NewTicker(tickerInterval)
		defer ticker.Stop()
		for {
			select {
			case <-cs.stopReload:
				return
			case <-ticker.C:
				cs.StapleOCSP()
			}
		}
	}()
}

// Ensure crypto import is used
var _ = crypto.SHA1
