package tls

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

// RFC 6960 sections 4.1.1 and Appendix B.1 require CertID.hashAlgorithm
// to be an AlgorithmIdentifier SEQUENCE, not adjacent OID and NULL fields.
// Decode independently of the production CertID struct.
type algorithmWireCertID struct {
	Algorithm pkix.AlgorithmIdentifier
	NameHash  []byte
	KeyHash   []byte
	Serial    *big.Int
}

type algorithmWireRequestItem struct {
	CertID algorithmWireCertID
}

type algorithmWireRequest struct {
	TBSRequest struct {
		Requests []algorithmWireRequestItem
	}
}

func decodeAlgorithmWireRequest(der []byte) (*algorithmWireRequest, error) {
	var request algorithmWireRequest
	rest, err := asn1.Unmarshal(der, &request)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || len(request.TBSRequest.Requests) != 1 {
		return nil, fmt.Errorf("expected exactly one request and no trailing bytes")
	}
	id := request.TBSRequest.Requests[0].CertID
	if !id.Algorithm.Algorithm.Equal(regOIDSHA1) || !bytes.Equal(id.Algorithm.Parameters.FullBytes, []byte{5, 0}) {
		return nil, fmt.Errorf("expected SHA-1 AlgorithmIdentifier with NULL parameters")
	}
	if len(id.NameHash) != 20 || len(id.KeyHash) != 20 || id.Serial == nil {
		return nil, fmt.Errorf("invalid CertID hash sizes or missing serial")
	}
	return &request, nil
}

func algorithmValidRequest(t *testing.T) []byte {
	t.Helper()
	var request algorithmWireRequest
	request.TBSRequest.Requests = []algorithmWireRequestItem{{CertID: algorithmWireCertID{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: regOIDSHA1, Parameters: asn1.NullRawValue},
		NameHash:  make([]byte, 20), KeyHash: make([]byte, 20), Serial: big.NewInt(42),
	}}}
	der, err := asn1.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestOCSPCertIDAlgorithmIdentifierControl(t *testing.T) {
	if _, err := decodeAlgorithmWireRequest(algorithmValidRequest(t)); err != nil {
		t.Fatalf("valid schema control rejected: %v", err)
	}
}

func TestOCSPCertIDAlgorithmIdentifierRequest(t *testing.T) {
	ca, _ := regGenCA(t)
	for _, serial := range []*big.Int{big.NewInt(1), big.NewInt(128), new(big.Int).Lsh(big.NewInt(1), 128)} {
		t.Run(serial.String(), func(t *testing.T) {
			der, err := buildOCSPRequest(ca, &x509.Certificate{SerialNumber: serial})
			if err != nil {
				t.Fatal(err)
			}
			request, err := decodeAlgorithmWireRequest(der)
			if err != nil {
				t.Fatalf("FAIL: generated OCSP request violates CertID AlgorithmIdentifier schema: %v", err)
			}
			if got := request.TBSRequest.Requests[0].CertID.Serial; got.Cmp(serial) != 0 {
				t.Fatalf("serial changed: got %v, want %v", got, serial)
			}
		})
	}
}

func TestOCSPCertIDAlgorithmIdentifierHTTP(t *testing.T) {
	responseDER := extraBuildValidOCSPResponse(t)
	requestErrors := make(chan error, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		der, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err == nil {
			_, err = decodeAlgorithmWireRequest(der)
		}
		requestErrors <- err
		if err != nil {
			http.Error(w, "malformed CertID", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(responseDER)
	}))
	defer server.Close()
	requestError := func() error {
		t.Helper()
		select {
		case err := <-requestErrors:
			return err
		default:
			t.Fatal("HTTP request did not reach fixture responder")
			return nil
		}
	}

	// Exercise the same real HTTP boundary with a correctly shaped request.
	control, err := ocspHTTPClient.Post(server.URL, "application/ocsp-request", bytes.NewReader(algorithmValidRequest(t)))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, control.Body)
	control.Body.Close()
	if requestErr := requestError(); control.StatusCode != http.StatusOK || requestErr != nil {
		t.Fatalf("valid HTTP control rejected: status=%d err=%v", control.StatusCode, requestErr)
	}

	_, _, cert := extraGenerateCertWithAIA(t, server.URL, "algorithm.example.com")
	response, err := FetchParsedOCSPResponse(cert, cert)
	requestErr := requestError()
	if err != nil {
		t.Fatalf("FAIL: FetchParsedOCSPResponse rejected by schema-validating responder: %v; request decode: %v", err, requestErr)
	}
	if requestErr != nil || response.Status != OCSPGood || !bytes.Equal(response.Raw, responseDER) {
		t.Fatalf("unexpected response or request error: response=%+v requestErr=%v", response, requestErr)
	}
}
