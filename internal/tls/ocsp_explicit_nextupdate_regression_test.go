package tls

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// explicitNextUpdateResponse uses RFC 6960 section 4.2.1's [0] EXPLICIT
// GeneralizedTime, unlike the older untagged timestamp fixtures. Signatures
// are placeholders: the production parser intentionally does not verify them.
func explicitNextUpdateResponse(t *testing.T, nextUpdate []byte) []byte {
	t.Helper()
	marshal := func(v any) []byte {
		t.Helper()
		der, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	alg := pkix.AlgorithmIdentifier{Algorithm: regOIDSHA1, Parameters: asn1.NullRawValue}
	certID := marshal(regCertID{Alg: alg, NameHash: make([]byte, 20), KeyHash: make([]byte, 20), Serial: big.NewInt(42)})
	thisUpdate := regGenTime(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	single := regTLV(0, 16, true, regConcat(certID, regTLV(2, 0, false, nil), thisUpdate, nextUpdate))
	// byKey is an explicitly tagged OCTET STRING.
	responderID := regTLV(2, 2, true, marshal(make([]byte, 20)))
	tbs := regTLV(0, 16, true, regConcat(responderID, thisUpdate, regTLV(0, 16, true, single)))
	sigAlg := marshal(pkix.AlgorithmIdentifier{Algorithm: regOIDSHA256RSA, Parameters: asn1.NullRawValue})
	basic := regTLV(0, 16, true, regConcat(tbs, sigAlg, regTLV(0, 3, false, []byte{0, 0})))
	rb := marshal(regRespBytes{Type: regOIDBasic, Response: basic})
	return regTLV(0, 16, true, regConcat([]byte{0x0a, 1, 0}, regTLV(2, 0, true, rb)))
}

func TestOCSPExplicitNextUpdateParsing(t *testing.T) {
	past := time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC)
	future := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		field   []byte
		want    time.Time
		wantErr bool
	}{
		{name: "expired", field: regTLV(2, 0, true, regGenTime(past)), want: past},
		{name: "unexpired", field: regTLV(2, 0, true, regGenTime(future)), want: future},
		{name: "absent"},
		{name: "extensions_without_expiry", field: regTLV(2, 1, true, regTLV(0, 16, true, nil))},
		{name: "empty_explicit_wrapper", field: regTLV(2, 0, true, nil), wantErr: true},
		{name: "invalid_explicit_time", field: regTLV(2, 0, true, regTLV(0, 24, false, []byte("not-a-time"))), wantErr: true},
		{name: "trailing_explicit_time", field: regTLV(2, 0, true, regConcat(regGenTime(past), regGenTime(future))), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := parseBasicOCSPResponse(explicitNextUpdateResponse(t, tc.field))
			if tc.wantErr {
				if err == nil {
					t.Fatal("FAIL: malformed explicit nextUpdate accepted as absent expiry")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !resp.NextUpdate.Equal(tc.want) {
				t.Fatalf("FAIL: NextUpdate = %v, want %v", resp.NextUpdate, tc.want)
			}
			if resp.Status != OCSPGood || resp.ThisUpdate.IsZero() {
				t.Fatalf("FAIL: unaffected status/thisUpdate changed: %+v", resp)
			}
		})
	}
}

func TestOCSPExplicitNextUpdateStaplePolicy(t *testing.T) {
	past := time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC)
	future := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name       string
		field      []byte
		wantStaple bool
	}{
		{name: "expired", field: regTLV(2, 0, true, regGenTime(past))},
		{name: "unexpired", field: regTLV(2, 0, true, regGenTime(future)), wantStaple: true},
		{name: "absent", wantStaple: true},
		{name: "malformed", field: regTLV(2, 0, true, nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der := explicitNextUpdateResponse(t, tc.field)
			domain := tc.name + ".example.com"
			cs, _ := staplePolicySetup(t, der, domain)
			cs.StapleOCSP()
			got := stapledBytes(cs, domain)
			if tc.wantStaple {
				if !bytes.Equal(got, der) {
					t.Fatal("FAIL: valid control response was not stapled intact")
				}
			} else if len(got) != 0 {
				t.Fatalf("FAIL: %s explicit nextUpdate response was stapled (%d bytes)", tc.name, len(got))
			}
		})
	}
}
