package tls

import (
	"bytes"
	"math/big"
	"testing"
	"time"
)

func TestOCSPFutureThisUpdateFixtureControl(t *testing.T) {
	now := time.Now()
	ca, _ := regGenCA(t)
	responseDER := buildRegResponse(t, ca, big.NewInt(42), 0, nil, now.Add(24*time.Hour), now.Add(48*time.Hour), regOIDBasic)
	response, err := parseBasicOCSPResponse(responseDER)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != OCSPGood || !response.ThisUpdate.After(now) || !response.NextUpdate.After(response.ThisUpdate) {
		t.Fatalf("fixture does not describe a future GOOD response: %+v", response)
	}
}

func TestStaplePolicy_FutureThisUpdateRefused(t *testing.T) {
	now := time.Now()
	ca, _ := regGenCA(t)
	futureDER := buildRegResponse(t, ca, big.NewInt(42), 0, nil, now.Add(24*time.Hour), now.Add(48*time.Hour), regOIDBasic)
	cs, _ := staplePolicySetup(t, futureDER, "future-thisupdate.example.com")

	cs.StapleOCSP()

	if stapled := stapledBytes(cs, "future-thisupdate.example.com"); len(stapled) != 0 {
		t.Fatalf("FAIL: OCSP response whose thisUpdate is in the future was stapled (%d bytes)", len(stapled))
	}
}

func TestStaplePolicy_CurrentValidityControl(t *testing.T) {
	now := time.Now()
	ca, _ := regGenCA(t)
	validDER := buildRegResponse(t, ca, big.NewInt(42), 0, nil, now.Add(-time.Hour), now.Add(time.Hour), regOIDBasic)
	cs, _ := staplePolicySetup(t, validDER, "current-thisupdate.example.com")

	cs.StapleOCSP()

	if stapled := stapledBytes(cs, "current-thisupdate.example.com"); !bytes.Equal(stapled, validDER) {
		t.Fatalf("validity control was not stapled intact: got %d bytes, want %d", len(stapled), len(validDER))
	}
}
