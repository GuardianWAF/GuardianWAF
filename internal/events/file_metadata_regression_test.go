package events

import (
	"encoding/json"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"testing"
)

func TestFileJSONPreservesEventMetadata(t *testing.T) {
	cases := []engine.Event{{}, {ID: "normal", TenantID: "tenant-a", CountryCode: "EE", CountryName: "Estonia", TLSVersion: "TLS 1.3", TLSCipherSuite: "cipher", JA3Hash: "ja3", JA4Fingerprint: "ja4", ServerName: "example.test"}, {TenantID: "quote\"and\\slash", CountryName: "Eesti\nland", ServerName: "host.test"}}
	keys := []string{"tenant_id", "country_code", "country_name", "tls_version", "tls_cipher", "ja3_hash", "ja4_fingerprint", "sni"}
	for _, ev := range cases {
		var got, want map[string]any
		if err := json.Unmarshal([]byte(marshalEventJSON(ev)), &got); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, &want); err != nil {
			t.Fatal(err)
		}
		for _, key := range keys {
			if got[key] != want[key] {
				t.Fatalf("%s got=%v want=%v", key, got[key], want[key])
			}
		}
	}
	t.Log("FIX VERIFIED")
}
