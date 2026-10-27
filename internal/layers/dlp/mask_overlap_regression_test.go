package dlp

import "testing"

// Regression (F175): two patterns matching the same bytes (an api_key value
// that is itself a card number) were substituted independently, the second
// at offsets the first had shifted — deleting or duplicating response bytes
// outside every match, nondeterministically (map-ordered Scan results).
func TestMaskContent_OverlappingMatchesDoNotCorruptBody(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, ScanResponse: true, MaskResponse: true,
		Patterns: []string{"credit_card", "api_key", "private_key"}})
	cases := []struct{ in, want string }{
		{`{"api_key":"4111111111111111","note":"rest"}`, `{"api_key":"****-****-****-1111","note":"rest"}`},
		{"x -----BEGIN PRIVATE KEY-----\ntoken=ABCDEFGHIJKLMNOPQRSTUVWXYZ\n-----END PRIVATE KEY-----", "x [PRIVATE KEY REMOVED]"},
		{`{"api_key":"ABCDEFGHIJKLMNOPQR","card":"4111111111111111"}`, `{"api_key":"ABCD****OPQR","card":"****-****-****-1111"}`},
	}
	for _, c := range cases {
		for i := range 200 {
			_, out := layer.ScanResponse([]byte(c.in), "application/json")
			if string(out) != c.want {
				t.Fatalf("iteration %d: masked %q\n got  %q\n want %q", i, c.in, out, c.want)
			}
		}
	}
}
