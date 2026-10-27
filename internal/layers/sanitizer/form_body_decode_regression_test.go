package sanitizer

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: urlencoded form bodies were percent-decoded by NormalizeAll,
// which leaves '+' in place, so "'+OR+1=1+--" reached detectors and classic
// payloads in every HTML form scored zero.
func TestInspectionBodyDecodesFormURLEncoded(t *testing.T) {
	cases := []struct{ ct, body, want string }{
		{"application/x-www-form-urlencoded", "comment=%27+OR+1%3D1+--&x=1", "comment=' OR 1=1 --&x=1"},
		{"Application/X-WWW-Form-URLEncoded; charset=UTF-8", "q=a+b", "q=a b"},
		{"application/x-www-form-urlencoded", "flag&bad=%zz", "flag&bad=%zz"},
		{"application/json", `{"q":"a+b"}`, `{"q":"a+b"}`},
		{"", "a+b", "a+b"},
	}
	for _, tc := range cases {
		ctx := &engine.RequestContext{ContentType: tc.ct, BodyString: tc.body}
		if got := inspectionBody(ctx); got != tc.want {
			t.Errorf("inspectionBody(%q, %q) = %q, want %q", tc.ct, tc.body, got, tc.want)
		}
	}
}
