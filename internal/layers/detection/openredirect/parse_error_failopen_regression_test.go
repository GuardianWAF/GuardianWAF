package openredirect

import (
	"net/http"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// TestRedirectTargetsRejectedByURLParse is the F197 regression: checkValue
// returned no finding whenever url.Parse failed, but browsers still follow
// "https://evil.com/%zz" (invalid escape), an interior DEL, or a value with
// leading C0 controls (stripped by the WHATWG parser) off-site.
func TestRedirectTargetsRejectedByURLParse(t *testing.T) {
	d := NewDetector(true, 1.0)
	cases := []struct {
		val       string
		wantBlock bool
	}{
		{"https://evil.com/%zz", true},
		{"https://evil.com/\x7f", true},
		{"\x01https://evil.com/", true},
		{"https://evil.com/%", true},
		{"\x01//evil.com/%zz", true},
		{"/100%off", false},
		{"https://app.example.com/%zz", false},
		{"https://sub.app.example.com/\x7f", false},
		{"\x01\x02", false},
	}
	for _, tc := range cases {
		ctx := &engine.RequestContext{
			Request:     &http.Request{Host: "app.example.com"},
			QueryParams: map[string][]string{"next": {tc.val}},
			Headers:     map[string][]string{},
		}
		got := d.Process(ctx).Score
		if (got >= 50) != tc.wantBlock {
			t.Errorf("next=%q: score=%d, wantBlock=%v", tc.val, got, tc.wantBlock)
		}
	}
}

// TestBrowserLenientURLIsFixedPoint guards the recursion bound in checkValue.
func TestBrowserLenientURLIsFixedPoint(t *testing.T) {
	for _, in := range []string{"https://evil.com/%zz", "\x01a\x7f%", "%", "", "%2", "ok%41"} {
		once := browserLenientURL(in)
		if twice := browserLenientURL(once); twice != once {
			t.Errorf("browserLenientURL not idempotent for %q: %q -> %q", in, once, twice)
		}
	}
}
