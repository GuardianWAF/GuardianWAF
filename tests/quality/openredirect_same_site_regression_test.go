package quality

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: the sanitizer's normalized view collapses "https://host" to
// "https:/host", and the scheme-without-slash rule judged that artifact as an
// external redirect, blocking every absolute same-site next= target.
func TestOpenRedirectSameSiteAndEncodedExternal(t *testing.T) {
	eng := newPipeline(t)
	cases := []struct {
		target string
		block  bool
	}{
		{"https://example.com/cart", false},
		{"https://shop.example.com/products/42?utm_source=mail", false},
		{"https%3A%2F%2Fexample.com%2Fcart", false},
		{"/account/orders", false},
		{"https://evil.com", true},
		{"//evil.com", true},
		{"https:/evil.com", true},
		{"https:evil.com", true},
		{"https%3A%2F%2Fevil.com", true},
		{"https:%2F%2Fevil.com", true},
		{`/\evil.com`, true},
	}
	for i, tc := range cases {
		r := placements["redirect"](tc.target)
		browserHeaders(r, i+1)
		ev := eng.Check(r)
		if got := ev.Action == engine.ActionBlock; got != tc.block {
			t.Errorf("next=%q: action=%v score=%d, want block=%v", tc.target, ev.Action, ev.Score, tc.block)
		}
	}
}
