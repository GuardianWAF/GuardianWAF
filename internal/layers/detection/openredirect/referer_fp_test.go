package openredirect

import (
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// TestReferer_IsNotARedirectTarget pins a false positive that made blocking
// mode unusable on any public site.
//
// The detector used to inspect the Referer header as though it were a redirect
// target. Referer is inbound — it says where the visitor came from, and the
// application never redirects to it. Any cross-origin referrer therefore looked
// like an open-redirect payload: an ordinary click-through from Google scored
// 60 against the default block_threshold of 50, so the first visitor arriving
// from a search engine, a social link or a partner site got a 403.
func TestReferer_IsNotARedirectTarget(t *testing.T) {
	d := NewDetector(true, 1.0)

	for _, referer := range []string{
		"https://www.google.com/",
		"https://news.ycombinator.com/item?id=1",
		"https://t.co/abc123",
		"https://partner.example.net/blog/post",
		"android-app://com.google.android.gm",
	} {
		t.Run(referer, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://example.com/product/42", nil)
			r.Header.Set("Referer", referer)
			r.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0")

			ctx := engine.AcquireContext(r, 1, 10<<20)
			defer engine.ReleaseContext(ctx)

			res := d.Process(ctx)

			score := 0
			for _, f := range res.Findings {
				score += f.Score
			}
			if res.Action == engine.ActionBlock {
				t.Fatalf("legitimate Referer %q blocked (score %d, findings %+v)", referer, score, res.Findings)
			}
			if score != 0 {
				t.Fatalf("legitimate Referer %q scored %d, want 0", referer, score)
			}
		})
	}
}

// TestLocationHeader_StillInspected guards against over-correcting the above
// into dropping redirect-header inspection altogether.
func TestLocationHeader_StillInspected(t *testing.T) {
	d := NewDetector(true, 1.0)

	r := httptest.NewRequest("GET", "http://example.com/go", nil)
	r.Header.Set("Location", "https://evil.example.net/steal")

	ctx := engine.AcquireContext(r, 1, 10<<20)
	defer engine.ReleaseContext(ctx)

	res := d.Process(ctx)
	if len(res.Findings) == 0 {
		t.Fatal("external Location header no longer flagged")
	}
}
