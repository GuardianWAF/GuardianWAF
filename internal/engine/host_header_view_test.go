package engine

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression: the Host header was missing from the WAF's header inspection view.
//
// AcquireContext built ctx.Headers from r.Header alone, but net/http's server
// promotes the request's Host header to Request.Host and deletes it from
// Header (http.ReadRequest does exactly that). priorityHeaders lists "Host" as
// an always-inspected priority header, and consumers read it from this view —
// the threat_intel domain-reputation check (threatintel.getHost) and
// rules-layer `header:Host` conditions — so both were inspecting nothing: a
// Host listed on a threat feed was never checked in production.
//
// servedRequest parses a request the way net/http's server does, which is what
// puts Host in Request.Host instead of Request.Header.
func servedRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("ReadRequest(%q): %v", raw, err)
	}
	return r
}

func TestHostHeaderPresentInInspectionView(t *testing.T) {
	r := servedRequest(t, "GET /admin HTTP/1.1\r\nHost: evil-phish.example\r\nUser-Agent: curl/8\r\n\r\n")

	// Premise: net/http moved Host out of Header. If this ever changes, the
	// rest of the test still holds (the view must expose Host either way).
	if _, ok := r.Header["Host"]; ok {
		t.Fatalf("premise changed: net/http kept Host in Header: %v", r.Header["Host"])
	}

	ctx := AcquireContext(r, 1, 1024)
	defer ReleaseContext(ctx)

	got := ctx.Headers["Host"]
	if len(got) != 1 || got[0] != "evil-phish.example" {
		t.Fatalf("Host missing from the inspection view: got %v, want [evil-phish.example]", got)
	}
	// Control: ordinary headers keep flowing through unchanged.
	if ua := ctx.Headers["User-Agent"]; len(ua) != 1 || ua[0] != "curl/8" {
		t.Errorf("unrelated header altered: User-Agent = %v", ua)
	}
}

// TestHostHeaderSurvivesHeaderFlood pins the priority guarantee that
// priorityHeaders documents for Host: an attacker padding the request with
// junk headers must not evict it from the capped selection.
func TestHostHeaderSurvivesHeaderFlood(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://evil-phish.example/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	for i := range 500 {
		r.Header.Set("X-Junk-"+strings.Repeat("a", 1)+string(rune('A'+i%26))+string(rune('0'+i%10))+string(rune('0'+(i/10)%10)), "x")
	}

	for range 20 { // repeat: selection must not vary with map iteration order
		ctx := AcquireContext(r, 1, 1024)
		got := ctx.Headers["Host"]
		if len(got) != 1 || got[0] != "evil-phish.example" {
			ReleaseContext(ctx)
			t.Fatalf("Host evicted from the inspection view under header flood: got %v", got)
		}
		if len(ctx.Headers) > maxInspectedHeaders {
			ReleaseContext(ctx)
			t.Fatalf("header count %d exceeds cap %d", len(ctx.Headers), maxInspectedHeaders)
		}
		ReleaseContext(ctx)
	}
}

// TestHostHeaderViewFallsBackToHeaderMap covers embedded/hand-built requests
// that carry Host in the header map with Request.Host unset.
func TestHostHeaderViewFallsBackToHeaderMap(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = ""
	r.Header.Set("Host", "fallback.example")

	ctx := AcquireContext(r, 1, 1024)
	defer ReleaseContext(ctx)

	got := ctx.Headers["Host"]
	if len(got) != 1 || got[0] != "fallback.example" {
		t.Fatalf("Host not taken from the header map when Request.Host is empty: got %v", got)
	}
}

// TestNoHostInventedWhenRequestHasNone is the boundary the view must not cross:
// an HTTP/1.0-style request with no Host at all must not gain a synthetic one.
func TestNoHostInventedWhenRequestHasNone(t *testing.T) {
	r := servedRequest(t, "GET / HTTP/1.0\r\nUser-Agent: curl/8\r\n\r\n")
	r.Host = ""

	ctx := AcquireContext(r, 1, 1024)
	defer ReleaseContext(ctx)

	if got, ok := ctx.Headers["Host"]; ok {
		t.Fatalf("Host invented for a request that carried none: %v", got)
	}
}
