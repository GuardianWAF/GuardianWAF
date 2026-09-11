package engine

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
)

// Regression tests (rounds 83-84): AcquireContext originally built ctx.Cookies
// with a LAST-wins overwrite loop, while Go backends read cookies via
// r.Cookie(name) — which returns the FIRST match (net/http readCookies
// order). With a cookie name repeated across Cookie header lines the WAF
// validated a different value than the application reads, attacker-
// orderable: violating-first + valid-last passed validation while the
// backend read the violating value. Round 83 flipped the capture to
// first-wins; round 84 evolved it further: ctx.Cookies carries ALL
// transmitted values per name in transmission order (mirroring
// QueryParams/Headers), so every inspection surface sees every value.
// vals[0] remains the r.Cookie() view a Go backend reads.

func readRequestRaw(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("http.ReadRequest: %v", err)
	}
	return req
}

func TestCookieCaptureMatchesRCookieFirstWins(t *testing.T) {
	// The round-83 bug scenario: violating value first, valid value last.
	// The capture must hold ALL transmitted values in transmission order,
	// and vals[0] must equal the r.Cookie() view a Go backend reads.
	req := readRequestRaw(t, "GET / HTTP/1.1\r\nHost: x\r\nCookie: session_id=omega\r\nCookie: session_id=alpha\r\n\r\n")
	ctx := AcquireContext(req, 0, 1<<20)
	defer ReleaseContext(ctx)

	got := ctx.Cookies["session_id"]
	if len(got) != 2 || got[0] != "omega" || got[1] != "alpha" {
		t.Fatalf("FAIL: expected both values in transmission order [omega alpha], got %v", got)
	}
	backend, err := req.Cookie("session_id")
	if err != nil {
		t.Fatalf("r.Cookie: %v", err)
	}
	if got[0] != backend.Value {
		t.Fatalf("FAIL: vals[0] = %q but the backend reads %q (r.Cookie first-wins)", got[0], backend.Value)
	}
}

func TestCookieCaptureOrderSwapStillMatches(t *testing.T) {
	req := readRequestRaw(t, "GET / HTTP/1.1\r\nHost: x\r\nCookie: session_id=alpha\r\nCookie: session_id=omega\r\n\r\n")
	ctx := AcquireContext(req, 0, 1<<20)
	defer ReleaseContext(ctx)

	got := ctx.Cookies["session_id"]
	if len(got) != 2 || got[0] != "alpha" || got[1] != "omega" {
		t.Fatalf("FAIL: order swap — expected [alpha omega], got %v", got)
	}
	backend, err := req.Cookie("session_id")
	if err != nil {
		t.Fatalf("r.Cookie: %v", err)
	}
	if got[0] != backend.Value {
		t.Fatalf("FAIL: vals[0] = %q, backend reads %q", got[0], backend.Value)
	}
}

func TestCookieCaptureSingleValueUnchanged(t *testing.T) {
	req := readRequestRaw(t, "GET / HTTP/1.1\r\nHost: x\r\nCookie: session_id=alpha; theme=dark\r\n\r\n")
	ctx := AcquireContext(req, 0, 1<<20)
	defer ReleaseContext(ctx)

	if got := ctx.Cookies["session_id"]; len(got) != 1 || got[0] != "alpha" {
		t.Fatalf("FAIL: single-value cookie capture changed: %v", got)
	}
	if got := ctx.Cookies["theme"]; len(got) != 1 || got[0] != "dark" {
		t.Fatalf("FAIL: second cookie missing: %v", got)
	}
}

func TestCookieCaptureEmptyValueStillPresent(t *testing.T) {
	// "session_id=" transmits a cookie with an empty value; r.Cookie returns
	// it, so the capture must too (present-but-empty, not missing).
	req := readRequestRaw(t, "GET / HTTP/1.1\r\nHost: x\r\nCookie: session_id=\r\n\r\n")
	ctx := AcquireContext(req, 0, 1<<20)
	defer ReleaseContext(ctx)

	if _, err := req.Cookie("session_id"); err != nil {
		t.Fatalf("fixture broken: r.Cookie reports missing: %v", err)
	}
	got, ok := ctx.Cookies["session_id"]
	if !ok {
		t.Fatalf("FAIL: transmitted empty cookie missing from capture")
	}
	if len(got) != 1 || got[0] != "" {
		t.Fatalf("FAIL: empty-value cookie captured as %v", got)
	}
}

func TestCookieCaptureNoCookiesEmptyMap(t *testing.T) {
	req := readRequestRaw(t, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	ctx := AcquireContext(req, 0, 1<<20)
	defer ReleaseContext(ctx)

	if len(ctx.Cookies) != 0 {
		t.Fatalf("FAIL: cookieless request captured cookies: %v", ctx.Cookies)
	}
}
