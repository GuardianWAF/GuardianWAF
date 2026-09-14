package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Regression (hunt round 9/25): Content-Length and Transfer-Encoding were
// missing from priorityHeaders, so a header flood whose junk names sort
// before them ("A0001".."A0200" < "Content-Length" < "Transfer-Encoding")
// pushed the framing headers out of the maxInspectedHeaders budget entirely.
// The smuggling detector reads ctx.Headers["Content-Length"] /
// ["Transfer-Encoding"] — both absent — and all five smuggling vectors
// silently passed while the backend still parsed the ambiguous framing.

func TestHeaderFloodKeepsFramingHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/upload", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("Content-Length", "5")
	r.Header.Set("Transfer-Encoding", "chunked")
	for i := range 200 {
		r.Header.Set(fmt.Sprintf("A%04d", i), "junk")
	}

	ctx := AcquireContext(r, 1, 1024)
	defer ReleaseContext(ctx)

	if got := ctx.Headers["Transfer-Encoding"]; len(got) == 0 {
		t.Fatalf("FAIL: Transfer-Encoding dropped under header flood — the smuggling detector cannot see the framing header")
	}
	if got := ctx.Headers["Content-Length"]; len(got) == 0 {
		t.Fatalf("FAIL: Content-Length dropped under header flood — the smuggling detector cannot see the framing header")
	}
}
