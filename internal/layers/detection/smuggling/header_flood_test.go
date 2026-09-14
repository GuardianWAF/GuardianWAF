package smuggling

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (hunt round 9/25): under a header flood whose junk names sort
// before "Content-Length"/"Transfer-Encoding", the framing headers were
// evicted from ctx.Headers (they were missing from priorityHeaders), so this
// detector saw no CL and no TE — all five smuggling vectors silently passed
// while the backend still parsed the ambiguous framing. Framing headers must
// be flood-immune (priorityHeaders).

func TestHeaderFloodDoesNotHideSmugglingVectors(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/upload", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("Content-Length", "5")
	r.Header.Set("Transfer-Encoding", "chunked")
	for i := range 200 {
		r.Header.Set(fmt.Sprintf("A%04d", i), "junk")
	}

	ctx := engine.AcquireContext(r, 1, 1024)
	defer engine.ReleaseContext(ctx)

	d := NewDetector(true, 1)
	res := d.Process(ctx)
	if len(res.Findings) == 0 {
		t.Fatalf("FAIL: CL.TE smuggling produced zero findings under header flooding — the framing headers were evicted from the inspection budget")
	}
}
