package smuggling

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// FuzzSmugglingDetector fuzzes the detector with arbitrary header values.
// The detector must never panic regardless of input.
func FuzzSmugglingDetector(f *testing.F) {
	seeds := []string{
		"chunked",
		"identity",
		"chunked, identity",
		"",
		"CHUNKED",
		"gzip, chunked",
		"chunked\r\nX: evil",
		"chunked\r\nTransfer-Encoding: identity",
		"chunked\r\n\r\nGET /admin HTTP/1.1",
		"  chunked  ",
		"\tchunked\t",
		"chunked\x00",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	d := NewDetector(true, 1.0)
	f.Fuzz(func(t *testing.T, teValue string) {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.Header = http.Header{
			"Content-Length":    {"100"},
			"Transfer-Encoding": {teValue},
		}
		r.Proto = "HTTP/1.1"
		ctx := engine.AcquireContext(r, 1, 1<<20)
		result := d.Process(ctx)
		_ = result
	})
}
