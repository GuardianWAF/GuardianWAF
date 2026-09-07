package engine

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression tests: maskingResponseWriter transforms buffered bodies (at
// minimum StripStackTraces, which REMOVES lines), so an upstream-declared
// Content-Length can no longer be honored once the body is transformed.
// The writer must drop a stale passthrough Content-Length — both on the
// explicit WriteHeader path and on the implicit-header path where net/http
// sends headers at the first real write — or clients see truncated
// responses (io.ErrUnexpectedEOF under a larger declared length).

const clStackBody = "Service ready.\ngoroutine 1 [running]:\n\t/main.go:10 +0x20\nAll done.\n"

var clMaskedBody = "Service ready.\nAll done.\n"

// clMaskFn mimics the engine's response masking hook: a length-CHANGING
// transform (the response layer's StripStackTraces removes trace headers AND
// frame lines). The writer's Content-Length contract is what is under test,
// not the masking logic itself.
func clMaskFn(s string) string {
	lines := strings.Split(s, "\n")
	var kept []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(line, "goroutine ") || strings.HasPrefix(trimmed, "/main.go:") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

func TestMaskingWriterDropsContentLengthOnExplicitWriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	mw := newMaskingResponseWriter(rec, clMaskFn, nil)

	mw.Header().Set("Content-Type", "text/plain")
	mw.Header().Set("Content-Length", "67")
	mw.WriteHeader(200)

	if mw.Header().Get("Content-Length") != "" {
		t.Fatal("FAIL: capturing writer kept the upstream Content-Length through WriteHeader")
	}

	if _, err := fmt.Fprint(mw, clStackBody); err != nil {
		t.Fatalf("write: %v", err)
	}
	mw.FlushMasked()

	if got := rec.Body.String(); got != clMaskedBody {
		t.Fatalf("FAIL: masked body = %q, want %q", got, clMaskedBody)
	}
}

// Handlers that never call WriteHeader (net/http auto-sends headers at the
// first real write) must also lose the stale Content-Length — the deletion
// happens at the write-out point in FlushMasked.
func TestMaskingWriterDropsContentLengthOnImplicitHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	mw := newMaskingResponseWriter(rec, clMaskFn, nil)

	mw.Header().Set("Content-Type", "text/plain")
	mw.Header().Set("Content-Length", "67")

	if _, err := fmt.Fprint(mw, clStackBody); err != nil {
		t.Fatalf("write: %v", err)
	}
	mw.FlushMasked()

	if mw.Header().Get("Content-Length") != "" {
		t.Fatal("FAIL: implicit-header path kept the stale Content-Length")
	}
	if got := rec.Body.String(); got != clMaskedBody {
		t.Fatalf("FAIL: masked body = %q, want %q", got, clMaskedBody)
	}
}

// Non-captured responses (binary bodies, unknown content types) pass through
// untransformed — their Content-Length must be PRESERVED, since the body is
// delivered exactly as declared.
func TestMaskingWriterPassthroughKeepsContentLength(t *testing.T) {
	rec := httptest.NewRecorder()
	mw := newMaskingResponseWriter(rec, clMaskFn, nil)

	mw.Header().Set("Content-Type", "application/octet-stream")
	mw.Header().Set("Content-Length", "10")
	mw.WriteHeader(200)

	if mw.Header().Get("Content-Length") != "10" {
		t.Fatal("FAIL: passthrough writer dropped Content-Length although the body is untransformed")
	}

	blob := strings.Repeat("\x00\x01\x02", 4)
	if _, err := fmt.Fprint(mw, blob); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := rec.Body.String(); got != blob {
		t.Fatalf("FAIL: passthrough body corrupted: %q", got)
	}
}
