package engine

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression: Flush() only flipped the streaming-passthrough switch when its
// buffer was non-empty. The universal "send headers now" streaming idiom
// (WriteHeader + Flush before the first body write) therefore left direct
// mode off, so every subsequent write was buffered inside the masking layer
// (up to 1 MB) instead of being handed to net/http — where the standard
// output buffer would have delivered it to the client. A streamed text
// response between ~4 KB and 1 MB was withheld until the handler completed
// (FlushMasked), instead of flowing like it does without the WAF. An explicit
// Flush must switch to passthrough even when the buffer is empty.
func TestMaskingResponseWriter_FlushWithEmptyBufferStreamsSubsequentWrites(t *testing.T) {
	rec := httptest.NewRecorder()
	mwr := newMaskingResponseWriter(rec, func(s string) string { return "[masked]" + s }, nil)

	mwr.Header().Set("Content-Type", "text/event-stream")
	mwr.WriteHeader(200)
	mwr.Flush() // empty buffer — the header pre-send flush idiom

	if !mwr.direct {
		t.Fatal("Flush with an empty buffer did not switch to streaming passthrough (direct=false) — subsequent writes would be buffered until the handler completes")
	}

	if n, err := mwr.Write([]byte("data: hello\n\n")); n == 0 || err != nil {
		t.Fatalf("Write after Flush: n=%d err=%v", n, err)
	}
	if mwr.buf.Len() != 0 {
		t.Fatalf("write after Flush was buffered (%d bytes) instead of passed through", mwr.buf.Len())
	}
	if !strings.Contains(rec.Body.String(), "data: hello") {
		t.Fatalf("event not handed to the underlying writer mid-handler: body=%q", rec.Body.String())
	}
}

// Control: without an explicit Flush, text bodies stay buffered and masked at
// completion — the fix must not turn the masking layer into a full passthrough.
func TestMaskingResponseWriter_WithoutFlushStillMasksAtCompletion(t *testing.T) {
	rec := httptest.NewRecorder()
	mwr := newMaskingResponseWriter(rec, func(s string) string {
		return strings.ReplaceAll(s, "4111111111111111", "[masked-card]")
	}, nil)

	mwr.Header().Set("Content-Type", "text/html")
	mwr.WriteHeader(200)
	if _, err := mwr.Write([]byte("card=4111111111111111")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if mwr.direct {
		t.Fatal("body unexpectedly switched to passthrough without any Flush")
	}
	if strings.Contains(rec.Body.String(), "card=") {
		t.Fatalf("buffered body leaked before FlushMasked: %q", rec.Body.String())
	}

	mwr.FlushMasked()
	body := rec.Body.String()
	if strings.Contains(body, "4111111111111111") {
		t.Fatalf("card number not masked at completion: %q", body)
	}
	if !strings.Contains(body, "[masked-card]") {
		t.Fatalf("masked body missing replacement: %q", body)
	}
}
