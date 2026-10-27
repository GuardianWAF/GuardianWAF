package engine

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)


func slotTestRequest(size int) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/upload", bytes.NewReader([]byte(strings.Repeat("a", size))))
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0 Safari/537.36")
	return r
}

func serveSlot(eng *Engine, size int) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	eng.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, slotTestRequest(size))
	return w
}

// With every slot busy a large body is refused with 503 (never forwarded
// uninspected), a small body is unaffected, and a freed slot admits it again.
func TestLargeBodyInspectionSlots(t *testing.T) {
	old := largeBodySlotTimeout
	largeBodySlotTimeout = 50 * time.Millisecond
	t.Cleanup(func() { largeBodySlotTimeout = old })

	eng, _, _ := testEngine(t)
	for range cap(eng.largeBodySlots) {
		eng.largeBodySlots <- struct{}{}
	}
	if w := serveSlot(eng, largeBodyBytes+1); w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Fatalf("large body with no free slot: status %d Retry-After %q, want 503 with Retry-After", w.Code, w.Header().Get("Retry-After"))
	}
	if got := eng.Stats().LargeBodyRejected; got != 1 {
		t.Fatalf("LargeBodyRejected = %d, want 1", got)
	}
	if w := serveSlot(eng, 4096); w.Code != http.StatusOK {
		t.Fatalf("small body while slots are busy: status %d, want 200", w.Code)
	}
	<-eng.largeBodySlots
	if w := serveSlot(eng, largeBodyBytes+1); w.Code != http.StatusOK {
		t.Fatalf("large body after a slot freed: status %d, want 200", w.Code)
	}
	if n := len(eng.largeBodySlots); n != cap(eng.largeBodySlots)-1 {
		t.Fatalf("slot not released after inspection: %d of %d busy", n, cap(eng.largeBodySlots))
	}
}

// A panic in the pipeline is recovered by Middleware and must not leak the
// slot the request held.
func TestLargeBodySlotReleasedOnPanic(t *testing.T) {
	eng, _, _ := testEngine(t)
	eng.AddLayer(OrderedLayer{Layer: &panicLayer{name: "slot-panic"}, Order: 100})
	if w := serveSlot(eng, largeBodyBytes+1); w.Code != http.StatusInternalServerError {
		t.Fatalf("panicking pipeline: status %d, want 500", w.Code)
	}
	if n := len(eng.largeBodySlots); n != 0 {
		t.Fatalf("%d slot(s) leaked after a recovered panic", n)
	}
}
