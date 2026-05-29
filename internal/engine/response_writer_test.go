package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMaskingResponseWriter_TextJSON(t *testing.T) {
	maskFn := func(body string) string {
		return strings.ReplaceAll(body, "SECRET", "******")
	}

	inner := httptest.NewRecorder()
	mwr := newMaskingResponseWriter(inner, maskFn, nil)
	mwr.Header().Set("Content-Type", "application/json; charset=utf-8")

	data := []byte(`{"card":"SECRET123"}`)
	n, err := mwr.Write(data)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Fatalf("expected %d bytes written, got %d", len(data), n)
	}

	mwr.FlushMasked()

	got := inner.Body.String()
	want := `{"card":"******123"}`
	if got != want {
		t.Errorf("masked body: got %q, want %q", got, want)
	}
}

func TestMaskingResponseWriter_Html(t *testing.T) {
	maskFn := func(body string) string {
		return strings.ReplaceAll(body, "secret", "*****")
	}

	inner := httptest.NewRecorder()
	mwr := newMaskingResponseWriter(inner, maskFn, nil)
	mwr.Header().Set("Content-Type", "text/html")

	mwr.Write([]byte("<p>my secret data</p>"))
	mwr.FlushMasked()

	got := inner.Body.String()
	want := "<p>my ***** data</p>"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMaskingResponseWriter_BinaryPassthrough(t *testing.T) {
	maskFn := func(body string) string {
		return "MASKED" // should never be called
	}

	inner := httptest.NewRecorder()
	mwr := newMaskingResponseWriter(inner, maskFn, nil)
	mwr.Header().Set("Content-Type", "image/png")

	body := []byte("binary-data-here")
	mwr.Write(body)
	mwr.FlushMasked()

	got := inner.Body.String()
	if got != "binary-data-here" {
		t.Errorf("binary response should pass through unmodified, got %q", got)
	}
}

func TestMaskingResponseWriter_LargeBodyPassthrough(t *testing.T) {
	maskFn := func(body string) string {
		return "MASKED"
	}

	inner := httptest.NewRecorder()
	mwr := newMaskingResponseWriter(inner, maskFn, nil)
	mwr.Header().Set("Content-Type", "application/json")

	// Write body larger than maxMaskingBufferSize (1 MB)
	largeBody := strings.Repeat(`{"data":"secret"}`, 100000) // ~1.5 MB
	mwr.Write([]byte(largeBody))
	mwr.FlushMasked()

	// Should have been flushed unmasked once buffer exceeded limit
	got := inner.Body.String()
	if got != largeBody {
		t.Error("large body should pass through unmasked when buffer limit exceeded")
	}
}

func TestMaskingResponseWriter_MultipleWrites(t *testing.T) {
	maskFn := func(body string) string {
		return strings.ReplaceAll(body, "X", "*")
	}

	inner := httptest.NewRecorder()
	mwr := newMaskingResponseWriter(inner, maskFn, nil)
	mwr.Header().Set("Content-Type", "text/plain")

	mwr.Write([]byte("heX"))
	mwr.Write([]byte("lo X"))
	mwr.Write([]byte("world"))
	mwr.FlushMasked()

	got := inner.Body.String()
	want := "he*lo *world"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMaskingResponseWriter_NilMaskFn(t *testing.T) {
	inner := httptest.NewRecorder()
	mwr := newMaskingResponseWriter(inner, nil, nil)
	mwr.Header().Set("Content-Type", "application/json")

	mwr.Write([]byte(`{"key":"value"}`))
	mwr.FlushMasked()

	got := inner.Body.String()
	if got != `{"key":"value"}` {
		t.Errorf("nil maskFn should pass through, got %q", got)
	}
}

func TestMaskingResponseWriter_BodyTransform(t *testing.T) {
	// bodyXform rewrites the HTML body (e.g. client-side sanitization).
	bodyXform := func(body []byte, contentType string) ([]byte, bool) {
		if !strings.Contains(contentType, "html") {
			return body, false
		}
		return []byte(strings.ReplaceAll(string(body), "<script>evil</script>", "")), true
	}

	inner := httptest.NewRecorder()
	mwr := newMaskingResponseWriter(inner, nil, bodyXform)
	mwr.Header().Set("Content-Type", "text/html")

	mwr.Write([]byte("<p>ok</p><script>evil</script>"))
	mwr.FlushMasked()

	if got, want := inner.Body.String(), "<p>ok</p>"; got != want {
		t.Errorf("body transform: got %q, want %q", got, want)
	}
}

func TestMaskingResponseWriter_BodyTransformThenMask(t *testing.T) {
	// The body transform runs first, then masking is applied to the result.
	bodyXform := func(body []byte, contentType string) ([]byte, bool) {
		return append(body, []byte(" SECRET")...), true
	}
	maskFn := func(body string) string {
		return strings.ReplaceAll(body, "SECRET", "******")
	}

	inner := httptest.NewRecorder()
	mwr := newMaskingResponseWriter(inner, maskFn, bodyXform)
	mwr.Header().Set("Content-Type", "text/plain")

	mwr.Write([]byte("hello"))
	mwr.FlushMasked()

	if got, want := inner.Body.String(), "hello ******"; got != want {
		t.Errorf("transform+mask: got %q, want %q", got, want)
	}
}

func TestMaskingResponseWriter_StatusCodes(t *testing.T) {
	inner := httptest.NewRecorder()
	mwr := newMaskingResponseWriter(inner, func(s string) string { return s }, nil)
	mwr.Header().Set("Content-Type", "application/json")
	mwr.WriteHeader(http.StatusCreated)
	mwr.Write([]byte(`{}`))
	mwr.FlushMasked()

	if inner.Code != http.StatusCreated {
		t.Errorf("status: got %d, want %d", inner.Code, http.StatusCreated)
	}
}
