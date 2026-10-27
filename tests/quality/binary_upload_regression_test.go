package quality

import (
	"bytes"
	"math/rand/v2"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: the default block_null_bytes check ran over the raw body, so
// every binary upload (multipart or raw) contained a NUL, scored 60 and was
// blocked by the full pipeline.
func TestBinaryUploadsPassEndToEnd(t *testing.T) {
	eng := newPipeline(t)
	rng := rand.New(rand.NewPCG(7, 7))
	blob := make([]byte, 64<<10)
	for i := range blob {
		blob[i] = byte(rng.UintN(256))
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("caption", "Holiday photo")
	fw, _ := w.CreateFormFile("photo", "beach.jpg")
	_, _ = fw.Write(append([]byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00"), blob...))
	_ = w.Close()
	reqs := map[string]*http.Request{"multipart": httptest.NewRequest(http.MethodPost, "/upload", &buf)}
	reqs["multipart"].Header.Set("Content-Type", w.FormDataContentType())
	for _, ct := range []string{"application/octet-stream", "application/pdf", "image/png"} {
		r := httptest.NewRequest(http.MethodPut, "/files/blob", bytes.NewReader(blob))
		r.Header.Set("Content-Type", ct)
		reqs[ct] = r
	}

	n := 0
	for name, r := range reqs {
		n++
		browserHeaders(r, n)
		if ev := eng.Check(r); ev.Action == engine.ActionBlock {
			t.Errorf("%s upload blocked (score %d): %v", name, ev.Score, ev.Findings)
		}
	}
}

// A binary media type does not hide a text payload: only a body that really
// is binary skips text inspection.
func TestTextUnderBinaryMediaTypeStillInspected(t *testing.T) {
	eng := newPipeline(t)
	r := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader([]byte("q=' OR 1=1 --")))
	r.Header.Set("Content-Type", "application/octet-stream")
	browserHeaders(r, 1)
	if ev := eng.Check(r); ev.Action != engine.ActionBlock {
		t.Fatalf("SQLi under application/octet-stream not blocked (score %d)", ev.Score)
	}
}
