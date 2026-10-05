package engine

import (
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

type bodyReplayFailureReader struct {
	r      *strings.Reader
	prefix int
	failed bool
	closed bool
}

func (r *bodyReplayFailureReader) Read(p []byte) (int, error) {
	if !r.failed {
		r.failed = true
		n, _ := r.r.Read(p[:min(r.prefix, len(p))])
		return n, errors.New("injected read error")
	}
	return r.r.Read(p)
}
func (r *bodyReplayFailureReader) Close() error { r.closed = true; return nil }
func TestAcquireContextPreservesBodyAfterReadError(t *testing.T) {
	for _, body := range []string{"", "hello-world"} {
		for _, prefix := range []int{0, 1, 2, len(body)} {
			input := &bodyReplayFailureReader{r: strings.NewReader(body), prefix: prefix}
			r := httptest.NewRequest("POST", "/", nil)
			r.Body = input
			ctx := AcquireContext(r, 2, 100)
			got, err := io.ReadAll(r.Body)
			if err != nil || string(got) != body {
				t.Fatalf("body=%q prefix=%d got=%q err=%v", body, prefix, got, err)
			}
			if err = r.Body.Close(); err != nil || !input.closed {
				t.Fatal("original body was not closed")
			}
			ReleaseContext(ctx)
		}
	}
	t.Log("FIX VERIFIED")
}
