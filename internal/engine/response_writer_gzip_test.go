package engine

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// F177: body transforms must not splice plaintext into compressed bytes.
func TestMaskingResponseWriter_GzipBodyStaysDecodable(t *testing.T) {
	xform := func(b []byte, _ string) ([]byte, bool) {
		return append([]byte("<script>agent</script>"), b...), true
	}
	mask := func(s string) string { return strings.ReplaceAll(s, "4111111111111111", "****") }

	run := func(encoding string, body []byte) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		w := newMaskingResponseWriter(rec, mask, xform)
		w.Header().Set("Content-Type", "text/html")
		if encoding != "" {
			w.Header().Set("Content-Encoding", encoding)
		}
		w.WriteHeader(200)
		_, _ = w.Write(body)
		w.FlushMasked()
		return rec
	}

	t.Run("gzip transformed and re-encoded", func(t *testing.T) {
		rec := run("gzip", gzipBytes(t, []byte("<html>card 4111111111111111</html>")))
		zr, err := gzip.NewReader(rec.Body)
		if err != nil {
			t.Fatalf("response no longer gunzips: %v", err)
		}
		got, _ := io.ReadAll(zr)
		if want := "<script>agent</script><html>card ****</html>"; string(got) != want {
			t.Fatalf("decoded body = %q, want %q", got, want)
		}
	})

	t.Run("identity control", func(t *testing.T) {
		rec := run("", []byte("<html>x</html>"))
		if got := rec.Body.String(); got != "<script>agent</script><html>x</html>" {
			t.Fatalf("body = %q", got)
		}
	})

	t.Run("unsupported encoding passes through", func(t *testing.T) {
		raw := []byte{0xce, 0xb2, 0xcf, 0x81}
		rec := run("br", raw)
		if !bytes.Equal(rec.Body.Bytes(), raw) {
			t.Fatalf("br body modified: %q", rec.Body.Bytes())
		}
	})

	t.Run("malformed gzip passes through", func(t *testing.T) {
		raw := []byte("not gzip at all")
		rec := run("gzip", raw)
		if !bytes.Equal(rec.Body.Bytes(), raw) {
			t.Fatalf("malformed gzip body modified: %q", rec.Body.Bytes())
		}
	})

	t.Run("oversized decoded body passes through", func(t *testing.T) {
		raw := gzipBytes(t, bytes.Repeat([]byte("a"), maxMaskingBufferSize+1))
		rec := run("gzip", raw)
		if !bytes.Equal(rec.Body.Bytes(), raw) {
			t.Fatal("bomb-sized gzip body was modified")
		}
	})
}
