package engine

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCORSHookPreservesVary(t *testing.T) {
	for _, preflight := range []bool{false, true} {
		for _, values := range [][]string{nil, {"Accept-Encoding"}, {"Accept-Encoding, origin"}, {"Accept-Encoding", "Accept-Language"}, {"*"}} {
			w := httptest.NewRecorder()
			for _, v := range values {
				w.Header().Add("Vary", v)
			}
			ctx := &RequestContext{}
			if preflight {
				ctx.CORSPreflightHeaders = map[string]string{"Access-Control-Allow-Origin": "https://example.test"}
			} else {
				ctx.CORSHeaders = map[string]string{"Access-Control-Allow-Origin": "https://example.test"}
			}
			applyCORSHook(w, ctx)
			applyCORSHook(w, ctx)
			joined := strings.Join(w.Header().Values("Vary"), ",")
			for _, v := range values {
				if !strings.Contains(joined, v) {
					t.Fatalf("lost Vary=%q in %q", v, joined)
				}
			}
			count := 0
			star := false
			for _, v := range strings.Split(joined, ",") {
				v = strings.TrimSpace(v)
				if strings.EqualFold(v, "Origin") {
					count++
				}
				if v == "*" {
					star = true
				}
			}
			if !star && count != 1 || star && count != 0 {
				t.Fatalf("unexpected Origin count %d in %q", count, joined)
			}
		}
	}
	t.Log("FIX VERIFIED")
}
