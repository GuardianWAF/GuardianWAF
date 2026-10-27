package engine

import (
	"bytes"
	"compress/zlib"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func zlibBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Regression: a compressed body the WAF could not decode (ratio heuristic,
// malformed stream, trailing junk, unsupported or stacked coding) was
// inspected as raw compressed bytes and forwarded, so a backend that
// decompresses request bodies executed a payload detectors never saw.
func TestRequestBodyDecodeFailsClosed(t *testing.T) {
	const marker = "ATTACK-MARKER"
	padded := []byte(`{"q":"` + marker + `","pad":"` + strings.Repeat(" ", 20_000) + `"}`)
	gz := gzipBytes(t, padded)

	cases := []struct {
		name      string
		encoding  []string
		body      []byte
		wantCode  int
		wantSeen  bool // detector saw the decoded marker
		wantReach bool // request reached the application
	}{
		{"high ratio gzip is decoded", []string{"gzip"}, gz, 403, true, false},
		{"x-gzip alias", []string{"x-gzip"}, gz, 403, true, false},
		{"mixed case with spaces", []string{" GZip "}, gz, 403, true, false},
		{"zlib deflate", []string{"deflate"}, zlibBytes(t, padded), 403, true, false},
		{"stacked gzip", []string{"gzip, gzip"}, gzipBytes(t, gz), 403, true, false},
		{"stacked across header lines", []string{"gzip", "gzip"}, gzipBytes(t, gz), 403, true, false},
		{"identity is passthrough", []string{"identity"}, padded, 403, true, false},
		{"malformed gzip", []string{"gzip"}, []byte("not gzip at all"), 400, false, false},
		{"truncated gzip", []string{"gzip"}, gz[:len(gz)/2], 400, false, false},
		{"gzip with trailing junk", []string{"gzip"}, append(append([]byte{}, gz...), "junk"...), 400, false, false},
		{"unsupported brotli", []string{"br"}, gz, 400, false, false},
		{"too many codings", []string{"gzip, gzip, gzip, gzip"}, gz, 400, false, false},
		{"clean gzip passes", []string{"gzip"}, gzipBytes(t, []byte(`{"q":"hello"}`)), 200, false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			e, _, _ := testEngineWithConfig(t, cfg)
			defer e.Close()
			seen := false
			e.AddLayer(OrderedLayer{Layer: modeProbeLayer{"marker", func(ctx *RequestContext) LayerResult {
				if strings.Contains(ctx.BodyString, marker) {
					seen = true
					return LayerResult{Action: ActionBlock, Findings: []Finding{{DetectorName: "marker", Score: 100}}}
				}
				return LayerResult{Action: ActionPass}
			}}, Order: OrderDetection})
			reached := false
			h := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				_, _ = io.Copy(io.Discard, r.Body)
			}))

			req := httptest.NewRequest("POST", "/api", bytes.NewReader(tc.body))
			for _, v := range tc.encoding {
				req.Header.Add("Content-Encoding", v)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != tc.wantCode || seen != tc.wantSeen || reached != tc.wantReach {
				t.Fatalf("status=%d seen=%v reached=%v, want status=%d seen=%v reached=%v",
					rr.Code, seen, reached, tc.wantCode, tc.wantSeen, tc.wantReach)
			}
		})
	}
}

func TestRequestBodyDecodeMonitorModeForwards(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = "monitor"
	e, store, _ := testEngineWithConfig(t, cfg)
	defer e.Close()
	reached := false
	h := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))

	req := httptest.NewRequest("POST", "/api", strings.NewReader("not gzip"))
	req.Header.Set("Content-Encoding", "gzip")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !reached {
		t.Fatal("monitor mode must forward an undecodable body")
	}
	if store.len() != 1 || store.get(0).Action != ActionLog {
		t.Fatal("monitor mode must log the undecodable body")
	}
}

func TestDecodeRequestBodyOverBudgetStopsUnwrapping(t *testing.T) {
	inner := bytes.Repeat([]byte("A"), 4096)
	out, reason := decodeRequestBody(gzipBytes(t, gzipBytes(t, inner)), []string{"gzip, gzip"}, 64)
	if reason != "" {
		t.Fatalf("over-budget stacked body reported %q; the size limit must decide", reason)
	}
	if len(out) != 65 {
		t.Fatalf("decoded output = %d bytes, want capped at limit+1", len(out))
	}
}
