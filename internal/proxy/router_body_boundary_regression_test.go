package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type bufferBoundaryTransport func(*http.Request) (*http.Response, error)

func (f bufferBoundaryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type bufferBoundaryBody struct {
	*strings.Reader
	terminal          error
	onEOF             func()
	bytesRead, closes int
	closed            bool
}

func (b *bufferBoundaryBody) Read(p []byte) (int, error) {
	if b.closed {
		return 0, errors.New("read after close")
	}
	n, err := b.Reader.Read(p)
	b.bytesRead += n
	if err == io.EOF {
		if b.terminal != nil {
			return n, b.terminal
		}
		if b.onEOF != nil {
			b.onEOF()
		}
	}
	return n, err
}

func (b *bufferBoundaryBody) Close() error { b.closes++; b.closed = true; return nil }

// Regression: the retry buffer must read the source terminal status at the
// exact cap before committing an upstream request.
func TestRouterBufferReadsTerminalStatusAtLimit(t *testing.T) {
	cases := []struct {
		name                                  string
		size                                  int
		declared                              int64
		terminalError, failFirst, eofMetadata bool
		wantCode, wantFirst, wantSibling      int
	}{
		{name: "control_error_below_cap", size: maxRetryBodyBytes - 1, declared: maxRetryBodyBytes - 1, terminalError: true, wantCode: 400},
		{name: "error_at_cap", size: maxRetryBodyBytes, declared: maxRetryBodyBytes, terminalError: true, wantCode: 400},
		{name: "small_error", size: 7, declared: 7, terminalError: true, wantCode: 400},
		{name: "small_success", size: 7, declared: 7, wantCode: 200, wantFirst: 1},
		{name: "eof_at_cap", size: maxRetryBodyBytes, declared: maxRetryBodyBytes, wantCode: 200, wantFirst: 1},
		{name: "metadata_at_cap", size: maxRetryBodyBytes, declared: maxRetryBodyBytes, eofMetadata: true, wantCode: 200, wantFirst: 1},
		{name: "replay_below_cap", size: maxRetryBodyBytes - 1, declared: maxRetryBodyBytes - 1, failFirst: true, wantCode: 200, wantFirst: 1, wantSibling: 1},
		{name: "replay_at_cap", size: maxRetryBodyBytes, declared: maxRetryBodyBytes, failFirst: true, wantCode: 200, wantFirst: 1, wantSibling: 1},
		{name: "metadata_replayed_at_cap", size: maxRetryBodyBytes, declared: maxRetryBodyBytes, eofMetadata: true, failFirst: true, wantCode: 200, wantFirst: 1, wantSibling: 1},
		{name: "empty_replay", failFirst: true, wantCode: 200, wantFirst: 1, wantSibling: 1},
		{name: "sentinel_overflow", size: maxRetryBodyBytes + 1, declared: maxRetryBodyBytes, wantCode: 400},
		{name: "bounded_overflow", size: maxRetryBodyBytes * 2, declared: maxRetryBodyBytes, wantCode: 400},
		{name: "oversized_stream", size: maxRetryBodyBytes + 1, declared: maxRetryBodyBytes + 1, wantCode: 200, wantFirst: 1},
		{name: "oversized_failure_no_replay", size: maxRetryBodyBytes + 1, declared: maxRetryBodyBytes + 1, failFirst: true, wantCode: 502, wantFirst: 1},
		{name: "unknown_stream", size: maxRetryBodyBytes + 1, declared: -1, wantCode: 200, wantFirst: 1},
		{name: "unknown_failure_no_replay", size: maxRetryBodyBytes + 1, declared: -1, failFirst: true, wantCode: 502, wantFirst: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := strings.Repeat("x", tc.size)
			r := httptest.NewRequest(http.MethodPut, "/data", strings.NewReader(payload))
			body := &bufferBoundaryBody{Reader: strings.NewReader(payload)}
			if tc.size != 0 {
				r.Body = body
			}
			r.ContentLength = tc.declared
			if tc.terminalError {
				body.terminal = errors.New("injected terminal body read failure")
			}
			if tc.eofMetadata {
				r.Trailer = http.Header{"Digest": nil}
				body.onEOF = func() { r.Trailer.Set("Digest", "fixture-digest") }
			}
			var firstCalls, siblingCalls int
			var firstBody, siblingBody string
			var firstTrailer, siblingTrailer string
			newTarget := func(first bool) *Target {
				target, err := NewTargetWithPolicy("http://192.0.2.1", 1, TargetPolicy{AllowPrivateTargets: true})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(target.Close)
				target.proxy.Transport = bufferBoundaryTransport(func(req *http.Request) (*http.Response, error) {
					var data []byte
					var err error
					if req.Body != nil {
						data, err = io.ReadAll(req.Body)
					}
					if first {
						firstCalls++
						firstBody, firstTrailer = string(data), req.Trailer.Get("Digest")
					} else {
						siblingCalls++
						siblingBody, siblingTrailer = string(data), req.Trailer.Get("Digest")
					}
					if err != nil {
						return nil, err
					}
					if first && tc.failFirst {
						return nil, errors.New("injected transport failure after consuming body")
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
				})
				return target
			}
			first, sibling := newTarget(true), newTarget(false)
			rec := httptest.NewRecorder()
			NewRouter([]Route{{PathPrefix: "/", Balancer: NewBalancer([]*Target{first, sibling}, StrategyRoundRobin)}}).ServeHTTP(rec, r)
			if rec.Code != tc.wantCode || firstCalls != tc.wantFirst || siblingCalls != tc.wantSibling {
				t.Fatalf("EXPECTED: status=%d first_calls=%d sibling_calls=%d | ACTUAL: status=%d first_calls=%d sibling_calls=%d", tc.wantCode, tc.wantFirst, tc.wantSibling, rec.Code, firstCalls, siblingCalls)
			}
			if firstCalls > 0 && firstBody != payload || siblingCalls > 0 && siblingBody != payload {
				t.Fatalf("body changed: first_bytes=%d sibling_bytes=%d, want %d", len(firstBody), len(siblingBody), len(payload))
			}
			if tc.eofMetadata && (firstTrailer != "fixture-digest" || siblingCalls > 0 && siblingTrailer != "fixture-digest") {
				t.Fatalf("EOF metadata lost: first=%q sibling=%q", firstTrailer, siblingTrailer)
			}
			if tc.size > 0 && tc.declared >= 0 && tc.declared <= maxRetryBodyBytes {
				if body.bytesRead > maxRetryBodyBytes+1 || body.closes != 1 {
					t.Fatalf("buffering bound/close violated: bytes_read=%d closes=%d", body.bytesRead, body.closes)
				}
			}
			if rec.Code == 400 && (first.CircuitState() != CircuitClosed || first.circuit.Failures() != 0 || sibling.circuit.Failures() != 0) {
				t.Fatal("body rejection affected upstream circuit state")
			}
		})
	}
}
