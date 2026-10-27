package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type flushChainWriter struct {
	http.ResponseWriter
	calls atomic.Int32
	err   error
}

func (w *flushChainWriter) FlushError() error {
	w.calls.Add(1)
	if w.err != nil {
		return w.err
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *flushChainWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type flushChainWrapper struct{ http.ResponseWriter }

func (w *flushChainWrapper) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func wrapFlushChain(w http.ResponseWriter, depth int) http.ResponseWriter {
	for range depth {
		w = &flushChainWrapper{ResponseWriter: w}
	}
	return w
}

type flushChainLegacyWriter struct {
	http.ResponseWriter
	calls atomic.Int32
}

func (w *flushChainLegacyWriter) Flush() { w.calls.Add(1) }

type flushChainBothWriter struct {
	*flushChainWriter
	legacyCalls atomic.Int32
}

func (w *flushChainBothWriter) Flush() { w.legacyCalls.Add(1) }

type flushChainTransport func(*http.Request) (*http.Response, error)

func (f flushChainTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type flushChainBrokenBody struct {
	*strings.Reader
	closes atomic.Int32
}

func (b *flushChainBrokenBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF {
		return n, errors.New("injected response read failure")
	}
	return n, err
}

func (b *flushChainBrokenBody) Close() error { b.closes.Add(1); return nil }

// Regression: proxy response wrapping must preserve supported controller
// operations through middleware and keep outer overrides authoritative.
func TestProxyErrorPreservesWrappedFlush(t *testing.T) {
	for _, depth := range []int{0, 1, 3} {
		for _, fail := range []bool{false, true} {
			t.Run(fmt.Sprintf("depth_%d/error_%v", depth, fail), func(t *testing.T) {
				base := &flushChainWriter{ResponseWriter: httptest.NewRecorder()}
				if fail {
					base.err = errors.New("injected flush error")
				}
				pe := &proxyError{ResponseWriter: wrapFlushChain(base, depth)}
				for call := int32(1); call <= 3; call++ {
					err := http.NewResponseController(pe).Flush()
					if !errors.Is(err, base.err) || base.calls.Load() != call {
						t.Fatalf("EXPECTED: error=%v calls=%d | ACTUAL: error=%v calls=%d", base.err, call, err, base.calls.Load())
					}
				}
				pe.Flush() // Legacy interface still flushes despite lacking an error return.
				if base.calls.Load() != 4 {
					t.Fatal("legacy Flush did not delegate")
				}
			})
		}
	}
	t.Run("legacy_only", func(t *testing.T) {
		base := &flushChainLegacyWriter{ResponseWriter: httptest.NewRecorder()}
		pe := &proxyError{ResponseWriter: wrapFlushChain(base, 2)}
		if err := http.NewResponseController(pe).Flush(); err != nil {
			t.Fatal(err)
		}
		pe.Flush()
		if base.calls.Load() != 2 {
			t.Fatal("legacy-only flusher was not called twice")
		}
	})
	t.Run("flush_error_priority", func(t *testing.T) {
		base := &flushChainBothWriter{flushChainWriter: &flushChainWriter{ResponseWriter: httptest.NewRecorder(), err: errors.New("preferred FlushError")}}
		if err := http.NewResponseController(&proxyError{ResponseWriter: base}).Flush(); !errors.Is(err, base.err) || base.calls.Load() != 1 || base.legacyCalls.Load() != 0 {
			t.Fatal("FlushError did not take priority over Flush")
		}
	})
	t.Run("outer_override", func(t *testing.T) {
		inner := &flushChainWriter{ResponseWriter: httptest.NewRecorder()}
		outer := &flushChainWriter{ResponseWriter: wrapFlushChain(inner, 2), err: errors.New("outer refuses flush")}
		if err := (&proxyError{ResponseWriter: outer}).FlushError(); !errors.Is(err, outer.err) || outer.calls.Load() != 1 || inner.calls.Load() != 0 {
			t.Fatal("outer flush implementation was bypassed")
		}
	})
	t.Run("unsupported", func(t *testing.T) {
		base := &struct{ http.ResponseWriter }{ResponseWriter: httptest.NewRecorder()}
		pe := &proxyError{ResponseWriter: wrapFlushChain(base, 2)}
		if err := http.NewResponseController(pe).Flush(); !errors.Is(err, http.ErrNotSupported) {
			t.Fatalf("unsupported flush error=%v", err)
		}
		pe.Flush() // Unsupported legacy flush remains harmless.
	})
	t.Run("target_stream", func(t *testing.T) {
		rec := httptest.NewRecorder()
		base := &flushChainWriter{ResponseWriter: rec}
		target, err := NewTargetWithPolicy("http://192.0.2.1", 1, TargetPolicy{AllowPrivateTargets: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(target.Close)
		target.proxy.Transport = flushChainTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: sample\n\n")), Request: r}, nil
		})
		if err := target.ServeHTTP(wrapFlushChain(base, 3), httptest.NewRequest("GET", "/events", nil), ""); err != nil {
			t.Fatal(err)
		}
		if rec.Code != 200 || rec.Body.String() != "data: sample\n\n" || !rec.Flushed || base.calls.Load() == 0 || target.ActiveConns() != 0 {
			t.Fatalf("EXPECTED: complete stream flushed active_conns=0 | ACTUAL: code=%d body=%q flushed=%v flush_calls=%d active_conns=%d", rec.Code, rec.Body.String(), rec.Flushed, base.calls.Load(), target.ActiveConns())
		}
	})
	t.Run("committed_stream_error_aborts_without_retry", func(t *testing.T) {
		body := &flushChainBrokenBody{Reader: strings.NewReader("partial")}
		var siblingCalls int
		newTarget := func(sibling bool) *Target {
			target, err := NewTargetWithPolicy("http://192.0.2.1", 1, TargetPolicy{AllowPrivateTargets: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(target.Close)
			target.proxy.Transport = flushChainTransport(func(r *http.Request) (*http.Response, error) {
				if sibling {
					siblingCalls++
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: body, Request: r}, nil
			})
			return target
		}
		first, sibling := newTarget(false), newTarget(true)
		rec := httptest.NewRecorder()
		base := &flushChainWriter{ResponseWriter: rec}
		r := httptest.NewRequest("GET", "/stream", nil)
		r = r.WithContext(context.WithValue(r.Context(), http.ServerContextKey, &http.Server{}))
		var panicValue any
		func() {
			defer func() { panicValue = recover() }()
			NewRouter([]Route{{PathPrefix: "/", Balancer: NewBalancer([]*Target{first, sibling}, "")}}).ServeHTTP(wrapFlushChain(base, 2), r)
		}()
		panicErr, _ := panicValue.(error)
		if !errors.Is(panicErr, http.ErrAbortHandler) || siblingCalls != 0 || rec.Code != 200 || rec.Body.String() != "partial" || body.closes.Load() != 1 || first.ActiveConns() != 0 {
			t.Fatalf("stream abort changed: panic=%v sibling_calls=%d code=%d body=%q closes=%d active_conns=%d", panicValue, siblingCalls, rec.Code, rec.Body.String(), body.closes.Load(), first.ActiveConns())
		}
	})
}
