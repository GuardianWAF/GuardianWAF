package engine

import (
	"bytes"
	"net/http"
	"strings"
)

const maxMaskingBufferSize = 1 << 20 // 1 MB — larger responses stream unmasked

// maskingResponseWriter wraps http.ResponseWriter to buffer text-based response
// bodies and apply data masking (credit cards, SSN, API keys) before writing to
// the underlying writer. Non-text responses pass through with zero overhead.
type maskingResponseWriter struct {
	http.ResponseWriter
	buf        bytes.Buffer
	maskFn     func(string) string
	bodyXform  func([]byte, string) ([]byte, bool) // client-side body transform (Magecart/agent-injection)
	statusCode int
	capture    bool // true once we decide to buffer
	decided    bool // true once capture mode is set
	direct     bool // true if body exceeded buffer limit — switch to passthrough
}

// newMaskingResponseWriter creates a response writer that applies an optional
// client-side body transform and/or data-masking function to text-based
// response bodies before writing to w. Either hook may be nil.
func newMaskingResponseWriter(w http.ResponseWriter, maskFn func(string) string, bodyXform func([]byte, string) ([]byte, bool)) *maskingResponseWriter {
	return &maskingResponseWriter{
		ResponseWriter: w,
		maskFn:         maskFn,
		bodyXform:      bodyXform,
	}
}

// WriteHeader captures the status code, decides the capture mode, and passes
// through. When capturing, the upstream Content-Length is dropped: the
// buffered body is transformed before it is written (StripStackTraces removes
// lines), so the declared length can no longer be honored — a stale
// Content-Length would make clients see truncated responses.
func (m *maskingResponseWriter) WriteHeader(code int) {
	m.statusCode = code
	if !m.decided {
		m.decided = true
		m.capture = m.shouldCapture()
		if m.capture {
			m.ResponseWriter.Header().Del("Content-Length")
		}
	}
	m.ResponseWriter.WriteHeader(code)
}

// Write either buffers the data (for text responses) or passes it through directly.
func (m *maskingResponseWriter) Write(p []byte) (int, error) {
	if !m.decided {
		m.decided = true
		m.capture = m.shouldCapture()
	}

	if m.direct || !m.capture {
		return m.ResponseWriter.Write(p)
	}

	// Check buffer limit
	if m.buf.Len()+len(p) > maxMaskingBufferSize {
		// Flush buffered content unmasked, then switch to direct
		if m.buf.Len() > 0 {
			_, _ = m.ResponseWriter.Write(m.buf.Bytes()) // nolint:errcheck // buffered write flush; error ignored
			m.buf.Reset()
		}
		m.direct = true
		return m.ResponseWriter.Write(p)
	}

	if _, err := m.buf.Write(p); err != nil {
		// Buffer write failed (memory pressure) — flush unmasked and switch to direct
		if m.buf.Len() > 0 {
			_, _ = m.ResponseWriter.Write(m.buf.Bytes()) // nolint:errcheck // buffered write flush; error ignored
			m.buf.Reset()
		}
		m.direct = true
		return m.ResponseWriter.Write(p)
	}
	return len(p), nil
}

// FlushMasked applies masking to the buffered body and writes it to the
// underlying writer. Call this after next.ServeHTTP returns.
func (m *maskingResponseWriter) FlushMasked() {
	if !m.capture || m.direct {
		return
	}
	if m.buf.Len() == 0 {
		return
	}

	data := m.buf.Bytes()
	m.buf.Reset()

	// Apply the client-side body transform first (Magecart sanitization /
	// agent injection), then data masking on the resulting body.
	if m.bodyXform != nil {
		if out, changed := m.bodyXform(data, m.Header().Get("Content-Type")); changed {
			data = out
		}
	}

	if m.maskFn != nil {
		// maskFn operates on string, convert once
		data = []byte(m.maskFn(string(data)))
	}
	// The transformed body length can differ from the declared length
	// (StripStackTraces removes lines). Drop a stale passthrough
	// Content-Length before the first real write — net/http sends headers
	// here when the handler never called WriteHeader, and a stale length
	// makes clients see truncated responses.
	m.ResponseWriter.Header().Del("Content-Length")
	_, _ = m.ResponseWriter.Write(data) // nolint:errcheck // masking write; error ignored
}

// shouldCapture determines whether to buffer the response body based on
// Content-Type. Only text/* and application/json bodies are captured.
func (m *maskingResponseWriter) shouldCapture() bool {
	ct := m.Header().Get("Content-Type")
	if ct == "" {
		return false
	}
	ct = strings.ToLower(ct)
	// Strip charset etc.
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = ct[:idx]
	}
	ct = strings.TrimSpace(ct)

	return strings.HasPrefix(ct, "text/") ||
		ct == "application/json" ||
		ct == "application/xml" ||
		strings.HasSuffix(ct, "+json") ||
		strings.HasSuffix(ct, "+xml")
}

// Unwrap returns the underlying http.ResponseWriter for http.ResponseController.
func (m *maskingResponseWriter) Unwrap() http.ResponseWriter {
	return m.ResponseWriter
}

// Flush implements http.Flusher. Flushes buffered content to the underlying writer.
// For streaming responses (SSE, chunked), buffered content is flushed unmasked and
// subsequent writes switch to passthrough since incremental masking is not possible.
func (m *maskingResponseWriter) Flush() {
	// An explicit Flush switches the writer to streaming passthrough even
	// when the buffer is empty: the common "send headers now" idiom
	// (WriteHeader + Flush before the first body write) must not leave
	// subsequent writes buffered — incremental masking is impossible for a
	// stream, so buffering them would stall SSE/chunked responses until the
	// handler returns or the 1 MB limit flushes them unmasked anyway.
	if m.capture && !m.direct {
		if m.buf.Len() > 0 {
			// Cannot mask streaming content incrementally — flush buffered as-is
			_, _ = m.ResponseWriter.Write(m.buf.Bytes()) // nolint:errcheck // buffered write flush; error ignored
			m.buf.Reset()
		}
		m.direct = true // switch to passthrough for subsequent writes
	}
	if f, ok := m.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
