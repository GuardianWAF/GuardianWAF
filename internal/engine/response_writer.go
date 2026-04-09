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
	buf       bytes.Buffer
	maskFn    func(string) string
	statusCode int
	capture   bool     // true once we decide to buffer
	decided   bool     // true once capture mode is set
	direct    bool     // true if body exceeded buffer limit — switch to passthrough
}

// newMaskingResponseWriter creates a response writer that applies maskFn to
// text-based response bodies before writing to w.
func newMaskingResponseWriter(w http.ResponseWriter, maskFn func(string) string) *maskingResponseWriter {
	return &maskingResponseWriter{
		ResponseWriter: w,
		maskFn:         maskFn,
	}
}

// WriteHeader captures the status code and passes it through.
func (m *maskingResponseWriter) WriteHeader(code int) {
	m.statusCode = code
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
			_, _ = m.ResponseWriter.Write(m.buf.Bytes())
			m.buf.Reset()
		}
		m.direct = true
		return m.ResponseWriter.Write(p)
	}

	if _, err := m.buf.Write(p); err != nil {
		// Buffer write failed (memory pressure) — flush unmasked and switch to direct
		if m.buf.Len() > 0 {
			_, _ = m.ResponseWriter.Write(m.buf.Bytes())
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

	if m.maskFn != nil {
		// maskFn operates on string, convert once
		masked := m.maskFn(string(data))
		_, _ = m.ResponseWriter.Write([]byte(masked))
	} else {
		_, _ = m.ResponseWriter.Write(data)
	}
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
