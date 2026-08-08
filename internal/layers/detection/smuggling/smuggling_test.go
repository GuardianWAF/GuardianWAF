package smuggling

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func newCtx(headers map[string][]string, proto string) *engine.RequestContext {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Proto = proto
	r.Header = headers
	ctx := engine.AcquireContext(r, 1, 1<<20)
	return ctx
}

func TestDetector_Disabled(t *testing.T) {
	d := NewDetector(false, 1.0)
	ctx := newCtx(map[string][]string{
		"Content-Length":    {"100"},
		"Transfer-Encoding": {"chunked"},
	}, "HTTP/1.1")
	result := d.Process(ctx)
	if len(result.Findings) != 0 {
		t.Fatalf("disabled detector should return 0 findings, got %d", len(result.Findings))
	}
}

func TestDetector_CLandTE_Coexistence(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := newCtx(map[string][]string{
		"Content-Length":    {"100"},
		"Transfer-Encoding": {"chunked"},
	}, "HTTP/1.1")
	result := d.Process(ctx)
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding for CL+TE, got %d", len(result.Findings))
	}
	if result.Findings[0].Severity != engine.SeverityCritical {
		t.Errorf("expected critical severity, got %v", result.Findings[0].Severity)
	}
	if result.Findings[0].Category != "http-request-smuggling" {
		t.Errorf("expected http-request-smuggling category, got %s", result.Findings[0].Category)
	}
}

func TestDetector_DuplicateContentLength_Different(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := newCtx(map[string][]string{
		"Content-Length": {"0", "100"},
	}, "HTTP/1.1")
	result := d.Process(ctx)
	found := false
	for _, f := range result.Findings {
		if f.Description != "" && contains(f.Description, "duplicate Content-Length") {
			found = true
			if f.Severity != engine.SeverityCritical {
				t.Errorf("expected critical for duplicate CL, got %v", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected duplicate Content-Length finding, got %+v", result.Findings)
	}
}

func TestDetector_DuplicateContentLength_Same(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := newCtx(map[string][]string{
		"Content-Length": {"100", "100"},
	}, "HTTP/1.1")
	result := d.Process(ctx)
	for _, f := range result.Findings {
		if contains(f.Description, "duplicate Content-Length") {
			t.Fatalf("should not flag duplicate CL with same values, got: %s", f.Description)
		}
	}
}

func TestDetector_ObfuscatedTE(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"exact chunked", "chunked", false},
		{"exact chunked upper", "CHUNKED", false},
		{"chunked with spaces", " chunked ", false},
		{"chunked identity", "chunked, identity", true},
		{"bare identity", "identity", true},
		{"gzip chunked", "gzip, chunked", true},
		{"xchunked", "xchunked", true},
		{"empty", "", true},
	}

	d := NewDetector(true, 1.0)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newCtx(map[string][]string{
				"Transfer-Encoding": {tt.value},
			}, "HTTP/1.1")
			result := d.Process(ctx)
			hasObfuscation := false
			for _, f := range result.Findings {
				if contains(f.Description, "not exactly") {
					hasObfuscation = true
				}
			}
			if hasObfuscation != tt.want {
				t.Errorf("isExactChunked(%q): got obfuscation=%v, want %v", tt.value, hasObfuscation, tt.want)
			}
		})
	}
}

func TestDetector_MultipleTE(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := newCtx(map[string][]string{
		"Transfer-Encoding": {"chunked", "identity"},
	}, "HTTP/1.1")
	result := d.Process(ctx)
	foundDup := false
	for _, f := range result.Findings {
		if contains(f.Description, "multiple Transfer-Encoding") {
			foundDup = true
		}
	}
	if !foundDup {
		t.Fatalf("expected duplicate TE finding, got %+v", result.Findings)
	}
}

func TestDetector_HTTP10WithTE(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := newCtx(map[string][]string{
		"Transfer-Encoding": {"chunked"},
	}, "HTTP/1.0")
	result := d.Process(ctx)
	found := false
	for _, f := range result.Findings {
		if contains(f.Description, "HTTP/1.0") {
			found = true
			if f.Severity != engine.SeverityMedium {
				t.Errorf("expected medium for HTTP/1.0+TE, got %v", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected HTTP/1.0+TE finding, got %+v", result.Findings)
	}
}

func TestDetector_HTTP11WithTE_NoFinding(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := newCtx(map[string][]string{
		"Transfer-Encoding": {"chunked"},
	}, "HTTP/1.1")
	result := d.Process(ctx)
	for _, f := range result.Findings {
		if contains(f.Description, "HTTP/1.0") {
			t.Fatalf("should not flag HTTP/1.1+TE, got: %s", f.Description)
		}
	}
}

func TestDetector_CleanRequest(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := newCtx(map[string][]string{
		"Content-Type": {"application/json"},
	}, "HTTP/1.1")
	result := d.Process(ctx)
	if len(result.Findings) != 0 {
		t.Fatalf("clean request should have 0 findings, got %d: %+v", len(result.Findings), result.Findings)
	}
}

func TestDetector_Multiplier(t *testing.T) {
	d := NewDetector(true, 2.0)
	ctx := newCtx(map[string][]string{
		"Content-Length":    {"100"},
		"Transfer-Encoding": {"chunked"},
	}, "HTTP/1.1")
	result := d.Process(ctx)
	if result.Score != 200 {
		t.Errorf("expected score 200 (100×2.0), got %d", result.Score)
	}
}

func TestDetector_Name(t *testing.T) {
	d := NewDetector(true, 1.0)
	if d.Name() != "smuggling-detector" {
		t.Errorf("expected smuggling-detector, got %s", d.Name())
	}
	if d.DetectorName() != "smuggling" {
		t.Errorf("expected smuggling, got %s", d.DetectorName())
	}
}

func TestDetector_Patterns(t *testing.T) {
	d := NewDetector(true, 1.0)
	pats := d.Patterns()
	if len(pats) != 6 {
		t.Fatalf("expected 6 patterns, got %d", len(pats))
	}
}

func TestDetector_MultipleVectors(t *testing.T) {
	d := NewDetector(true, 1.0)
	// CL + TE + duplicate CL + obfuscated TE + duplicate TE + HTTP/1.0
	ctx := newCtx(map[string][]string{
		"Content-Length":    {"0", "100"},
		"Transfer-Encoding": {"chunked", "identity"},
	}, "HTTP/1.0")
	result := d.Process(ctx)
	// Expect: CL+TE (1), dup CL (1), obfuscated TE (1), dup TE (1), HTTP/1.0+TE (1) = 5
	if len(result.Findings) < 4 {
		t.Fatalf("expected at least 4 findings for multi-vector request, got %d: %+v", len(result.Findings), result.Findings)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && containsStr(s, substr)))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
