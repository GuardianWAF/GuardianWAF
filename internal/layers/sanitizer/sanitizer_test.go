package sanitizer

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ersinkoc/guardianwaf/internal/engine"
)

// newTestContext creates a minimal RequestContext for testing.
func newTestContext(method, uri, path, body string) *engine.RequestContext {
	ctx := &engine.RequestContext{
		Method:      method,
		URI:         uri,
		Path:        path,
		QueryParams: make(map[string][]string),
		Headers:     make(map[string][]string),
		Cookies:     make(map[string]string),
		Body:        []byte(body),
		BodyString:  body,
		Accumulator: engine.NewScoreAccumulator(2),
		Metadata:    make(map[string]any),
	}
	return ctx
}

func TestSanitizerLayer_Normalize(t *testing.T) {
	cfg := SanitizerConfig{
		MaxURLLength:   2048,
		MaxHeaderSize:  8192,
		MaxHeaderCount: 50,
		MaxBodySize:    1048576,
		AllowedMethods: []string{"GET", "POST"},
	}
	layer := NewLayer(cfg)

	ctx := newTestContext("GET", "/test%20path", "/test%20path", "")
	ctx.QueryParams["q"] = []string{"%3Cscript%3E"}

	result := layer.Process(ctx)

	// NormalizedPath should be populated
	if ctx.NormalizedPath == "" {
		t.Error("NormalizedPath should be populated after processing")
	}

	// NormalizedQuery should be populated
	if len(ctx.NormalizedQuery) == 0 {
		t.Error("NormalizedQuery should be populated after processing")
	}

	// Check that query param was decoded
	if vals, ok := ctx.NormalizedQuery["q"]; ok {
		if len(vals) > 0 && !strings.Contains(vals[0], "script") {
			t.Errorf("NormalizedQuery[q] = %q, expected it to contain 'script'", vals[0])
		}
	}

	// NormalizedBody should be populated (even if empty input)
	// The body was empty, so NormalizedBody should also be minimal
	if ctx.NormalizedBody == "" && ctx.BodyString != "" {
		t.Error("NormalizedBody should be populated when BodyString is non-empty")
	}

	if result.Action != engine.ActionPass {
		t.Errorf("Expected ActionPass for valid request, got %v", result.Action)
	}
}

func TestSanitizerLayer_ValidateURLLength(t *testing.T) {
	cfg := SanitizerConfig{
		MaxURLLength:   50,
		AllowedMethods: []string{"GET"},
	}
	layer := NewLayer(cfg)

	longURL := "/" + strings.Repeat("a", 100)
	ctx := newTestContext("GET", longURL, longURL, "")

	result := layer.Process(ctx)

	if len(result.Findings) == 0 {
		t.Error("Expected findings for URL exceeding max length")
	}

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "URL length") {
			found = true
			if f.Score != 40 {
				t.Errorf("URL length violation score = %d, want 40", f.Score)
			}
			if f.Severity != engine.SeverityHigh {
				t.Errorf("URL length violation severity = %v, want SeverityHigh", f.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected a URL length finding")
	}
}

func TestSanitizerLayer_ValidateMethod(t *testing.T) {
	cfg := SanitizerConfig{
		AllowedMethods: []string{"GET", "POST"},
	}
	layer := NewLayer(cfg)

	ctx := newTestContext("DELETE", "/test", "/test", "")

	result := layer.Process(ctx)

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "not allowed") {
			found = true
			if f.Score != 50 {
				t.Errorf("Method violation score = %d, want 50", f.Score)
			}
		}
	}
	if !found {
		t.Error("Expected a disallowed method finding")
	}

	// Score is 50, should trigger block
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected ActionBlock for disallowed method (score 50), got %v", result.Action)
	}
}

func TestSanitizerLayer_ValidateNullBytes(t *testing.T) {
	cfg := SanitizerConfig{
		BlockNullBytes: true,
		AllowedMethods: []string{"GET"},
	}
	layer := NewLayer(cfg)

	ctx := newTestContext("GET", "/test%00path", "/test%00path", "")

	result := layer.Process(ctx)

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "Null byte") {
			found = true
			if f.Score != 60 {
				t.Errorf("Null byte violation score = %d, want 60", f.Score)
			}
		}
	}
	if !found {
		t.Error("Expected a null byte finding")
	}
}

func TestSanitizerLayer_HopByHopStripping(t *testing.T) {
	cfg := SanitizerConfig{
		StripHopByHop:  true,
		AllowedMethods: []string{"GET"},
	}
	layer := NewLayer(cfg)

	ctx := newTestContext("GET", "/test", "/test", "")
	ctx.Headers["Connection"] = []string{"keep-alive"}
	ctx.Headers["Keep-Alive"] = []string{"timeout=5"}
	ctx.Headers["Transfer-Encoding"] = []string{"chunked"}
	ctx.Headers["X-Custom"] = []string{"value"}

	layer.Process(ctx)

	// Hop-by-hop headers should be removed
	if _, ok := ctx.Headers["Connection"]; ok {
		t.Error("Connection header should have been stripped")
	}
	if _, ok := ctx.Headers["Keep-Alive"]; ok {
		t.Error("Keep-Alive header should have been stripped")
	}
	if _, ok := ctx.Headers["Transfer-Encoding"]; ok {
		t.Error("Transfer-Encoding header should have been stripped")
	}

	// Custom header should remain
	if _, ok := ctx.Headers["X-Custom"]; !ok {
		t.Error("X-Custom header should not have been stripped")
	}
}

func TestSanitizerLayer_Disabled(t *testing.T) {
	cfg := SanitizerConfig{
		MaxURLLength:   10,
		AllowedMethods: []string{"GET"},
	}
	layer := NewLayer(cfg)
	layer.SetEnabled(false)

	longURL := "/" + strings.Repeat("a", 100)
	ctx := newTestContext("GET", longURL, longURL, "")

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("Disabled layer should return ActionPass, got %v", result.Action)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Disabled layer should have no findings, got %d", len(result.Findings))
	}

	// Normalized fields should NOT be populated
	if ctx.NormalizedPath != "" {
		t.Error("Disabled layer should not populate NormalizedPath")
	}
}

func TestSanitizerLayer_BlockOnHighScore(t *testing.T) {
	cfg := SanitizerConfig{
		MaxURLLength:   50,
		BlockNullBytes: true,
		AllowedMethods: []string{"GET"},
	}
	layer := NewLayer(cfg)

	// URL too long (40) + null bytes (60) = 100, well above 50
	longURL := "/" + strings.Repeat("a", 100) + "%00"
	ctx := newTestContext("GET", longURL, longURL, "")

	result := layer.Process(ctx)

	if result.Action != engine.ActionBlock {
		t.Errorf("Expected ActionBlock for high score, got %v (score: %d)", result.Action, result.Score)
	}
	if result.Score < 50 {
		t.Errorf("Expected score >= 50, got %d", result.Score)
	}
}

func TestValidateRequest_HeaderCount(t *testing.T) {
	cfg := SanitizerConfig{
		MaxHeaderCount: 3,
	}

	ctx := newTestContext("GET", "/test", "/test", "")
	ctx.Headers["H1"] = []string{"v1"}
	ctx.Headers["H2"] = []string{"v2"}
	ctx.Headers["H3"] = []string{"v3"}
	ctx.Headers["H4"] = []string{"v4"}

	findings := ValidateRequest(ctx, cfg)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Description, "Header count") {
			found = true
			if f.Score != 30 {
				t.Errorf("Header count violation score = %d, want 30", f.Score)
			}
			if f.Severity != engine.SeverityMedium {
				t.Errorf("Header count violation severity = %v, want SeverityMedium", f.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected a header count finding")
	}
}

func TestValidateRequest_BodySize(t *testing.T) {
	cfg := SanitizerConfig{
		MaxBodySize: 10,
	}

	body := strings.Repeat("x", 20)
	ctx := newTestContext("POST", "/test", "/test", body)

	findings := ValidateRequest(ctx, cfg)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Description, "Body size") {
			found = true
			if f.Score != 40 {
				t.Errorf("Body size violation score = %d, want 40", f.Score)
			}
			if f.Severity != engine.SeverityHigh {
				t.Errorf("Body size violation severity = %v, want SeverityHigh", f.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected a body size finding")
	}
}

func TestValidateRequest_CookieSize(t *testing.T) {
	cfg := SanitizerConfig{
		MaxCookieSize: 10,
	}

	ctx := newTestContext("GET", "/test", "/test", "")
	ctx.Cookies["session"] = strings.Repeat("a", 50)

	findings := ValidateRequest(ctx, cfg)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Description, "Cookie") {
			found = true
			if f.Score != 20 {
				t.Errorf("Cookie size violation score = %d, want 20", f.Score)
			}
			if f.Severity != engine.SeverityLow {
				t.Errorf("Cookie size violation severity = %v, want SeverityLow", f.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected a cookie size finding")
	}
}

func TestValidateRequest_HeaderSize(t *testing.T) {
	cfg := SanitizerConfig{
		MaxHeaderSize: 50,
	}

	ctx := newTestContext("GET", "/test", "/test", "")
	ctx.Headers["X-Large"] = []string{strings.Repeat("a", 100)}

	findings := ValidateRequest(ctx, cfg)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Description, "header size") {
			found = true
			if f.Score != 30 {
				t.Errorf("Header size violation score = %d, want 30", f.Score)
			}
		}
	}
	if !found {
		t.Error("Expected a header size finding")
	}
}

func TestSanitizerLayer_ImplementsInterface(t *testing.T) {
	cfg := SanitizerConfig{}
	layer := NewLayer(cfg)

	// Verify it satisfies engine.Layer
	var _ engine.Layer = layer

	if layer.Name() != "sanitizer" {
		t.Errorf("Name() = %q, want %q", layer.Name(), "sanitizer")
	}
}

func TestSanitizerLayer_LogOnLowScore(t *testing.T) {
	cfg := SanitizerConfig{
		MaxCookieSize:  10,
		AllowedMethods: []string{"GET"},
	}
	layer := NewLayer(cfg)

	ctx := newTestContext("GET", "/test", "/test", "")
	ctx.Cookies["session"] = strings.Repeat("a", 50)

	result := layer.Process(ctx)

	// Score is 20 (cookie size), which is > 0 but < 50 -> ActionLog
	if result.Action != engine.ActionLog {
		t.Errorf("Expected ActionLog for low score (%d), got %v", result.Score, result.Action)
	}
}

func TestStripHopByHopHeaders(t *testing.T) {
	ctx := newTestContext("GET", "/", "/", "")
	ctx.Headers["Connection"] = []string{"keep-alive"}
	ctx.Headers["Upgrade"] = []string{"websocket"}
	ctx.Headers["Content-Type"] = []string{"text/html"}

	StripHopByHopHeaders(ctx)

	if _, ok := ctx.Headers["Connection"]; ok {
		t.Error("Connection header should be stripped")
	}
	if _, ok := ctx.Headers["Upgrade"]; ok {
		t.Error("Upgrade header should be stripped")
	}
	if _, ok := ctx.Headers["Content-Type"]; !ok {
		t.Error("Content-Type should not be stripped")
	}
}

func TestSanitizerLayer_WithRealHTTPRequest(t *testing.T) {
	cfg := SanitizerConfig{
		MaxURLLength:   2048,
		MaxHeaderSize:  8192,
		MaxHeaderCount: 50,
		MaxBodySize:    1048576,
		AllowedMethods: []string{"GET", "POST"},
	}
	layer := NewLayer(cfg)

	reqURL, _ := url.Parse("http://example.com/test?q=%3Cscript%3E")
	req := &http.Request{
		Method: "GET",
		URL:    reqURL,
		Header: http.Header{
			"Content-Type": []string{"text/html"},
		},
	}

	ctx := &engine.RequestContext{
		Request:     req,
		Method:      req.Method,
		URI:         reqURL.String(),
		Path:        reqURL.Path,
		QueryParams: reqURL.Query(),
		Headers:     map[string][]string{"Content-Type": {"text/html"}},
		Cookies:     make(map[string]string),
		Body:        nil,
		BodyString:  "",
		Accumulator: engine.NewScoreAccumulator(2),
		Metadata:    make(map[string]any),
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("Expected ActionPass for normal request, got %v", result.Action)
	}
	if ctx.NormalizedPath == "" {
		t.Error("Expected NormalizedPath to be populated")
	}
}

func TestValidateRequest_NullByteInBody(t *testing.T) {
	cfg := SanitizerConfig{
		BlockNullBytes: true,
	}

	ctx := newTestContext("POST", "/test", "/test", "hello\x00world")

	findings := ValidateRequest(ctx, cfg)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Description, "Null byte") && f.Location == "body" {
			found = true
		}
	}
	if !found {
		t.Error("Expected a null byte finding in body")
	}
}

func TestValidateRequest_NullByteInHeader(t *testing.T) {
	cfg := SanitizerConfig{
		BlockNullBytes: true,
	}

	ctx := newTestContext("GET", "/test", "/test", "")
	ctx.Headers["X-Evil"] = []string{"val\x00ue"}

	findings := ValidateRequest(ctx, cfg)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Description, "Null byte") && f.Location == "header" {
			found = true
		}
	}
	if !found {
		t.Error("Expected a null byte finding in header")
	}
}
