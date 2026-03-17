package engine

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestAcquireRelease(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/test?a=1", nil)
	r.RemoteAddr = "192.168.1.1:12345"

	ctx := AcquireContext(r, 2, 1024)
	if ctx == nil {
		t.Fatal("AcquireContext returned nil")
	}
	if ctx.Method != http.MethodGet {
		t.Errorf("expected method GET, got %s", ctx.Method)
	}
	if ctx.Path != "/test" {
		t.Errorf("expected path /test, got %s", ctx.Path)
	}
	if ctx.RequestID == "" {
		t.Error("expected non-empty RequestID")
	}
	if ctx.Accumulator == nil {
		t.Error("expected non-nil Accumulator")
	}

	// Release and re-acquire to test pool recycling
	ReleaseContext(ctx)

	r2 := httptest.NewRequest(http.MethodPost, "/other", nil)
	r2.RemoteAddr = "10.0.0.1:9999"
	ctx2 := AcquireContext(r2, 1, 1024)
	if ctx2 == nil {
		t.Fatal("second AcquireContext returned nil")
	}
	if ctx2.Method != http.MethodPost {
		t.Errorf("expected method POST after reuse, got %s", ctx2.Method)
	}
	if ctx2.Path != "/other" {
		t.Errorf("expected path /other after reuse, got %s", ctx2.Path)
	}
	ReleaseContext(ctx2)
}

func TestExtractClientIP_XForwardedFor(t *testing.T) {
	// Single IP
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.50")

	ctx := AcquireContext(r, 1, 1024)
	defer ReleaseContext(ctx)

	if ctx.ClientIP.String() != "203.0.113.50" {
		t.Errorf("expected 203.0.113.50, got %s", ctx.ClientIP)
	}

	// Multiple IPs — should take first
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.RemoteAddr = "127.0.0.1:1234"
	r2.Header.Set("X-Forwarded-For", "198.51.100.10, 203.0.113.50, 10.0.0.1")

	ctx2 := AcquireContext(r2, 1, 1024)
	defer ReleaseContext(ctx2)

	if ctx2.ClientIP.String() != "198.51.100.10" {
		t.Errorf("expected 198.51.100.10, got %s", ctx2.ClientIP)
	}
}

func TestExtractClientIP_XRealIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Real-IP", "198.51.100.20")

	ctx := AcquireContext(r, 1, 1024)
	defer ReleaseContext(ctx)

	if ctx.ClientIP.String() != "198.51.100.20" {
		t.Errorf("expected 198.51.100.20, got %s", ctx.ClientIP)
	}
}

func TestExtractClientIP_RemoteAddr(t *testing.T) {
	// With port
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.20.30.40:5555"

	ctx := AcquireContext(r, 1, 1024)
	defer ReleaseContext(ctx)

	if ctx.ClientIP.String() != "10.20.30.40" {
		t.Errorf("expected 10.20.30.40, got %s", ctx.ClientIP)
	}

	// Without port (bare IP)
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.RemoteAddr = "10.20.30.40"

	ctx2 := AcquireContext(r2, 1, 1024)
	defer ReleaseContext(ctx2)

	if ctx2.ClientIP.String() != "10.20.30.40" {
		t.Errorf("expected 10.20.30.40, got %s", ctx2.ClientIP)
	}
}

func TestExtractClientIP_IPv6(t *testing.T) {
	// IPv6 with port (bracket notation used by net/http)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "[::1]:8080"

	ctx := AcquireContext(r, 1, 1024)
	defer ReleaseContext(ctx)

	if ctx.ClientIP.String() != "::1" {
		t.Errorf("expected ::1, got %s", ctx.ClientIP)
	}

	// IPv6 via X-Forwarded-For
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.RemoteAddr = "127.0.0.1:1234"
	r2.Header.Set("X-Forwarded-For", "2001:db8::1")

	ctx2 := AcquireContext(r2, 1, 1024)
	defer ReleaseContext(ctx2)

	if ctx2.ClientIP.String() != "2001:db8::1" {
		t.Errorf("expected 2001:db8::1, got %s", ctx2.ClientIP)
	}

	// IPv6 via X-Real-IP
	r3 := httptest.NewRequest(http.MethodGet, "/", nil)
	r3.RemoteAddr = "127.0.0.1:1234"
	r3.Header.Set("X-Real-IP", "fe80::1")

	ctx3 := AcquireContext(r3, 1, 1024)
	defer ReleaseContext(ctx3)

	if ctx3.ClientIP.String() != "fe80::1" {
		t.Errorf("expected fe80::1, got %s", ctx3.ClientIP)
	}
}

func TestGenerateRequestID(t *testing.T) {
	// Format validation: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars)
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	id := generateRequestID()
	if !re.MatchString(id) {
		t.Errorf("request ID %q does not match expected UUID-like format", id)
	}

	// Uniqueness: generate 100 IDs and ensure all are different
	seen := make(map[string]struct{}, 100)
	for i := range 100 {
		rid := generateRequestID()
		if !re.MatchString(rid) {
			t.Errorf("request ID %q (iteration %d) has invalid format", rid, i)
		}
		if _, exists := seen[rid]; exists {
			t.Errorf("duplicate request ID %q at iteration %d", rid, i)
		}
		seen[rid] = struct{}{}
	}
}

func TestBodyReading(t *testing.T) {
	body := "hello world body content"
	r := httptest.NewRequest(http.MethodPost, "/data", strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"

	ctx := AcquireContext(r, 1, 4096)
	defer ReleaseContext(ctx)

	if string(ctx.Body) != body {
		t.Errorf("expected Body %q, got %q", body, string(ctx.Body))
	}
	if ctx.BodyString != body {
		t.Errorf("expected BodyString %q, got %q", body, ctx.BodyString)
	}
	if !ctx.bodyRead {
		t.Error("expected bodyRead to be true")
	}
}

func TestBodySizeLimit(t *testing.T) {
	// Create a body larger than the limit
	bigBody := strings.Repeat("A", 2000)
	r := httptest.NewRequest(http.MethodPost, "/data", strings.NewReader(bigBody))
	r.RemoteAddr = "127.0.0.1:1234"

	maxSize := int64(100)
	ctx := AcquireContext(r, 1, maxSize)
	defer ReleaseContext(ctx)

	if int64(len(ctx.Body)) != maxSize {
		t.Errorf("expected body length %d, got %d", maxSize, len(ctx.Body))
	}
	if int64(len(ctx.BodyString)) != maxSize {
		t.Errorf("expected BodyString length %d, got %d", maxSize, len(ctx.BodyString))
	}
}

func TestHeaderExtraction(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Custom-Header", "custom-value")
	r.Header.Set("Accept", "text/html")
	r.Header.Add("Accept-Encoding", "gzip")
	r.Header.Add("Accept-Encoding", "deflate")
	r.Header.Set("Content-Type", "application/json")

	ctx := AcquireContext(r, 1, 1024)
	defer ReleaseContext(ctx)

	// Check Content-Type
	if ctx.ContentType != "application/json" {
		t.Errorf("expected ContentType application/json, got %s", ctx.ContentType)
	}

	// Check custom header
	vals, ok := ctx.Headers["X-Custom-Header"]
	if !ok || len(vals) != 1 || vals[0] != "custom-value" {
		t.Errorf("expected X-Custom-Header=[custom-value], got %v", vals)
	}

	// Check multi-value header
	enc, ok := ctx.Headers["Accept-Encoding"]
	if !ok || len(enc) != 2 {
		t.Errorf("expected Accept-Encoding with 2 values, got %v", enc)
	}
	if enc[0] != "gzip" || enc[1] != "deflate" {
		t.Errorf("expected [gzip, deflate], got %v", enc)
	}

	// Verify headers are copies, not references to original
	r.Header.Set("X-Custom-Header", "modified")
	if ctx.Headers["X-Custom-Header"][0] != "custom-value" {
		t.Error("header values should be independent copies")
	}
}

func TestCookieExtraction(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})
	r.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})
	r.AddCookie(&http.Cookie{Name: "lang", Value: "en"})

	ctx := AcquireContext(r, 1, 1024)
	defer ReleaseContext(ctx)

	if len(ctx.Cookies) != 3 {
		t.Errorf("expected 3 cookies, got %d", len(ctx.Cookies))
	}
	if ctx.Cookies["session"] != "abc123" {
		t.Errorf("expected cookie session=abc123, got %s", ctx.Cookies["session"])
	}
	if ctx.Cookies["theme"] != "dark" {
		t.Errorf("expected cookie theme=dark, got %s", ctx.Cookies["theme"])
	}
	if ctx.Cookies["lang"] != "en" {
		t.Errorf("expected cookie lang=en, got %s", ctx.Cookies["lang"])
	}
}

func TestReleaseResetsFields(t *testing.T) {
	body := "test body"
	r := httptest.NewRequest(http.MethodPost, "/path?key=val", bytes.NewReader([]byte(body)))
	r.RemoteAddr = "1.2.3.4:5678"
	r.Header.Set("X-Test", "value")
	r.AddCookie(&http.Cookie{Name: "sid", Value: "xyz"})

	ctx := AcquireContext(r, 3, 1024)

	// Verify fields are populated before release
	if ctx.Method == "" || ctx.Path == "" || ctx.ClientIP == nil {
		t.Fatal("context fields should be populated before release")
	}

	ReleaseContext(ctx)

	// After release, all fields should be zeroed
	if ctx.Request != nil {
		t.Error("Request should be nil after release")
	}
	if ctx.ClientIP != nil {
		t.Error("ClientIP should be nil after release")
	}
	if ctx.Method != "" {
		t.Error("Method should be empty after release")
	}
	if ctx.URI != "" {
		t.Error("URI should be empty after release")
	}
	if ctx.Path != "" {
		t.Error("Path should be empty after release")
	}
	if ctx.QueryParams != nil {
		t.Error("QueryParams should be nil after release")
	}
	if ctx.Headers != nil {
		t.Error("Headers should be nil after release")
	}
	if ctx.Cookies != nil {
		t.Error("Cookies should be nil after release")
	}
	if ctx.Body != nil {
		t.Error("Body should be nil after release")
	}
	if ctx.BodyString != "" {
		t.Error("BodyString should be empty after release")
	}
	if ctx.ContentType != "" {
		t.Error("ContentType should be empty after release")
	}
	if ctx.NormalizedPath != "" {
		t.Error("NormalizedPath should be empty after release")
	}
	if ctx.NormalizedQuery != nil {
		t.Error("NormalizedQuery should be nil after release")
	}
	if ctx.NormalizedBody != "" {
		t.Error("NormalizedBody should be empty after release")
	}
	if ctx.NormalizedHeaders != nil {
		t.Error("NormalizedHeaders should be nil after release")
	}
	if ctx.Accumulator != nil {
		t.Error("Accumulator should be nil after release")
	}
	if ctx.Action != ActionPass {
		t.Error("Action should be ActionPass after release")
	}
	if ctx.RequestID != "" {
		t.Error("RequestID should be empty after release")
	}
	if !ctx.StartTime.IsZero() {
		t.Error("StartTime should be zero after release")
	}
	if ctx.Metadata != nil {
		t.Error("Metadata should be nil after release")
	}
	if ctx.TLSVersion != 0 {
		t.Error("TLSVersion should be 0 after release")
	}
	if ctx.TLSCipherSuite != 0 {
		t.Error("TLSCipherSuite should be 0 after release")
	}
	if ctx.ServerName != "" {
		t.Error("ServerName should be empty after release")
	}
	if ctx.bodyRead {
		t.Error("bodyRead should be false after release")
	}
}

func TestQueryParamsExtraction(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/search?q=hello&lang=en&lang=fr", nil)
	r.RemoteAddr = "127.0.0.1:1234"

	ctx := AcquireContext(r, 1, 1024)
	defer ReleaseContext(ctx)

	if len(ctx.QueryParams) != 2 {
		t.Errorf("expected 2 query param keys, got %d", len(ctx.QueryParams))
	}
	if ctx.QueryParams["q"][0] != "hello" {
		t.Errorf("expected q=hello, got %s", ctx.QueryParams["q"][0])
	}
	langs := ctx.QueryParams["lang"]
	if len(langs) != 2 || langs[0] != "en" || langs[1] != "fr" {
		t.Errorf("expected lang=[en, fr], got %v", langs)
	}
}

func TestNilBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"

	ctx := AcquireContext(r, 1, 1024)
	defer ReleaseContext(ctx)

	// GET requests with nil body should have empty Body
	if len(ctx.Body) != 0 {
		t.Errorf("expected empty Body for GET, got %d bytes", len(ctx.Body))
	}
	if ctx.BodyString != "" {
		t.Errorf("expected empty BodyString for GET, got %q", ctx.BodyString)
	}
}

func TestMetadataMap(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"

	ctx := AcquireContext(r, 1, 1024)
	defer ReleaseContext(ctx)

	if ctx.Metadata == nil {
		t.Fatal("expected non-nil Metadata map")
	}

	ctx.Metadata["key1"] = "value1"
	ctx.Metadata["key2"] = 42

	if ctx.Metadata["key1"] != "value1" {
		t.Error("Metadata key1 not stored correctly")
	}
	if ctx.Metadata["key2"] != 42 {
		t.Error("Metadata key2 not stored correctly")
	}
}
