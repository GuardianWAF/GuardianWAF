package cors

import (
	"regexp"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- compileWildcard ---

func TestCompileWildcard_SubdomainPattern(t *testing.T) {
	re := compileWildcard("https://*.example.com")
	if re == nil {
		t.Fatal("expected non-nil regex")
	}
	// Should match single subdomain
	if !re.MatchString("https://api.example.com") {
		t.Error("should match api.example.com")
	}
	// Should match nested subdomains
	if !re.MatchString("https://a.b.c.example.com") {
		t.Error("should match a.b.c.example.com (nested)")
	}
	// Should not match bare domain
	if re.MatchString("https://example.com") {
		t.Error("should not match bare example.com")
	}
}

func TestCompileWildcard_WildcardScheme(t *testing.T) {
	re := compileWildcard("*://*.example.com")
	if re == nil {
		t.Fatal("expected non-nil regex")
	}
	if !re.MatchString("https://api.example.com") {
		t.Error("should match https scheme")
	}
	if re.MatchString("http://api.example.com") {
		t.Error("should NOT match http scheme — wildcard *:// now matches HTTPS only (L4 fix)")
	}
	if re.MatchString("ftp://api.example.com") {
		t.Error("should not match ftp scheme (only https)")
	}
}

func TestCompileWildcard_ExactPattern(t *testing.T) {
	// No wildcard at all — compileWildcard is called only when "*" is present,
	// but let's verify behavior when the host has no wildcard character.
	re := compileWildcard("https://example.com")
	if re == nil {
		t.Fatal("expected non-nil regex")
	}
	if !re.MatchString("https://example.com") {
		t.Error("should match exact origin")
	}
	if re.MatchString("https://other.com") {
		t.Error("should not match different host")
	}
}

func TestCompileWildcard_NoScheme(t *testing.T) {
	re := compileWildcard("*.example.com")
	if re == nil {
		t.Fatal("expected non-nil regex")
	}
	// When no scheme is present, the regex becomes "^://.+\.example\.com$"
	// which requires :// in the input. Inputs without :// won't match.
	if re.MatchString("api.example.com") {
		t.Error("should not match without :// since pattern includes ://")
	}
	if !re.MatchString("://api.example.com") {
		t.Error("should match when input includes :// prefix (no scheme)")
	}
}

func TestCompileWildcard_MultipleWildcards(t *testing.T) {
	re := compileWildcard("https://*.*.example.com")
	if re == nil {
		t.Fatal("expected non-nil regex")
	}
	if !re.MatchString("https://a.b.example.com") {
		t.Error("should match a.b.example.com")
	}
}

func TestCompileWildcard_SpecialChars(t *testing.T) {
	// Ensure dots in host are escaped (regex-safe)
	re := compileWildcard("https://*.example.com")
	if re == nil {
		t.Fatal("expected non-nil regex")
	}
	// Dots in "exampleXcom" should not match
	if re.MatchString("https://api.exampleXcom") {
		t.Error("dot should be escaped, should not match exampleXcom")
	}
}

func TestCompileWildcard_RegexSafe(t *testing.T) {
	// The compiled regex must be valid
	re := compileWildcard("https://*.test.com")
	if re == nil {
		t.Fatal("expected non-nil regex")
	}
	// Verify it's a *regexp.Regexp
	if _, ok := any(re).(*regexp.Regexp); !ok {
		t.Error("expected *regexp.Regexp type")
	}
}

// --- handlePreflight ---

func TestHandlePreflight_MissingOrigin(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://example.com"},
		AllowMethods: []string{"GET", "POST"},
	}
	layer, _ := NewLayer(&cfg)

	// handlePreflight is called internally via Process when it's a preflight,
	// but the origin validation happens before handlePreflight is called.
	// So test via Process: missing method header means not a preflight.
	ctx := &engine.RequestContext{
		Method:   "OPTIONS",
		Headers:  map[string][]string{},
		Metadata: make(map[string]any),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass when not a CORS request, got %v", result.Action)
	}
}

func TestHandlePreflight_MissingRequestMethod(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://example.com"},
		StrictMode:   true,
	}
	layer, _ := NewLayer(&cfg)

	// OPTIONS with Origin but no Access-Control-Request-Method → not a preflight
	ctx := &engine.RequestContext{
		Method:   "OPTIONS",
		Headers:  map[string][]string{"Origin": {"https://example.com"}},
		Metadata: make(map[string]any),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for OPTIONS without Request-Method, got %v", result.Action)
	}
	// Should still set regular CORS headers, not preflight headers
	if _, ok := ctx.Metadata["cors_headers"]; !ok {
		t.Error("expected cors_headers to be set for non-preflight CORS request")
	}
}

func TestHandlePreflight_InvalidMethod_StrictMode(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://example.com"},
		AllowMethods: []string{"GET", "POST"},
		StrictMode:   true,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method: "OPTIONS",
		Headers: map[string][]string{
			"Origin":                        {"https://example.com"},
			"Access-Control-Request-Method": {"PATCH"},
		},
		Metadata: make(map[string]any),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for invalid method in strict mode, got %v", result.Action)
	}
	if result.Score != 25 {
		t.Errorf("expected score 25, got %d", result.Score)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings")
	}
	if result.Findings[0].DetectorName != "cors" {
		t.Errorf("expected detector 'cors', got %q", result.Findings[0].DetectorName)
	}
}

func TestHandlePreflight_InvalidMethod_NonStrict(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://example.com"},
		AllowMethods: []string{"GET", "POST"},
		StrictMode:   false,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method: "OPTIONS",
		Headers: map[string][]string{
			"Origin":                        {"https://example.com"},
			"Access-Control-Request-Method": {"DELETE"},
		},
		Metadata: make(map[string]any),
	}
	result := layer.Process(ctx)
	// Non-strict: pass (browser will handle it)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for invalid method in non-strict mode, got %v", result.Action)
	}
}

func TestHandlePreflight_EmptyAllowMethods(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://example.com"},
		AllowMethods: []string{}, // empty
		StrictMode:   true,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method: "OPTIONS",
		Headers: map[string][]string{
			"Origin":                        {"https://example.com"},
			"Access-Control-Request-Method": {"POST"},
		},
		Metadata: make(map[string]any),
	}
	result := layer.Process(ctx)
	// When AllowMethods is empty, method check is skipped
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass when AllowMethods is empty, got %v", result.Action)
	}
}

func TestHandlePreflight_BlockedHeader_StrictMode(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://example.com"},
		AllowMethods: []string{"POST"},
		AllowHeaders: []string{"Content-Type"},
		StrictMode:   true,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method: "OPTIONS",
		Headers: map[string][]string{
			"Origin":                         {"https://example.com"},
			"Access-Control-Request-Method":  {"POST"},
			"Access-Control-Request-Headers": {"X-Custom-Header"},
		},
		Metadata: make(map[string]any),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for disallowed header in strict mode, got %v", result.Action)
	}
	if result.Score != 15 {
		t.Errorf("expected score 15, got %d", result.Score)
	}
	if result.Findings[0].Category != "policy" {
		t.Errorf("expected category 'policy', got %q", result.Findings[0].Category)
	}
}

func TestHandlePreflight_BlockedHeader_NonStrict(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://example.com"},
		AllowMethods: []string{"POST"},
		AllowHeaders: []string{"Content-Type"},
		StrictMode:   false,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method: "OPTIONS",
		Headers: map[string][]string{
			"Origin":                         {"https://example.com"},
			"Access-Control-Request-Method":  {"POST"},
			"Access-Control-Request-Headers": {"X-Evil-Header"},
		},
		Metadata: make(map[string]any),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for disallowed header in non-strict mode, got %v", result.Action)
	}
}

func TestHandlePreflight_EmptyAllowHeaders(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://example.com"},
		AllowMethods: []string{"POST"},
		AllowHeaders: []string{}, // empty
		StrictMode:   true,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method: "OPTIONS",
		Headers: map[string][]string{
			"Origin":                         {"https://example.com"},
			"Access-Control-Request-Method":  {"POST"},
			"Access-Control-Request-Headers": {"X-Custom"},
		},
		Metadata: make(map[string]any),
	}
	result := layer.Process(ctx)
	// When AllowHeaders is empty, header check is skipped
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass when AllowHeaders is empty, got %v", result.Action)
	}
}

// --- setCORSHeaders ---

func TestSetCORSHeaders_CredentialsEnabled(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		AllowOrigins:     []string{"https://example.com"},
		AllowCredentials: true,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method:   "GET",
		Headers:  map[string][]string{"Origin": {"https://example.com"}},
		Metadata: make(map[string]any),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected pass, got %v", result.Action)
	}
	headers := ctx.Metadata["cors_headers"].(map[string]string)
	if headers["Access-Control-Allow-Credentials"] != "true" {
		t.Errorf("expected 'true', got %q", headers["Access-Control-Allow-Credentials"])
	}
}

func TestSetCORSHeaders_CredentialsDisabled(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		AllowOrigins:     []string{"https://example.com"},
		AllowCredentials: false,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method:   "GET",
		Headers:  map[string][]string{"Origin": {"https://example.com"}},
		Metadata: make(map[string]any),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected pass, got %v", result.Action)
	}
	headers := ctx.Metadata["cors_headers"].(map[string]string)
	if headers["Access-Control-Allow-Credentials"] != "false" {
		t.Errorf("expected 'false', got %q", headers["Access-Control-Allow-Credentials"])
	}
}

func TestSetCORSHeaders_ExposeHeaders(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		AllowOrigins:  []string{"https://example.com"},
		ExposeHeaders: []string{"X-Custom-Header", "X-Request-Id"},
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method:   "GET",
		Headers:  map[string][]string{"Origin": {"https://example.com"}},
		Metadata: make(map[string]any),
	}
	layer.Process(ctx)

	exposed := ctx.Metadata["cors_expose_headers"]
	if exposed == nil {
		t.Fatal("expected cors_expose_headers to be set")
	}
	exposedStr := exposed.(string)
	if exposedStr != "X-Custom-Header, X-Request-Id" {
		t.Errorf("expected 'X-Custom-Header, X-Request-Id', got %q", exposedStr)
	}
}

func TestSetCORSHeaders_NoExposeHeaders(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		AllowOrigins:  []string{"https://example.com"},
		ExposeHeaders: []string{},
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method:   "GET",
		Headers:  map[string][]string{"Origin": {"https://example.com"}},
		Metadata: make(map[string]any),
	}
	layer.Process(ctx)

	if _, ok := ctx.Metadata["cors_expose_headers"]; ok {
		t.Error("expected cors_expose_headers to NOT be set when empty")
	}
}

func TestSetCORSHeaders_ResponseHook(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://example.com"},
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method:   "GET",
		Headers:  map[string][]string{"Origin": {"https://example.com"}},
		Metadata: make(map[string]any),
	}
	layer.Process(ctx)

	if ctx.Metadata["cors_response_hook"] != true {
		t.Error("expected cors_response_hook to be true")
	}
}

func TestSetCORSHeaders_OriginReflected(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://app.example.com", "https://api.example.com"},
	}
	layer, _ := NewLayer(&cfg)

	for _, origin := range []string{"https://app.example.com", "https://api.example.com"} {
		ctx := &engine.RequestContext{
			Method:   "GET",
			Headers:  map[string][]string{"Origin": {origin}},
			Metadata: make(map[string]any),
		}
		layer.Process(ctx)
		headers := ctx.Metadata["cors_headers"].(map[string]string)
		if headers["Access-Control-Allow-Origin"] != origin {
			t.Errorf("expected Allow-Origin to be %q, got %q", origin, headers["Access-Control-Allow-Origin"])
		}
	}
}

// --- setPreflightHeaders ---

func TestSetPreflightHeaders_MaxAge(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		AllowOrigins:  []string{"https://example.com"},
		AllowMethods:  []string{"GET", "POST"},
		MaxAgeSeconds: 7200,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method: "OPTIONS",
		Headers: map[string][]string{
			"Origin":                        {"https://example.com"},
			"Access-Control-Request-Method": {"POST"},
		},
		Metadata: make(map[string]any),
	}
	layer.Process(ctx)

	headers := ctx.Metadata["cors_preflight_headers"].(map[string]string)
	if headers["Access-Control-Max-Age"] != "7200" {
		t.Errorf("expected Max-Age '7200', got %q", headers["Access-Control-Max-Age"])
	}
}

func TestSetPreflightHeaders_ZeroMaxAge(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		AllowOrigins:  []string{"https://example.com"},
		AllowMethods:  []string{"GET"},
		MaxAgeSeconds: 0,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method: "OPTIONS",
		Headers: map[string][]string{
			"Origin":                        {"https://example.com"},
			"Access-Control-Request-Method": {"GET"},
		},
		Metadata: make(map[string]any),
	}
	layer.Process(ctx)

	headers := ctx.Metadata["cors_preflight_headers"].(map[string]string)
	if _, ok := headers["Access-Control-Max-Age"]; ok {
		t.Error("expected no Max-Age header when MaxAgeSeconds is 0")
	}
}

func TestSetPreflightHeaders_MethodsAndHeaders(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://example.com"},
		AllowMethods: []string{"GET", "POST", "PUT"},
		AllowHeaders: []string{"Content-Type", "Authorization"},
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method: "OPTIONS",
		Headers: map[string][]string{
			"Origin":                        {"https://example.com"},
			"Access-Control-Request-Method": {"PUT"},
		},
		Metadata: make(map[string]any),
	}
	layer.Process(ctx)

	headers := ctx.Metadata["cors_preflight_headers"].(map[string]string)
	if headers["Access-Control-Allow-Methods"] != "GET, POST, PUT" {
		t.Errorf("expected 'GET, POST, PUT', got %q", headers["Access-Control-Allow-Methods"])
	}
	if headers["Access-Control-Allow-Headers"] != "Content-Type, Authorization" {
		t.Errorf("expected 'Content-Type, Authorization', got %q", headers["Access-Control-Allow-Headers"])
	}
}

func TestSetPreflightHeaders_NoMethodsNoHeaders(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://example.com"},
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method: "OPTIONS",
		Headers: map[string][]string{
			"Origin":                        {"https://example.com"},
			"Access-Control-Request-Method": {"GET"},
		},
		Metadata: make(map[string]any),
	}
	layer.Process(ctx)

	headers := ctx.Metadata["cors_preflight_headers"].(map[string]string)
	if _, ok := headers["Access-Control-Allow-Methods"]; ok {
		t.Error("expected no Allow-Methods when AllowMethods is empty")
	}
	if _, ok := headers["Access-Control-Allow-Headers"]; ok {
		t.Error("expected no Allow-Headers when AllowHeaders is empty")
	}
}

func TestSetPreflightHeaders_CredentialsInPreflight(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		AllowOrigins:     []string{"https://example.com"},
		AllowMethods:     []string{"GET"},
		AllowCredentials: true,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method: "OPTIONS",
		Headers: map[string][]string{
			"Origin":                        {"https://example.com"},
			"Access-Control-Request-Method": {"GET"},
		},
		Metadata: make(map[string]any),
	}
	layer.Process(ctx)

	headers := ctx.Metadata["cors_preflight_headers"].(map[string]string)
	if headers["Access-Control-Allow-Credentials"] != "true" {
		t.Errorf("expected 'true', got %q", headers["Access-Control-Allow-Credentials"])
	}
	if headers["Access-Control-Allow-Origin"] != "https://example.com" {
		t.Errorf("expected origin reflected, got %q", headers["Access-Control-Allow-Origin"])
	}
}

// --- containsFold ---

func TestContainsFold_ExactMatch(t *testing.T) {
	slice := []string{"Content-Type", "Authorization"}
	if !containsFold(slice, "Content-Type") {
		t.Error("expected exact match to be found")
	}
}

func TestContainsFold_CaseInsensitive(t *testing.T) {
	slice := []string{"Content-Type", "Authorization"}
	if !containsFold(slice, "content-type") {
		t.Error("expected case-insensitive match for lowercase")
	}
	if !containsFold(slice, "CONTENT-TYPE") {
		t.Error("expected case-insensitive match for uppercase")
	}
	if !containsFold(slice, "authorization") {
		t.Error("expected case-insensitive match for lowercase authorization")
	}
}

func TestContainsFold_MixedCase(t *testing.T) {
	slice := []string{"X-Custom-Header"}
	if !containsFold(slice, "x-custom-header") {
		t.Error("expected case-insensitive match for mixed case")
	}
	if !containsFold(slice, "X-CUSTOM-HEADER") {
		t.Error("expected case-insensitive match for all upper case")
	}
}

func TestContainsFold_NotFound(t *testing.T) {
	slice := []string{"Content-Type", "Authorization"}
	if containsFold(slice, "X-Custom") {
		t.Error("expected false for non-existent item")
	}
}

func TestContainsFold_EmptySlice(t *testing.T) {
	slice := []string{}
	if containsFold(slice, "anything") {
		t.Error("expected false for empty slice")
	}
}

func TestContainsFold_EmptyItem(t *testing.T) {
	slice := []string{"Content-Type", ""}
	if !containsFold(slice, "") {
		t.Error("expected true for empty string match")
	}
}

// --- intToStr ---

func TestIntToStr_Zero(t *testing.T) {
	if intToStr(0) != "0" {
		t.Errorf("expected '0', got %q", intToStr(0))
	}
}

func TestIntToStr_Positive(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{1, "1"},
		{10, "10"},
		{42, "42"},
		{100, "100"},
		{3600, "3600"},
	}
	for _, tt := range tests {
		got := intToStr(tt.input)
		if got != tt.expected {
			t.Errorf("intToStr(%d) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestIntToStr_LargeValues(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{999999, "999999"},
		{2147483647, "2147483647"}, // max int32
	}
	for _, tt := range tests {
		got := intToStr(tt.input)
		if got != tt.expected {
			t.Errorf("intToStr(%d) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestIntToStr_Negative(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{-1, "-1"},
		{-42, "-42"},
		{-3600, "-3600"},
	}
	for _, tt := range tests {
		got := intToStr(tt.input)
		if got != tt.expected {
			t.Errorf("intToStr(%d) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// --- helper coverage ---

func TestParseHeaderList(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"Content-Type, Authorization", []string{"Content-Type", "Authorization"}},
		{"  Content-Type ,  Authorization  ", []string{"Content-Type", "Authorization"}},
		{"Content-Type", []string{"Content-Type"}},
		{"", nil},
		{" , , ", nil},
	}
	for _, tt := range tests {
		got := parseHeaderList(tt.input)
		if len(got) != len(tt.expected) {
			t.Errorf("parseHeaderList(%q) = %v, want %v", tt.input, got, tt.expected)
			continue
		}
		for i, v := range got {
			if v != tt.expected[i] {
				t.Errorf("parseHeaderList(%q)[%d] = %q, want %q", tt.input, i, v, tt.expected[i])
			}
		}
	}
}

func TestGetHeader_CaseInsensitive(t *testing.T) {
	headers := map[string][]string{
		"Content-Type": {"application/json"},
	}
	if v := getHeader(headers, "content-type"); v != "application/json" {
		t.Errorf("expected 'application/json', got %q", v)
	}
	if v := getHeader(headers, "CONTENT-TYPE"); v != "application/json" {
		t.Errorf("expected 'application/json', got %q", v)
	}
}

func TestGetHeader_EmptyHeaders(t *testing.T) {
	headers := map[string][]string{}
	if v := getHeader(headers, "Content-Type"); v != "" {
		t.Errorf("expected empty string, got %q", v)
	}
}

func TestGetHeader_MultipleValues(t *testing.T) {
	headers := map[string][]string{
		"Accept": {"text/html", "application/json"},
	}
	if v := getHeader(headers, "Accept"); v != "text/html" {
		t.Errorf("expected first value 'text/html', got %q", v)
	}
}

func TestHasHeader(t *testing.T) {
	headers := map[string][]string{
		"Content-Type": {"application/json"},
	}
	if !hasHeader(headers, "Content-Type") {
		t.Error("expected true for existing header")
	}
	if hasHeader(headers, "Authorization") {
		t.Error("expected false for missing header")
	}
}

func TestContains(t *testing.T) {
	slice := []string{"GET", "POST", "PUT"}
	if !contains(slice, "GET") {
		t.Error("expected true for existing item")
	}
	if contains(slice, "DELETE") {
		t.Error("expected false for missing item")
	}
	if contains([]string{}, "GET") {
		t.Error("expected false for empty slice")
	}
}
