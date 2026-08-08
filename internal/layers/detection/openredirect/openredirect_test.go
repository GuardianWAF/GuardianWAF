package openredirect

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func makeCtx(host, rawQuery string, headers map[string][]string) *engine.RequestContext {
	req, _ := http.NewRequest("GET", "http://"+host+"/?"+rawQuery, nil)
	query := map[string][]string{}
	for k, vs := range req.URL.Query() {
		query[k] = vs
	}
	hdrs := headers
	if hdrs == nil {
		hdrs = map[string][]string{}
	}
	return &engine.RequestContext{
		Request:         req,
		Path:            req.URL.Path,
		NormalizedPath:  req.URL.Path,
		QueryParams:     query,
		NormalizedQuery: query,
		Headers:         hdrs,
		Cookies:         map[string]string{},
	}
}

func TestDisabledDetectorPasses(t *testing.T) {
	d := NewDetector(false, 1.0)
	ctx := makeCtx("app.example.com", "next=https://evil.com", nil)
	result := d.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("disabled detector should pass, got %v", result.Action)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("disabled detector should have no findings, got %d", len(result.Findings))
	}
}

func TestBenignRelativePaths(t *testing.T) {
	d := NewDetector(true, 1.0)
	for _, val := range []string{
		"/dashboard",
		"/login?foo=bar",
		"relative/path",
		"",
	} {
		ctx := makeCtx("app.example.com", "next="+val, nil)
		result := d.Process(ctx)
		if len(result.Findings) != 0 {
			t.Fatalf("relative path %q should not trigger, got %d findings: %+v", val, len(result.Findings), result.Findings)
		}
	}
}

func TestSameHostAbsoluteURL(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := makeCtx("app.example.com", "redirect=https://app.example.com/dashboard", nil)
	result := d.Process(ctx)
	if len(result.Findings) != 0 {
		t.Fatalf("same-host absolute URL should not trigger, got %d findings", len(result.Findings))
	}
}

func TestSubdomainAllowed(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := makeCtx("example.com", "next=https://sub.example.com/path", nil)
	result := d.Process(ctx)
	if len(result.Findings) != 0 {
		t.Fatalf("subdomain of request host should not trigger, got %d findings", len(result.Findings))
	}
}

func TestExternalRedirectBlocked(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := makeCtx("app.example.com", "next=https://evil.com/phish", nil)
	result := d.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("external redirect should trigger a finding")
	}
	if result.Action != engine.ActionBlock {
		t.Fatalf("external redirect should block, got %v", result.Action)
	}
	f := result.Findings[0]
	if f.Severity != engine.SeverityHigh {
		t.Fatalf("severity should be high, got %v", f.Severity)
	}
}

func TestProtocolRelativeBlocked(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := makeCtx("app.example.com", "redirect=//evil.com/steal", nil)
	result := d.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("protocol-relative URL should trigger")
	}
}

func TestJavascriptSchemeBlocked(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := makeCtx("app.example.com", "callback=javascript:alert(1)", nil)
	result := d.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("javascript: scheme should trigger")
	}
	f := result.Findings[0]
	if f.Score < 70 {
		t.Fatalf("dangerous scheme should score >= 70, got %d", f.Score)
	}
}

func TestDataSchemeBlocked(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := makeCtx("app.example.com", "next=data:text/html,<script>alert(1)</script>", nil)
	result := d.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("data: scheme should trigger")
	}
}

func TestControlCharBlocked(t *testing.T) {
	d := NewDetector(true, 1.0)
	// Build context manually — http.NewRequest rejects CRLF in URLs.
	ctx := &engine.RequestContext{
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/", RawQuery: "redirect=https://evil.com"},
			Host:   "app.example.com",
		},
		Path:            "/",
		QueryParams:     map[string][]string{"redirect": {"https://evil.com\r\nSet-Cookie:stolen=1"}},
		NormalizedQuery: map[string][]string{"redirect": {"https://evil.com\r\nSet-Cookie:stolen=1"}},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}
	result := d.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("redirect with CRLF should trigger")
	}
}

func TestMultipleParamsMultipleFindings(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := makeCtx("app.example.com", "next=https://evil.com&redirect=https://evil2.com", nil)
	result := d.Process(ctx)
	if len(result.Findings) < 2 {
		t.Fatalf("two external redirect params should produce >= 2 findings, got %d", len(result.Findings))
	}
}

func TestRedirectParamCaseInsensitive(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := makeCtx("app.example.com", "NEXT=https://evil.com", nil)
	result := d.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("NEXT (uppercase) should trigger after normalization")
	}
}

func TestRedirectParamVariants(t *testing.T) {
	d := NewDetector(true, 1.0)
	params := []string{"return", "dest", "goto", "target", "redir"}
	for _, p := range params {
		ctx := makeCtx("app.example.com", p+"=https://evil.com", nil)
		result := d.Process(ctx)
		if len(result.Findings) == 0 {
			t.Fatalf("param %q should trigger for external redirect", p)
		}
	}
}

func TestNonRedirectParamIgnored(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := makeCtx("app.example.com", "page=https://evil.com", nil)
	result := d.Process(ctx)
	if len(result.Findings) != 0 {
		t.Fatal("non-redirect param 'page' should not trigger")
	}
}

func TestLocationHeaderChecked(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := makeCtx("app.example.com", "", map[string][]string{
		"Location": {"https://evil.com/phish"},
	})
	result := d.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("Location header with external URL should trigger")
	}
}

func TestEmptyValueIgnored(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := makeCtx("app.example.com", "next=", nil)
	result := d.Process(ctx)
	if len(result.Findings) != 0 {
		t.Fatal("empty redirect value should not trigger")
	}
}
