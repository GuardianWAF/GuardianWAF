package cors

import (
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests: allowlist origins must be normalized to URL semantics
// before matching — DNS host names are case-insensitive, browsers omit
// default ports from Origin, and scheme-less wildcard patterns previously
// compiled to "^://..." (empty scheme) and matched nothing.

func TestNormalizeOrigin(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://Example.com", "https://example.com"},
		{"HTTPS://EXAMPLE.COM", "https://example.com"},
		{"https://example.com:443", "https://example.com"},
		{"http://example.com:80", "http://example.com"},
		{"https://example.com:8443", "https://example.com:8443"}, // non-default port kept
		{"*.example.com", "https://*.example.com"},               // scheme-less wildcard → https
		{"  https://Example.com  ", "https://example.com"},
		{"https://example.com/path", "https://example.com/path"},
	}
	for _, tc := range cases {
		if got := normalizeOrigin(tc.in); got != tc.want {
			t.Errorf("FAIL: normalizeOrigin(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsOriginAllowedNormalized(t *testing.T) {
	l, err := NewLayer(&Config{
		Enabled:      true,
		AllowOrigins: []string{"https://Example.com", "https://example.com:443", "*.example.com"},
	})
	if err != nil {
		t.Fatalf("FAIL: NewLayer returned an error: %v", err)
	}

	allowed := []string{
		"https://example.com",     // lowercase browser form vs uppercase config
		"https://EXAMPLE.com",     // either direction
		"https://foo.example.com", // scheme-less wildcard config
		"https://a.b.example.com", // multi-level subdomain (documented intent)
	}
	for _, o := range allowed {
		if !l.isOriginAllowed(o) {
			t.Errorf("FAIL: normalized origin %q was not allowed", o)
		}
	}

	denied := []string{
		"https://evil.com",
		"https://example.com.evil.com",
		"https://example.com:8443", // non-default port is a different origin
	}
	for _, o := range denied {
		if l.isOriginAllowed(o) {
			t.Errorf("FAIL: origin %q was allowed but must not be", o)
		}
	}
}

func TestProcessPreflightNormalizedOrigin(t *testing.T) {
	l, err := NewLayer(&Config{
		Enabled:      true,
		AllowOrigins: []string{"https://Example.com"},
	})
	if err != nil {
		t.Fatalf("FAIL: NewLayer returned an error: %v", err)
	}

	req := httptest.NewRequest("OPTIONS", "https://api.example.com/data", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	ctx := &engine.RequestContext{
		Method:  "OPTIONS",
		Path:    "/data",
		Request: req,
		Headers: map[string][]string{
			"Origin":                        {"https://example.com"},
			"Access-Control-Request-Method": {"GET"},
		},
	}

	l.Process(ctx)

	found := false
	for _, m := range []map[string]string{ctx.CORSPreflightHeaders, ctx.CORSHeaders} {
		if _, ok := m["Access-Control-Allow-Origin"]; ok {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: preflight with a normalization-matching origin produced no Access-Control-Allow-Origin header")
	}
}
