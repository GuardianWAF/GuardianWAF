package guardianwaf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/layers/ipacl"
)

func writeLibraryConfig(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "waf.yaml")
	if err := os.WriteFile(p, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func libraryStatus(e *Engine, method, path, body, key string) int {
	r := httptest.NewRequest(method, "http://example.test"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "text/plain")
	if key != "" {
		r.Header.Set("X-API-Key", key)
	}
	rr := httptest.NewRecorder()
	e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })).ServeHTTP(rr, r)
	return rr.Code
}

func TestLibraryDefaultDetectorParity(t *testing.T) {
	a, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := NewFromFile(writeLibraryConfig(t, "mode: enforce\nwaf:\n  bot_detection:\n    enabled: false\n  rate_limit:\n    enabled: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	cases := []struct {
		name, path, body, contentType string
		headers                       map[string]string
	}{
		{name: "ssti", path: "/search?q=" + url.QueryEscape("__class__.__mro__")},
		{name: "nosqli", path: "/search?q=" + url.QueryEscape("$where")},
		{name: "openredirect", path: "/redirect?redirect=" + url.QueryEscape("https://evil.example/path")},
		{name: "graphql", path: "/graphql", body: "{ __schema { types { name } } }", contentType: "application/graphql"},
		{name: "smuggling", path: "/", headers: map[string]string{"Content-Length": "1", "Transfer-Encoding": "chunked"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, e := range []*Engine{a, b} {
				r := httptest.NewRequest("POST", "http://example.test"+tc.path, strings.NewReader(tc.body))
				if tc.contentType != "" {
					r.Header.Set("Content-Type", tc.contentType)
				}
				for k, v := range tc.headers {
					r.Header.Set(k, v)
				}
				got := e.Check(r)
				found := false
				for _, f := range got.Findings {
					if f.Detector == tc.name {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing %s finding: %+v", tc.name, got)
				}
			}
		})
	}
	for _, e := range []*Engine{a, b} {
		if got := libraryStatus(e, "GET", "/search?q=hello", "", ""); got != 204 {
			t.Fatalf("clean control status %d", got)
		}
	}
}

func TestLibraryAPIKeyEnforcement(t *testing.T) {
	const key = "review-key-123456789012345678901234567890"
	e, err := NewFromFile(writeLibraryConfig(t, `mode: enforce
waf:
  bot_detection:
    enabled: false
  api_security:
    enabled: true
    skip_paths: [/health]
    api_keys:
      enabled: true
      header_name: X-API-Key
      keys:
        - name: test
          key_hash: `+key+`
          enabled: true
`))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	for _, tc := range []struct {
		path, key string
		want      int
	}{{"/private", "", 403}, {"/private", "invalid", 403}, {"/private", key, 204}, {"/health", "", 204}} {
		if got := libraryStatus(e, "GET", tc.path, "", tc.key); got != tc.want {
			t.Errorf("%s key present=%v got %d want %d", tc.path, tc.key != "", got, tc.want)
		}
	}
}

func TestLibrarySanitizerPathLimits(t *testing.T) {
	e, err := NewFromFile(writeLibraryConfig(t, `mode: enforce
waf:
  bot_detection:
    enabled: false
  sanitizer:
    max_body_size: 1024
    path_overrides:
      - path: /admin
        max_body_size: 8
      - path: /upload
        max_body_size: 2048
`))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	for _, tc := range []struct {
		path    string
		n, want int
	}{{"/admin", 0, 204}, {"/admin", 8, 204}, {"/admin", 9, 413}, {"/public", 64, 204}, {"/public", 1025, 413}, {"/upload", 1025, 204}, {"/upload", 2049, 413}} {
		if got := libraryStatus(e, "POST", tc.path, strings.Repeat("a", tc.n), ""); got != tc.want {
			t.Errorf("%s bytes=%d got %d want %d", tc.path, tc.n, got, tc.want)
		}
	}
}

func TestLibraryRejectsUnsupportedEnabledLayer(t *testing.T) {
	_, err := NewFromFile(writeLibraryConfig(t, "waf:\n  cors:\n    enabled: true\n"))
	if err == nil || !strings.Contains(err.Error(), "cors") || !strings.Contains(err.Error(), "not supported in library mode") {
		t.Fatalf("want explicit unsupported layer error, got %v", err)
	}
}

func TestLibraryCloseFlushesBans(t *testing.T) {
	persist := filepath.Join(t.TempDir(), "bans.json")
	e, err := New(Config{}, func(c *config.Config) { c.WAF.IPACL.AutoBan.PersistPath = persist })
	if err != nil {
		t.Fatal(err)
	}
	acl := e.internal.FindLayer("ipacl").(*ipacl.Layer)
	acl.AddAutoBan("203.0.113.7", "regression", e.cfg.WAF.IPACL.AutoBan.DefaultTTL)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if err := e.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	restored, err := New(Config{}, func(c *config.Config) { c.WAF.IPACL.AutoBan.PersistPath = persist })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.Close() })
	r := httptest.NewRequest("GET", "http://example.test/", nil)
	r.RemoteAddr = "203.0.113.7:12345"
	if !restored.Check(r).Blocked {
		t.Fatal("Close did not persist ban")
	}
}
