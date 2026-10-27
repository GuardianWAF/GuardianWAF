package guardianwaf

// Regression: library mode dropped the configured HSTS settings, so
// `Strict-Transport-Security` was never emitted — not even when the operator
// enabled it explicitly (it is enabled by default:
// internal/config/defaults.go sets response.security_headers.hsts.enabled =
// true, max_age = 31536000, include_subdomains = true).
//
// The serve-mode builder maps the same settings
// (internal/runtime/layerregistry/registry.go buildResponse), so the two
// documented deployment modes emitted different security headers for the same
// configuration file: serve mode sent Strict-Transport-Security, library mode
// did not. addDefaultLayers in guardianwaf.go never mapped the HSTS values
// into the response layer.
//
// The tests below drive the real library path (NewFromFile -> addDefaultLayers
// -> engine.Middleware) and assert the configured header value.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const hstsLibraryYAML = `
mode: enforce
waf:
  response:
    security_headers:
      enabled: true
      hsts:
        enabled: true
        max_age: 31536000
        include_subdomains: true
`

func writeHSTSLibraryYAML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "waf.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	return path
}

// hstsLibraryHeader returns the Strict-Transport-Security header that library
// mode emits for the given YAML.
func hstsLibraryHeader(t *testing.T, yaml string) string {
	t.Helper()
	eng, err := NewFromFile(writeHSTSLibraryYAML(t, yaml))
	if err != nil {
		t.Fatalf("NewFromFile: %v", err)
	}
	defer eng.Close()

	rec := httptest.NewRecorder()
	eng.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	return rec.Header().Get("Strict-Transport-Security")
}

// The configured HSTS header must be emitted in library mode.
func TestLibraryModeEmitsConfiguredHSTS(t *testing.T) {
	got := hstsLibraryHeader(t, hstsLibraryYAML)
	if got != "max-age=31536000; includeSubDomains" {
		t.Fatalf("FAIL: library mode emitted Strict-Transport-Security %q, want %q. The HSTS "+
			"settings are parsed into config and the serve-mode builder maps them, but "+
			"addDefaultLayers in guardianwaf.go never mapped them into the response layer, "+
			"so the operator's configured HSTS policy was silently dropped", got,
			"max-age=31536000; includeSubDomains")
	}
}

// Boundary: include_subdomains off must not append the directive.
func TestLibraryModeHSTSWithoutIncludeSubDomains(t *testing.T) {
	yaml := `
mode: enforce
waf:
  response:
    security_headers:
      enabled: true
      hsts:
        enabled: true
        max_age: 600
        include_subdomains: false
`
	got := hstsLibraryHeader(t, yaml)
	if got != "max-age=600" {
		t.Fatalf("FAIL: library mode emitted Strict-Transport-Security %q, want %q", got, "max-age=600")
	}
}

// The disabled knob must suppress the header in library mode too.
func TestLibraryModeHSTSDisabled(t *testing.T) {
	yaml := `
mode: enforce
waf:
  response:
    security_headers:
      enabled: true
      hsts:
        enabled: false
`
	if got := hstsLibraryHeader(t, yaml); got != "" {
		t.Fatalf("FAIL: library mode emitted Strict-Transport-Security %q with hsts.enabled: false", got)
	}
}
