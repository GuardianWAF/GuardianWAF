package quality

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: only Referer and User-Agent (plus four SSRF headers for the
// SSRF detector) were scanned, so an injection in any application-defined
// header — one the backend reads as data — scored 0 and was forwarded.
func TestCustomHeaderInjectionBlocked(t *testing.T) {
	eng := newPipeline(t)
	for i, tc := range []struct{ name, value string }{
		{"X-Api-Key", "' OR '1'='1' --"},
		{"X-Tenant-Id", "acme' UNION SELECT password FROM users--"},
		{"X-Original-URL", "/admin/../../../../etc/passwd"},
		{"X-File-Name", "report.pdf; cat /etc/shadow"},
		{"X-Search-Query", "<script>alert(document.cookie)</script>"},
		{"X-Template", "{{7*7}}{{config.__class__.__init__.__globals__}}"},
		{"X-Filter", `{"$where": "this.password.length > 0"}`},
	} {
		r := httptest.NewRequest(http.MethodGet, "/api/items", nil)
		browserHeaders(r, i)
		r.Header.Set(tc.name, tc.value)
		if ev := eng.Check(r); ev.Action != engine.ActionBlock {
			t.Errorf("%s: %q not blocked (score %d)", tc.name, tc.value, ev.Score)
		}
	}
}

// Protocol and credential headers are not free text: SQL-looking bytes in a
// base64 Authorization value or a Sec-* client hint must not score.
func TestStructuredHeadersNotScannedAsText(t *testing.T) {
	eng := newPipeline(t)
	r := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	browserHeaders(r, 1)
	r.Header.Set("Authorization", "Bearer ' OR 1=1 --")
	r.Header.Set("Sec-Ch-Ua", `"Chromium";v="131", "Not_A Brand";v="24"`)
	r.Header.Set("If-None-Match", `W/"<script>"`)
	if ev := eng.Check(r); ev.Action == engine.ActionBlock {
		t.Fatalf("structured headers blocked (score %d)", ev.Score)
	}
}
