package quality

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: classic payloads in application/x-www-form-urlencoded bodies
// scored zero end to end, so every HTML form (login, comment, search) was an
// unprotected path.
func TestFormBodyAttacksAreBlocked(t *testing.T) {
	eng := newPipeline(t)
	for i, payload := range []string{
		"' OR 1=1 --",
		"admin' --",
		"1' UNION SELECT username, password FROM users--",
		"<script>alert(1)</script>",
		"; cat /etc/passwd",
	} {
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("user="+url.QueryEscape(payload)+"&remember=on"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		browserHeaders(r, i+1)
		if ev := eng.Check(r); ev.Action != engine.ActionBlock {
			t.Errorf("form payload %q: action=%v score=%d, want block", payload, ev.Action, ev.Score)
		}
	}
}
