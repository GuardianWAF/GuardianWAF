package quality

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: cookie values were inspected only as transmitted, so the
// URL-encoded SQL injection that PHP, Express and Rails decode before the
// application reads it scored 0.
func TestURLEncodedCookieInjectionBlocked(t *testing.T) {
	eng := newPipeline(t)
	for i, cookie := range []string{
		"session=%27+OR+1%3D1+--",
		"session=%27%20UNION%20SELECT%20password%20FROM%20users--",
		"prefs=%3Bcat+%2Fetc%2Fpasswd",
	} {
		r := httptest.NewRequest(http.MethodGet, "/account", nil)
		browserHeaders(r, i)
		r.Header.Set("Cookie", cookie)
		if ev := eng.Check(r); ev.Action != engine.ActionBlock {
			t.Errorf("Cookie %q not blocked (score %d)", cookie, ev.Score)
		}
	}
}
