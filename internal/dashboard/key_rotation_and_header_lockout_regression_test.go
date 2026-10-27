package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func serveWith(d *Dashboard, method, path, ip, key string, cookie *http.Cookie, body string) int {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = ip + ":1234"
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	d.Handler().ServeHTTP(w, req)
	return w.Code
}

// Regression: rotating the dashboard key (the response to a leak) left every
// browser session valid for up to its 7-day absolute lifetime, because
// sessions are signed with the session secret, not the API key.
func TestRotateKeyRevokesExistingSessions(t *testing.T) {
	d := newTestDashboard(t, "old-dashboard-key-0001")
	t.Cleanup(d.Close)
	const ip = "192.0.2.30"
	stale := &http.Cookie{Name: sessionCookieName, Value: signSessionAt(ip, time.Now(), time.Now().Add(-time.Hour))}

	if code := serveWith(d, "GET", "/api/v1/stats", ip, "", stale, ""); code != http.StatusOK {
		t.Fatalf("pre-rotation session status = %d, want 200", code)
	}
	body := `{"current_key":"old-dashboard-key-0001","new_key":"new-dashboard-key-0002"}`
	if code := serveWith(d, "POST", "/api/v1/rotate-key", ip, "old-dashboard-key-0001", nil, body); code != http.StatusOK {
		t.Fatalf("rotate status = %d, want 200", code)
	}
	if code := serveWith(d, "GET", "/api/v1/stats", ip, "", stale, ""); code != http.StatusUnauthorized {
		t.Fatalf("pre-rotation session after rotation: status = %d, want 401", code)
	}

	fresh := &http.Cookie{Name: sessionCookieName, Value: signSessionAt(ip, time.Now(), time.Now().Add(time.Second))}
	if code := serveWith(d, "GET", "/api/v1/stats", ip, "", fresh, ""); code != http.StatusOK {
		t.Fatalf("post-rotation session status = %d, want 200", code)
	}

	// Revocation is per dashboard instance, not process-global state.
	other := newTestDashboard(t, "other-dashboard-key-03")
	t.Cleanup(other.Close)
	if code := serveWith(other, "GET", "/api/v1/stats", ip, "", stale, ""); code != http.StatusOK {
		t.Fatalf("unrelated dashboard rejected its session: status = %d", code)
	}
}

// Regression: the 5-attempt lockout only guarded POST /login, so X-API-Key
// allowed unlimited online key guessing.
func TestHeaderKeyGuessingSharesLoginLockout(t *testing.T) {
	d := newTestDashboard(t, "real-dashboard-key-001")
	d.SetAdminKey("real-admin-key-000001")
	t.Cleanup(d.Close)

	const attacker = "203.0.113.40"
	for i := range loginMaxAttempts {
		if code := serveWith(d, "GET", "/api/v1/stats", attacker, "guess-"+string(rune('a'+i)), nil, ""); code != http.StatusUnauthorized {
			t.Fatalf("guess %d status = %d, want 401", i, code)
		}
	}
	if code := serveWith(d, "GET", "/api/v1/stats", attacker, "real-dashboard-key-001", nil, ""); code != http.StatusTooManyRequests {
		t.Fatalf("correct key during lockout: status = %d, want 429", code)
	}
	if code := serveWith(d, "GET", "/api/admin/tenants", attacker, "real-admin-key-000001", nil, ""); code != http.StatusTooManyRequests {
		t.Fatalf("admin route during lockout: status = %d, want 429", code)
	}
	if d.checkLoginRateLimit(attacker) {
		t.Fatal("header guessing did not lock out the /login form")
	}

	// Another client is unaffected.
	if code := serveWith(d, "GET", "/api/v1/stats", "203.0.113.41", "real-dashboard-key-001", nil, ""); code != http.StatusOK {
		t.Fatalf("unrelated client status = %d, want 200", code)
	}
}

func TestAdminRouteWithDashboardKeyDoesNotCountAsGuess(t *testing.T) {
	d := newTestDashboard(t, "real-dashboard-key-001")
	d.SetAdminKey("real-admin-key-000001")
	t.Cleanup(d.Close)

	const operator = "203.0.113.50"
	for range loginMaxAttempts + 2 {
		if code := serveWith(d, "GET", "/api/admin/tenants", operator, "real-dashboard-key-001", nil, ""); code != http.StatusUnauthorized {
			t.Fatalf("dashboard key on admin route: status = %d, want 401", code)
		}
	}
	if code := serveWith(d, "GET", "/api/v1/stats", operator, "real-dashboard-key-001", nil, ""); code != http.StatusOK {
		t.Fatalf("operator locked out by permission errors: status = %d", code)
	}
}
