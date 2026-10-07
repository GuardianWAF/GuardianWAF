package ato

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

// Regression: a successful login must clear the failed attempts recorded for it,
// through the real request path.
//
// Process records every login attempt optimistically — it cannot see the
// upstream response — so the counter is only correct if the layer is told the
// outcome afterwards. PostProcess existed but had no production caller (the
// engine never invoked it), so a user who mistyped twice, logged in
// successfully, then mistyped once was answered 403 by the WAF instead of
// reaching the upstream. The layer now registers
// engine.RequestContext.PostResponseHook during Process and the engine invokes
// it with success = upstream status < 400.
func TestSuccessfulLoginClearsFailedAttemptsThroughEngine(t *testing.T) {
	const (
		badLogin  = "email=user%40example.com&password=wrong-guess"
		goodLogin = "email=user%40example.com&password=correct-horse"
	)

	newServer := func(t *testing.T) (*httptest.Server, *Layer) {
		t.Helper()
		layer, err := NewLayer(&Config{
			Enabled:    true,
			LoginPaths: []string{"/login"},
			BruteForce: BruteForceConfig{
				Enabled:             true,
				Window:              time.Hour,
				MaxAttemptsPerIP:    3,
				MaxAttemptsPerEmail: 10,
				BlockDuration:       time.Minute,
			},
		})
		if err != nil {
			t.Fatalf("NewLayer: %v", err)
		}

		eng, err := engine.NewEngine(config.DefaultConfig(), events.NewMemoryStore(64), events.NewEventBus())
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		t.Cleanup(func() { _ = eng.Close() })
		eng.AddLayer(engine.OrderedLayer{Layer: layer, Order: engine.OrderATO})

		upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "wrong-guess") {
				w.WriteHeader(http.StatusUnauthorized) // upstream: login failed
				return
			}
			w.WriteHeader(http.StatusOK) // upstream: login succeeded
		})

		srv := httptest.NewServer(eng.Middleware(upstream))
		t.Cleanup(srv.Close)
		return srv, layer
	}

	post := func(t *testing.T, srv *httptest.Server, body string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/login", strings.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	t.Run("success clears the counter", func(t *testing.T) {
		srv, _ := newServer(t)
		if got := post(t, srv, badLogin); got != http.StatusUnauthorized {
			t.Fatalf("first failed login: got %d, want %d", got, http.StatusUnauthorized)
		}
		if got := post(t, srv, badLogin); got != http.StatusUnauthorized {
			t.Fatalf("second failed login: got %d, want %d", got, http.StatusUnauthorized)
		}
		if got := post(t, srv, goodLogin); got != http.StatusOK {
			t.Fatalf("successful login: got %d, want %d", got, http.StatusOK)
		}
		// The counter was cleared, so this mistyped login reaches the upstream.
		if got := post(t, srv, badLogin); got != http.StatusUnauthorized {
			t.Fatalf("login after a success: got %d, want %d — the successful login did not "+
				"clear the failed-attempt counter", got, http.StatusUnauthorized)
		}
	})

	// Control: without a successful login the threshold still blocks, so the
	// test above cannot pass merely because brute-force detection is broken.
	t.Run("threshold still blocks without a success", func(t *testing.T) {
		srv, _ := newServer(t)
		var blockedAt int
		for i := 1; i <= 4; i++ {
			if post(t, srv, badLogin) == http.StatusForbidden && blockedAt == 0 {
				blockedAt = i
			}
		}
		// Process checks the counter before recording the current attempt, so
		// the attempt that trips MaxAttemptsPerIP=3 is the fourth.
		if blockedAt != 4 {
			t.Fatalf("first WAF block at request #%d, want #4 — brute-force detection itself is broken", blockedAt)
		}
	})
}
