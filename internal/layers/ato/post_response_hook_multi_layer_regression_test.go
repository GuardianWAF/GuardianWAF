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
	"github.com/guardianwaf/guardianwaf/internal/layers/botdetect"
)

// Regression: a successful login must clear the failed-attempt counter even
// when another layer also needs the upstream outcome.
//
// The outcome channel (engine.RequestContext.PostResponseHook) serves more than
// one layer — the ATO layer (order 250) clears a successful login's failed
// attempts, bot detection (order 500) counts upstream errors — but it held a
// single function. The pipeline runs bot detection after the ATO layer, so its
// plain assignment overwrote the ATO layer's hook: the ATO hook never ran.
//
// The visible effect in the default serve configuration (bot detection is
// enabled by default): a user who mistyped twice, logged in successfully, and
// then mistyped once was answered 403 by the WAF instead of reaching the
// upstream. The existing ATO hook regression test wired only the ATO layer, so
// it never saw the collision.
//
// Control: with only the ATO layer in the pipeline the counter is cleared, and
// without a successful login the threshold still blocks — so this test cannot
// pass merely because brute-force detection is broken.
const (
	multiLayerBadLogin  = "email=user%40example.com&password=wrong-guess"
	multiLayerGoodLogin = "email=user%40example.com&password=correct-guess"
	multiLayerChromeUA  = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

// multiLayerServer wires the ATO layer and — optionally — the bot detection
// layer into one engine, at the positions they occupy in the serve pipeline.
func multiLayerServer(t *testing.T, withBotDetection bool) *httptest.Server {
	t.Helper()

	atoLayer, err := NewLayer(&Config{
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
		t.Fatalf("NewLayer(ato): %v", err)
	}

	eng, err := engine.NewEngine(config.DefaultConfig(), events.NewMemoryStore(64), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })
	eng.AddLayer(engine.OrderedLayer{Layer: atoLayer, Order: engine.OrderATO})

	if withBotDetection {
		// Bot detection's behavior analysis is enabled by default
		// (internal/config/defaults.go) and registers the SAME outcome channel.
		botLayer := botdetect.NewLayer(&botdetect.Config{
			Enabled: true,
			Mode:    "monitor",
			UserAgent: botdetect.UAConfig{
				Enabled:            true,
				BlockEmpty:         true,
				BlockKnownScanners: true,
			},
			Behavior: botdetect.BehaviorAnalysisConfig{
				Enabled:            true,
				Window:             time.Minute,
				RPSThreshold:       1000,
				ErrorRateThreshold: 1000,
			},
		})
		eng.AddLayer(engine.OrderedLayer{Layer: botLayer, Order: engine.OrderBotDetect})
	}

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
	return srv
}

func multiLayerPost(t *testing.T, srv *httptest.Server, body string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/login", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", multiLayerChromeUA)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestSuccessfulLoginClearsFailedAttemptsWithOtherOutcomeLayers(t *testing.T) {
	t.Run("bot detection does not discard the ATO hook", func(t *testing.T) {
		srv := multiLayerServer(t, true)
		if got := multiLayerPost(t, srv, multiLayerBadLogin); got != http.StatusUnauthorized {
			t.Fatalf("first failed login: got %d, want %d", got, http.StatusUnauthorized)
		}
		if got := multiLayerPost(t, srv, multiLayerBadLogin); got != http.StatusUnauthorized {
			t.Fatalf("second failed login: got %d, want %d", got, http.StatusUnauthorized)
		}
		if got := multiLayerPost(t, srv, multiLayerGoodLogin); got != http.StatusOK {
			t.Fatalf("successful login: got %d, want %d", got, http.StatusOK)
		}
		if got := multiLayerPost(t, srv, multiLayerBadLogin); got != http.StatusUnauthorized {
			t.Fatalf("login after a success: got %d, want %d — the successful login did not clear the "+
				"failed-attempt counter; another layer's registration on the outcome channel discarded the "+
				"ATO layer's hook", got, http.StatusUnauthorized)
		}
	})

	t.Run("control: ATO alone clears the counter", func(t *testing.T) {
		srv := multiLayerServer(t, false)
		if got := multiLayerPost(t, srv, multiLayerBadLogin); got != http.StatusUnauthorized {
			t.Fatalf("first failed login: got %d, want %d", got, http.StatusUnauthorized)
		}
		if got := multiLayerPost(t, srv, multiLayerBadLogin); got != http.StatusUnauthorized {
			t.Fatalf("second failed login: got %d, want %d", got, http.StatusUnauthorized)
		}
		if got := multiLayerPost(t, srv, multiLayerGoodLogin); got != http.StatusOK {
			t.Fatalf("successful login: got %d, want %d", got, http.StatusOK)
		}
		if got := multiLayerPost(t, srv, multiLayerBadLogin); got != http.StatusUnauthorized {
			t.Fatalf("CONTROL FAILED: login after a success got %d, want %d — harness problem", got, http.StatusUnauthorized)
		}
	})

	t.Run("control: threshold still blocks without a success", func(t *testing.T) {
		srv := multiLayerServer(t, true)
		blockedAt := 0
		for i := 1; i <= 4; i++ {
			if multiLayerPost(t, srv, multiLayerBadLogin) == http.StatusForbidden && blockedAt == 0 {
				blockedAt = i
			}
		}
		// Process checks the counter before recording the current attempt, so
		// the attempt that trips MaxAttemptsPerIP=3 is the fourth.
		if blockedAt != 4 {
			t.Fatalf("CONTROL FAILED: first WAF block at request #%d, want #4 — brute-force detection itself is broken", blockedAt)
		}
	})
}
