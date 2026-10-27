package dashboard

// Regression: the bot-detection config PUT silently dropped fields that the
// same endpoint advertises on GET (and that the YAML config loader accepts).
//
// Defect: applyWAFPatch's bot_detection branch handled only enabled, mode,
// user_agent.block_empty, user_agent.block_known_scanners,
// behavior.rps_threshold and behavior.error_rate_threshold. Everything else
// the GET counterpart (handleGetBotConfig) advertises —
// tls_fingerprint.{enabled,known_bots_action,unknown_action,mismatch_action},
// user_agent.enabled, behavior.enabled and behavior.window — was IGNORED.
//
// The endpoint nevertheless answered 200 "Bot detection configuration updated
// and saved", so the operator's change reached neither the running
// configuration nor the persisted config file (routingCtrl.Save writes
// eng.Config()): the setting was lost even across a restart, and the GET
// read-back kept reporting the old value.
//
// The violated invariant is the one this repository already established for
// the apivalidation per-schema strict_mode fix (internal/dashboard/
// apivalidation_handlers.go): an accepted parameter must either reach its
// consumer or be explicitly refused — never silently dropped while the
// endpoint reports success.
//
// PUT /api/v1/config is NOT an alternative write path for these fields:
// validateRuntimeReloadableConfig -> validateRuntimeReloadableWAFConfig 409s
// any waf.bot_detection change (reloadGuardWAFShape includes BotDetection).
// PUT /api/v1/config/bot is the only live write path.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/runtime/layerregistry"
)

type botConfigRegressionStore struct{}

func (botConfigRegressionStore) Store(engine.Event) error { return nil }
func (botConfigRegressionStore) Close() error             { return nil }

type botConfigRegressionBus struct{}

func (botConfigRegressionBus) Subscribe(chan<- engine.Event) {}
func (botConfigRegressionBus) Publish(engine.Event)          {}
func (botConfigRegressionBus) Close()                        {}

func botConfigRegressionRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "bot-config-key")
	return req
}

// newBotConfigRegressionDashboard wires a dashboard over a real engine with
// the real bot-detection layer installed (same wiring as
// cmd/guardianwaf/layers.go).
func newBotConfigRegressionDashboard(t *testing.T) (*Dashboard, *engine.Engine) {
	t.Helper()
	cfg := config.DefaultConfig()
	e, err := engine.NewEngine(cfg, botConfigRegressionStore{}, botConfigRegressionBus{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	ol, ok, err := layerregistry.BuildLayer("bot_detection", cfg)
	if err != nil || !ok {
		t.Fatalf("build bot_detection layer: ok=%v err=%v", ok, err)
	}
	e.AddLayer(ol)
	return New(e, events.NewMemoryStore(100), "bot-config-key"), e
}

// TestBotConfigPutAppliesAdvertisedFields pins the invariant: every field the
// endpoint advertises on GET and accepts on PUT must reach the configuration
// and the persisted config file.
func TestBotConfigPutAppliesAdvertisedFields(t *testing.T) {
	d, e := newBotConfigRegressionDashboard(t)

	// The config that routingCtrl.Save writes to disk (SaveFn persists
	// eng.Config()).
	var persisted *config.Config
	d.SetRoutingController(AtomicRoutingControllerFuncs{
		RoutingControllerFuncs: RoutingControllerFuncs{
			SaveFn: func() error {
				persisted = e.Config()
				return nil
			},
		},
	})

	body := `{
		"tls_fingerprint": {"enabled": false, "known_bots_action": "log", "unknown_action": "pass", "mismatch_action": "log"},
		"user_agent": {"enabled": false, "block_empty": false, "block_known_scanners": false},
		"behavior": {"enabled": false, "window": "90s", "rps_threshold": 42, "error_rate_threshold": 7}
	}`
	w := httptest.NewRecorder()
	d.Handler().ServeHTTP(w, botConfigRegressionRequest("PUT", "/api/v1/config/bot", body))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /api/v1/config/bot status=%d body=%s", w.Code, w.Body.String())
	}

	cfg := e.Config()
	bd := cfg.WAF.BotDetection

	if bd.TLSFingerprint.Enabled {
		t.Errorf("tls_fingerprint.enabled was silently dropped: still %v, want false", bd.TLSFingerprint.Enabled)
	}
	if bd.TLSFingerprint.KnownBotsAction != "log" {
		t.Errorf("tls_fingerprint.known_bots_action was silently dropped: still %q, want %q", bd.TLSFingerprint.KnownBotsAction, "log")
	}
	if bd.TLSFingerprint.UnknownAction != "pass" {
		t.Errorf("tls_fingerprint.unknown_action was silently dropped: still %q, want %q", bd.TLSFingerprint.UnknownAction, "pass")
	}
	if bd.TLSFingerprint.MismatchAction != "log" {
		t.Errorf("tls_fingerprint.mismatch_action was silently dropped: still %q, want %q", bd.TLSFingerprint.MismatchAction, "log")
	}
	if bd.UserAgent.Enabled {
		t.Errorf("user_agent.enabled was silently dropped: still %v, want false", bd.UserAgent.Enabled)
	}
	if bd.UserAgent.BlockEmpty {
		t.Errorf("user_agent.block_empty was silently dropped: still %v, want false", bd.UserAgent.BlockEmpty)
	}
	if bd.UserAgent.BlockKnownScanners {
		t.Errorf("user_agent.block_known_scanners was silently dropped: still %v, want false", bd.UserAgent.BlockKnownScanners)
	}
	if bd.Behavior.Enabled {
		t.Errorf("behavior.enabled was silently dropped: still %v, want false", bd.Behavior.Enabled)
	}
	if got := bd.Behavior.Window.String(); got != "1m30s" {
		t.Errorf("behavior.window was silently dropped: still %q, want %q", got, "1m30s")
	}
	if bd.Behavior.RPSThreshold != 42 {
		t.Errorf("behavior.rps_threshold was not applied: still %d, want 42", bd.Behavior.RPSThreshold)
	}
	if bd.Behavior.ErrorRateThreshold != 7 {
		t.Errorf("behavior.error_rate_threshold was not applied: still %d, want 7", bd.Behavior.ErrorRateThreshold)
	}

	// The values must also reach the persisted config file, otherwise the
	// operator's change is silently reverted on the next restart.
	if persisted == nil {
		t.Fatalf("PUT reported success but never persisted the config (routingCtrl.Save was not invoked)")
	}
	pbd := persisted.WAF.BotDetection
	if pbd.TLSFingerprint.Enabled || pbd.UserAgent.Enabled || pbd.Behavior.Enabled {
		t.Errorf("the persisted config file kept the old bot-detection posture "+
			"(tls_fingerprint.enabled=%v user_agent.enabled=%v behavior.enabled=%v) — the operator's change is lost on restart",
			pbd.TLSFingerprint.Enabled, pbd.UserAgent.Enabled, pbd.Behavior.Enabled)
	}
	if got := pbd.Behavior.Window.String(); got != "1m30s" {
		t.Errorf("the persisted config file kept the old behavior.window %q, want %q", got, "1m30s")
	}
}

// TestBotConfigPutRejectsMalformedWindow pins the second half of the
// invariant: a value that cannot be applied must be refused loudly rather
// than ignored while the endpoint reports success.
func TestBotConfigPutRejectsMalformedWindow(t *testing.T) {
	d, e := newBotConfigRegressionDashboard(t)

	w := httptest.NewRecorder()
	d.Handler().ServeHTTP(w, botConfigRegressionRequest("PUT", "/api/v1/config/bot",
		`{"behavior": {"window": "not-a-duration"}}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a malformed behavior.window, got %d body %s", w.Code, w.Body.String())
	}
	if got := e.Config().WAF.BotDetection.Behavior.Window.String(); got != config.DefaultConfig().WAF.BotDetection.Behavior.Window.String() {
		t.Errorf("a rejected patch must not change the configuration: behavior.window is now %q", got)
	}
}

// TestBotConfigPutControlKeepsHonouredFields is the control: the fields the
// PUT path already honoured must keep working, and an unrelated section must
// not be disturbed by a bot-detection patch.
func TestBotConfigPutControlKeepsHonouredFields(t *testing.T) {
	d, e := newBotConfigRegressionDashboard(t)

	w := httptest.NewRecorder()
	d.Handler().ServeHTTP(w, botConfigRegressionRequest("PUT", "/api/v1/config/bot",
		`{"enabled": false, "mode": "monitor", "behavior": {"rps_threshold": 42}}`))
	if w.Code != http.StatusOK {
		t.Fatalf("control: PUT status=%d body=%s", w.Code, w.Body.String())
	}
	cfg := e.Config()
	if cfg.WAF.BotDetection.Enabled {
		t.Errorf("control: bot_detection.enabled was not applied (still %v)", cfg.WAF.BotDetection.Enabled)
	}
	if cfg.WAF.BotDetection.Mode != "monitor" {
		t.Errorf("control: bot_detection.mode was not applied (still %q)", cfg.WAF.BotDetection.Mode)
	}
	if cfg.WAF.BotDetection.Behavior.RPSThreshold != 42 {
		t.Errorf("control: behavior.rps_threshold was not applied (still %d)", cfg.WAF.BotDetection.Behavior.RPSThreshold)
	}
	if cfg.WAF.Detection.Enabled != config.DefaultConfig().WAF.Detection.Enabled {
		t.Errorf("control: a bot_detection patch changed waf.detection.enabled")
	}
}
