package dashboard

// Regression: the security-disable audit must only record changes that are
// actually live.
//
// handleUpdateConfig called logSecurityConfigChanges BEFORE the three gates
// that can reject a change:
//
//	validateRuntimeReloadableConfig -> 409 Conflict
//	d.engine.Reload                 -> 500
//	routingCtrl.Save()              -> 500 + rollback to oldCfg
//
// so every rejected, failed or rolled-back security disable was still logged
// as "security feature disabled via config API" — a false record of a WAF
// control being switched off while it is still enabled.
//
// These tests drive the real handler against a real *engine.Engine. The handler
// is invoked directly rather than through authAuditWrap so the API-key rate
// limiter cannot turn a follow-up call into a 429.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

const cfgAuditSecurityDisableMsg = "security feature disabled via config API"

// cfgAuditCapture records which features the security-disable audit fired for.
type cfgAuditCapture struct {
	mu   sync.Mutex
	hits []string
}

func (c *cfgAuditCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *cfgAuditCapture) Handle(_ context.Context, r slog.Record) error {
	if r.Message != cfgAuditSecurityDisableMsg {
		return nil
	}
	feature := ""
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "feature" {
			feature = a.Value.String()
		}
		return true
	})
	c.mu.Lock()
	c.hits = append(c.hits, feature)
	c.mu.Unlock()
	return nil
}

func (c *cfgAuditCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *cfgAuditCapture) WithGroup(string) slog.Handler      { return c }

func (c *cfgAuditCapture) reset() {
	c.mu.Lock()
	c.hits = nil
	c.mu.Unlock()
}

func (c *cfgAuditCapture) saw(feature string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range c.hits {
		if f == feature {
			return true
		}
	}
	return false
}

func installCfgAuditCapture(t *testing.T) *cfgAuditCapture {
	t.Helper()
	c := &cfgAuditCapture{}
	old := dashboardLog
	dashboardLog = slog.New(c)
	t.Cleanup(func() { dashboardLog = old })
	return c
}

// cfgAuditDashboard builds a Dashboard whose engine starts with detection and
// challenge both enabled, so a disable is a real true->false transition.
func cfgAuditDashboard(t *testing.T) *Dashboard {
	t.Helper()
	proxy.SetPrivateTargetsAllowed(true)
	cfg := config.DefaultConfig()
	allowPrivate := true
	cfg.AllowPrivateUpstreams = &allowPrivate
	cfg.WAF.Detection.Enabled = true
	cfg.WAF.Challenge.Enabled = true

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("setup: engine.NewEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })
	d := New(eng, store, "cfg-audit-test-key")
	t.Cleanup(d.Close)

	live := d.engine.Config()
	if !live.WAF.Detection.Enabled || !live.WAF.Challenge.Enabled {
		t.Fatalf("setup: expected detection and challenge enabled; got detection=%v challenge=%v",
			live.WAF.Detection.Enabled, live.WAF.Challenge.Enabled)
	}
	return d
}

func cfgAuditPut(t *testing.T, d *Dashboard, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/config", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	d.handleUpdateConfig(rr, req)
	return rr
}

// cfgAuditFailingSave makes the persistence gate fail so the rollback branch runs.
type cfgAuditFailingSave struct{}

func (cfgAuditFailingSave) Rebuild() error { return nil }
func (cfgAuditFailingSave) Save() error    { return errors.New("disk full") }

// TestSecurityDisableAuditNotRecordedForRejectedChange is the defect: a change
// the runtime-reload guard rejects with 409 must not be audited as applied.
func TestSecurityDisableAuditNotRecordedForRejectedChange(t *testing.T) {
	audit := installCfgAuditCapture(t)
	d := cfgAuditDashboard(t)

	audit.reset()
	rr := cfgAuditPut(t, d, `{"waf":{"detection":{"enabled":false}}}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("precondition: disabling detection is a WAF topology change and must be rejected with 409; got %d (%s)",
			rr.Code, strings.TrimSpace(rr.Body.String()))
	}
	if !d.engine.Config().WAF.Detection.Enabled {
		t.Fatal("precondition: detection must still be enabled after a rejected change")
	}
	if audit.saw("detection") {
		t.Fatalf("rejected change (409) was audited as an applied security disable; detection is still enabled. " +
			"The audit must fire only after the change is live and persisted.")
	}
}

// Direct logger control: retain auditing for callers that have actually applied
// a security change; generic config API now rejects every layer topology change.
func TestSecurityDisableAuditRecordedForAppliedChange(t *testing.T) {
	audit := installCfgAuditCapture(t)
	d := cfgAuditDashboard(t)
	old := d.engine.Config()
	changed := old.DeepCopy()
	changed.WAF.Challenge.Enabled = false
	audit.reset()
	d.logSecurityConfigChanges(old, changed, httptest.NewRequest(http.MethodPut, "/api/v1/config", nil))
	if !audit.saw("challenge") {
		t.Fatal("applied security disable must remain auditable")
	}
}

// TestSecurityDisableAuditNotRecordedWhenRollbackRuns covers the persistence
// gate: Save() failing rolls the runtime back to the previous config, so the
// change never took effect and must not be audited as applied.
func TestSecurityDisableAuditNotRecordedWhenRollbackRuns(t *testing.T) {
	audit := installCfgAuditCapture(t)
	d := cfgAuditDashboard(t)
	d.SetRoutingController(cfgAuditFailingSave{})
	old := d.engine.Config().WAF.Detection.Threshold.Block
	audit.reset()
	rr := cfgAuditPut(t, d, `{"waf":{"detection":{"threshold":{"block":75}}}}`)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("failing Save must return 500, got %d (%s)", rr.Code, rr.Body.String())
	}
	if d.engine.Config().WAF.Detection.Threshold.Block != old {
		t.Fatal("threshold was not rolled back")
	}
	if len(audit.hits) != 0 {
		t.Fatal("rolled-back update was audited as security disable")
	}
}

// TestSecurityDisableAuditNotRecordedForNoOpUpdate is the neighbouring-valid
// control: an update that changes no security flag must not log anything.
func TestSecurityDisableAuditNotRecordedForNoOpUpdate(t *testing.T) {
	audit := installCfgAuditCapture(t)
	d := cfgAuditDashboard(t)

	// A detection threshold is runtime-reloadable (zeroed in reloadGuardWAFShape)
	// and is not a security-disable field.
	audit.reset()
	rr := cfgAuditPut(t, d, `{"waf":{"detection":{"threshold":{"block":75}}}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("a runtime-reloadable threshold update must return 200; got %d (%s)",
			rr.Code, strings.TrimSpace(rr.Body.String()))
	}
	if len(audit.hits) != 0 {
		t.Fatalf("no security feature was disabled, so the audit must be silent; recorded %v", audit.hits)
	}
}
