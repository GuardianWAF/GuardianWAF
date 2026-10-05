package dashboard

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestRateLimitConfigExplicitZeroBurst(t *testing.T) {
	for _, emptyRules := range []bool{false, true} {
		cfg := config.DefaultConfig()
		if emptyRules {
			cfg.WAF.RateLimit.Rules = nil
		}
		e, err := engine.NewEngine(cfg, round75MockEventStore{}, round75MockEventBus{})
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		d := &Dashboard{engine: e}
		var persisted int
		failSave := false
		d.SetRoutingController(AtomicRoutingControllerFuncs{RoutingControllerFuncs: RoutingControllerFuncs{SaveFn: func() error {
			if failSave {
				return errors.New("fixture save failure")
			}
			persisted = e.Config().WAF.RateLimit.Rules[0].Burst
			return nil
		}}})
		apply := func(body string) int {
			rr := httptest.NewRecorder()
			d.handleUpdateRateLimitConfig(rr, httptest.NewRequest("PUT", "/api/v1/config/ratelimit", strings.NewReader(body)))
			return rr.Code
		}
		for _, tc := range []struct {
			body string
			want int
		}{
			{`{"burst":17}`, 17}, {`{"burst":0}`, 0}, {`{}`, 0}, {`{"burst":0}`, 0}, {`{"burst":8}`, 8}, {`{}`, 8}, {`{"burst":null}`, 8},
		} {
			if status := apply(tc.body); status != 200 {
				t.Fatalf("%s: status %d", tc.body, status)
			}
			if got := e.Config().WAF.RateLimit.Rules[0].Burst; got != tc.want || persisted != tc.want {
				t.Fatalf("%s: runtime=%d saved=%d want=%d", tc.body, got, persisted, tc.want)
			}
		}
		failSave = true
		if apply(`{"burst":0}`) != 500 || e.Config().WAF.RateLimit.Rules[0].Burst != 8 {
			t.Fatal("failed persistence did not restore previous burst")
		}
	}
}
