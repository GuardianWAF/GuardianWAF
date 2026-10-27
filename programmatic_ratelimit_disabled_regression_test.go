package guardianwaf_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	guardianwaf "github.com/guardianwaf/guardianwaf"
)

func rateLimitProofRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://waf.example/benign", nil)
	req.RemoteAddr = "198.51.100.42:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0")
	return req
}

func TestProgrammaticDisabledRateLimitDoesNotThrottle(t *testing.T) {
	waf, err := guardianwaf.New(guardianwaf.Config{
		Mode: guardianwaf.ModeEnforce,
		RateLimit: guardianwaf.RateLimitConfig{
			Enabled: false,
			// Supplying a rule makes the caller's intent explicit: retain the
			// configuration but do not enforce it while the layer is disabled.
			Rules: []guardianwaf.RateLimitRule{{
				ID:     "must-stay-disabled",
				Scope:  "ip",
				Limit:  1,
				Window: time.Hour,
				Burst:  1,
				Action: "block",
			}},
		},
	})
	if err != nil {
		t.Fatalf("New disabled rate limiter: %v", err)
	}
	defer waf.Close()

	// More than the internal default burst of 50 proves that convertConfig did
	// not silently retain the default-enabled global limiter.
	for i := range 60 {
		result := waf.Check(rateLimitProofRequest())
		if result.Blocked || result.Action == "block" {
			t.Fatalf("FAIL: RateLimit.Enabled=false blocked benign request %d: action=%q score=%d findings=%+v", i+1, result.Action, result.TotalScore, result.Findings)
		}
	}
}

func TestProgrammaticEnabledRateLimitStillEnforces(t *testing.T) {
	waf, err := guardianwaf.New(guardianwaf.Config{
		Mode: guardianwaf.ModeEnforce,
		RateLimit: guardianwaf.RateLimitConfig{
			Enabled: true,
			Rules: []guardianwaf.RateLimitRule{{
				ID:     "enabled-control",
				Scope:  "ip",
				Limit:  1,
				Window: time.Hour,
				Burst:  1,
				Action: "block",
			}},
		},
	})
	if err != nil {
		t.Fatalf("New enabled rate limiter: %v", err)
	}
	defer waf.Close()

	if first := waf.Check(rateLimitProofRequest()); first.Blocked || first.Action == "block" {
		t.Fatalf("enabled control blocked its first request: %+v", first)
	}
	second := waf.Check(rateLimitProofRequest())
	if !second.Blocked || second.Action != "block" {
		t.Fatalf("enabled control did not block its second request: %+v", second)
	}
}
