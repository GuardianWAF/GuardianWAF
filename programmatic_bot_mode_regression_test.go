package guardianwaf_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	guardianwaf "github.com/guardianwaf/guardianwaf"
)

func programmaticBotConfig(mode string) guardianwaf.Config {
	return guardianwaf.Config{
		Mode:      mode,
		Threshold: guardianwaf.ThresholdConfig{Block: 100, Log: 90},
		Bot: guardianwaf.BotConfig{
			Enabled:    true,
			BlockEmpty: true,
		},
		Challenge: guardianwaf.ChallengeConfig{
			Enabled:    true,
			Difficulty: 1,
		},
	}
}

func programmaticBotRequest(ua string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", ua)
	return req
}

func TestProgrammaticEnforceModeChallengesBotScoreBand(t *testing.T) {
	waf, err := guardianwaf.New(programmaticBotConfig(guardianwaf.ModeEnforce))
	if err != nil {
		t.Fatal(err)
	}
	defer waf.Close()

	verdict := waf.Check(programmaticBotRequest(""))
	if verdict.Action != "challenge" {
		t.Errorf("FAIL: New(ModeEnforce) produced action %q at score %d for the bot challenge band; want challenge", verdict.Action, verdict.TotalScore)
	}

	called := false
	rec := httptest.NewRecorder()
	waf.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rec, programmaticBotRequest(""))
	if called || rec.Header().Get("X-GuardianWAF-Challenge") != "1" || !strings.Contains(rec.Body.String(), "Security Check") {
		t.Fatalf("FAIL: programmatic enforce-mode bot request bypassed the challenge: called=%v status=%d header=%q body=%.120q", called, rec.Code, rec.Header().Get("X-GuardianWAF-Challenge"), rec.Body.String())
	}
}

func TestProgrammaticMonitorModeStillLogsAndPasses(t *testing.T) {
	waf, err := guardianwaf.New(programmaticBotConfig(guardianwaf.ModeMonitor))
	if err != nil {
		t.Fatal(err)
	}
	defer waf.Close()

	if verdict := waf.Check(programmaticBotRequest("")); verdict.Action != "pass" {
		t.Fatalf("monitor-mode empty-UA action = %q, want pass below the configured global thresholds", verdict.Action)
	}
	rec := httptest.NewRecorder()
	waf.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, programmaticBotRequest(""))
	if rec.Code != http.StatusNoContent || rec.Header().Get("X-GuardianWAF-Challenge") != "" {
		t.Fatalf("monitor-mode control did not pass through: status=%d header=%q", rec.Code, rec.Header().Get("X-GuardianWAF-Challenge"))
	}
}

func TestProgrammaticEnforceModeNormalBrowserPasses(t *testing.T) {
	waf, err := guardianwaf.New(programmaticBotConfig(guardianwaf.ModeEnforce))
	if err != nil {
		t.Fatal(err)
	}
	defer waf.Close()

	const browserUA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"
	if verdict := waf.Check(programmaticBotRequest(browserUA)); verdict.Action != "pass" {
		t.Fatalf("normal-browser action = %q, want pass", verdict.Action)
	}
	rec := httptest.NewRecorder()
	waf.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})).ServeHTTP(rec, programmaticBotRequest(browserUA))
	if rec.Code != http.StatusAccepted || rec.Header().Get("X-GuardianWAF-Challenge") != "" {
		t.Fatalf("normal-browser control did not pass through: status=%d header=%q", rec.Code, rec.Header().Get("X-GuardianWAF-Challenge"))
	}
}
