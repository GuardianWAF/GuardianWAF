package guardianwaf

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests: NewFromFile must wire the challenge service when the
// YAML enables it. New() wires challenge.Config from the public Config, but
// NewFromFile — the documented quick-start path — never called
// SetChallengeService. Combined with bot_detection.mode: enforce (the only
// library-mode way to produce ActionChallenge, since the public BotConfig
// cannot set the bot mode), a challenge-band request got the block fallback
// in Middleware instead of the proof-of-work challenge.

const challengeFromFileYAML = `
mode: enforce
waf:
  detection:
    enabled: true
    threshold:
      block: 200
      log: 25
  challenge:
    enabled: true
    difficulty: 20
  bot_detection:
    enabled: true
    mode: enforce
    user_agent:
      enabled: true
      block_empty: true
`

func TestNewFromFileWiresChallengeService(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, "waf.yaml")
	if err := os.WriteFile(specPath, []byte(challengeFromFileYAML), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	fromFile, err := NewFromFile(specPath)
	if err != nil {
		t.Fatalf("NewFromFile: %v", err)
	}
	defer fromFile.Close()

	ualess := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("User-Agent", "") // botdetect scores an empty UA at 40
		return req
	}

	// Precondition: the pipeline itself must decide ActionChallenge for the
	// empty-UA request (botdetect enforce band) — this proves the fixture
	// drives the challenge path, independent of the wiring bug.
	verdict := fromFile.Check(ualess())
	if verdict.Action != "challenge" {
		t.Fatalf("FAIL: fixture precondition broken — engine verdict for empty-UA request = %v (score %d), want challenge", verdict.Action, verdict.TotalScore)
	}

	// The defect: with the challenge service unwired, Middleware fell back to
	// the block page instead of serving the proof-of-work challenge.
	rec := httptest.NewRecorder()
	fromFile.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, ualess())

	if rec.Header().Get("X-GuardianWAF-Challenge") != "1" {
		t.Fatalf("FAIL: NewFromFile ignored challenge.enabled — challenge-band request served %.200q instead of the challenge page", rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Security Check") {
		t.Fatalf("FAIL: challenge response missing the challenge page body: %.200q", body)
	}
	if strings.Contains(body, "Request Blocked") || strings.Contains(body, "403 Blocked") {
		t.Fatalf("FAIL: challenge-band request served the block page: %.200q", body)
	}

	// Boundary: a normal browser UA must pass through untouched.
	okReq := httptest.NewRequest(http.MethodGet, "/", nil)
	okReq.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0")
	okRec := httptest.NewRecorder()
	fromFile.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusTeapot {
		t.Fatalf("FAIL: normal-browser request did not reach the handler: %d / %.120q", okRec.Code, okRec.Body.String())
	}
}
