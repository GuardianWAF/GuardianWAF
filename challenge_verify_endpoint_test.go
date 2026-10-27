package guardianwaf

// Regression test: the WAF must own the JS-challenge VERIFICATION endpoint.
//
// The challenge page the WAF serves embeds an absolute form action
// ("/__guardianwaf/challenge/verify", internal/layers/challenge/page.go), so
// the WAF that serves that page must also answer the solution POST. Serve
// mode registers the path on its mux ahead of the proxy route
// (cmd/guardianwaf/challenge_runtime.go), but library and sidecar mode have
// no such mux: the engine wires the very same challenge service
// (guardianwaf.go wireChallengeService -> eng.SetChallengeService) and
// serves the challenge page, yet nothing owned the verification path.
//
// The consequence was a permanently stuck client: the solution POST fell
// through to the embedder's own handler, the __gwaf_challenge clearance
// cookie was never issued, and every request stayed in the challenge band.
//
// This test drives the real library path (NewFromFile -> Middleware) and
// asserts the WAF owns the endpoint. Controls: a normal browser request
// still reaches the application, and the challenge page is still served for
// the challenge-band request.

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/layers/challenge"
)

const libraryChallengeVerifyYAML = `
mode: enforce
waf:
  detection:
    enabled: true
    threshold:
      block: 200
      log: 25
  challenge:
    enabled: true
    difficulty: 8
  bot_detection:
    enabled: true
    mode: enforce
    user_agent:
      enabled: true
      block_empty: true
`

const libraryChallengeChromeUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// solveLibraryChallengePoW finds a nonce such that SHA256(challenge+nonce)
// has the given number of leading zero bits — the scheme the challenge page's
// inline JavaScript implements.
func solveLibraryChallengePoW(challengeToken string, bits int) (string, bool) {
	for n := 0; n < 1<<22; n++ {
		nonce := strconv.FormatInt(int64(n), 16)
		sum := sha256.Sum256([]byte(challengeToken + nonce))
		if libraryChallengeLeadingZeroBits(sum[:], bits) {
			return nonce, true
		}
	}
	return "", false
}

func libraryChallengeLeadingZeroBits(hash []byte, bits int) bool {
	full := bits / 8
	rem := bits % 8
	for i := 0; i < full; i++ {
		if hash[i] != 0 {
			return false
		}
	}
	if rem > 0 && full < len(hash) {
		if hash[full]&(0xFF<<(8-rem)) != 0 {
			return false
		}
	}
	return true
}

// TestLibraryModeOwnsChallengeVerificationEndpoint asserts that the WAF
// answers the proof-of-work solution POST itself and issues the clearance
// cookie, instead of letting it fall through to the application.
func TestLibraryModeOwnsChallengeVerificationEndpoint(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, "waf.yaml")
	if err := os.WriteFile(specPath, []byte(libraryChallengeVerifyYAML), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	eng, err := NewFromFile(specPath)
	if err != nil {
		t.Fatalf("NewFromFile: %v", err)
	}
	defer func() { _ = eng.Close() }()

	appHits := 0
	app := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		appHits++
		// 200, not an error status: the bot detector's behavior tracker
		// scores the response error rate, and a 4xx/5xx from the app would
		// push the challenge-band request into the block band instead of the
		// challenge band (a harness artifact, not the defect).
		w.WriteHeader(http.StatusOK)
	})
	mw := eng.Middleware(app)

	// Control: a normal browser request reaches the application.
	okReq := httptest.NewRequest(http.MethodGet, "/", nil)
	okReq.Header.Set("User-Agent", libraryChallengeChromeUA)
	okRec := httptest.NewRecorder()
	mw.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("control failed: normal browser request did not reach the app (%d) — harness problem", okRec.Code)
	}

	// Control: the challenge-band request is served the challenge page.
	chalReq := httptest.NewRequest(http.MethodGet, "/", nil)
	chalReq.Header.Set("User-Agent", "")
	chalRec := httptest.NewRecorder()
	mw.ServeHTTP(chalRec, chalReq)
	if chalRec.Header().Get("X-GuardianWAF-Challenge") != "1" {
		t.Fatalf("control failed: no challenge page served (status %d) — harness problem", chalRec.Code)
	}
	page := chalRec.Body.String()
	if !strings.Contains(page, "Security Check") {
		t.Fatalf("control failed: challenge page body missing — harness problem")
	}

	// The challenge token the page hands to the browser.
	m := regexp.MustCompile(`var C="([^"]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("control failed: no challenge token in the page — harness problem")
	}
	token := m[1]

	nonce, ok := solveLibraryChallengePoW(token, 8)
	if !ok {
		t.Fatalf("harness: no PoW nonce found")
	}

	// The defect: the solution POST must be answered by the WAF.
	form := url.Values{"challenge": {token}, "nonce": {nonce}, "redirect": {"/"}}
	post := httptest.NewRequest(http.MethodPost, challenge.VerifyPath, strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("User-Agent", libraryChallengeChromeUA)
	postRec := httptest.NewRecorder()
	before := appHits
	mw.ServeHTTP(postRec, post)

	if postRec.Code != http.StatusSeeOther {
		t.Fatalf("the challenge solution POST to %s was not handled by the WAF (status %d, body %.120q). "+
			"The challenge page embeds that absolute form action, so the WAF owns the verification endpoint — "+
			"but outside serve mode nothing routed it, so the solution fell through to the application "+
			"(%d app hits) and no clearance cookie was ever issued: the client stays challenged forever.",
			challenge.VerifyPath, postRec.Code, postRec.Body.String(), appHits-before)
	}
	if appHits != before {
		t.Errorf("the challenge solution POST reached the application (%d extra hits) — the WAF must own the endpoint", appHits-before)
	}

	cookies := postRec.Result().Cookies()
	clearance := ""
	for _, c := range cookies {
		if c.Name == "__gwaf_challenge" {
			clearance = c.Value
		}
	}
	if clearance == "" {
		t.Fatalf("the WAF answered the solution POST with %d but issued no __gwaf_challenge clearance cookie "+
			"(cookies: %v) — the client stays challenged forever", postRec.Code, cookies)
	}

	// Secondary branch: with the clearance cookie the client is no longer challenged.
	replay := httptest.NewRequest(http.MethodGet, "/", nil)
	replay.Header.Set("User-Agent", "")
	replay.AddCookie(&http.Cookie{Name: "__gwaf_challenge", Value: clearance})
	replayRec := httptest.NewRecorder()
	mw.ServeHTTP(replayRec, replay)
	if replayRec.Header().Get("X-GuardianWAF-Challenge") == "1" {
		t.Fatalf("a client holding a valid clearance cookie is still challenged")
	}
}
