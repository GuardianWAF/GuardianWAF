package challenge

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newReplayTestService(t *testing.T) *Service {
	t.Helper()

	svc, err := NewService(Config{
		SecretKey:  []byte("test-key-32-bytes-long-aaaaaaaaaaa!"),
		Difficulty: 4,
		CookieName: "__gwaf_test",
		CookieTTL:  time.Hour,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func postSolution(t *testing.T, svc *Service, challenge, nonce, remoteAddr string) *http.Response {
	t.Helper()

	form := url.Values{"challenge": {challenge}, "nonce": {nonce}, "redirect": {"/"}}
	req := httptest.NewRequest(http.MethodPost, VerifyPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = remoteAddr

	w := httptest.NewRecorder()
	svc.VerifyHandler().ServeHTTP(w, req)
	return w.Result()
}

// TestVerifyHandler_RejectsSelfMintedChallenge pins the core fix: the challenge
// must be one this server issued. Previously VerifyHandler read the challenge
// straight from the POST form and only checked that SHA256(challenge+nonce) had
// the required leading zero bits — so an attacker chose a convenient string,
// ground a nonce offline once, and got a clearance cookie without the server
// ever having issued anything.
func TestVerifyHandler_RejectsSelfMintedChallenge(t *testing.T) {
	svc := newReplayTestService(t)

	attackerChallenge := "deadbeef01234567deadbeef01234567"
	nonce := solvePoW(t, attackerChallenge, svc.config.Difficulty)

	resp := postSolution(t, svc, attackerChallenge, nonce, "192.168.1.1:12345")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("self-minted challenge accepted: status = %d, want 403", resp.StatusCode)
	}
	if cookies := resp.Cookies(); len(cookies) != 0 {
		t.Fatalf("self-minted challenge set a clearance cookie: %+v", cookies)
	}
}

// TestVerifyHandler_SolutionIsSingleUse pins replay protection: one solved
// challenge buys exactly one clearance cookie. Without it, a botnet solved a
// single pair once and replayed it from every host indefinitely.
func TestVerifyHandler_SolutionIsSingleUse(t *testing.T) {
	svc := newReplayTestService(t)
	const addr = "192.168.1.1:12345"

	challenge, nonce := issueAndSolve(t, svc, remoteAddrIP(t, addr))

	first := postSolution(t, svc, challenge, nonce, addr)
	if first.StatusCode != http.StatusSeeOther {
		t.Fatalf("first redemption status = %d, want 303", first.StatusCode)
	}
	if len(first.Cookies()) == 0 {
		t.Fatal("first redemption set no clearance cookie")
	}

	second := postSolution(t, svc, challenge, nonce, addr)
	if second.StatusCode != http.StatusForbidden {
		t.Fatalf("replayed solution status = %d, want 403", second.StatusCode)
	}
	if cookies := second.Cookies(); len(cookies) != 0 {
		t.Fatalf("replayed solution set a clearance cookie: %+v", cookies)
	}
}

// TestVerifyHandler_ChallengeIsIPBound stops a solved challenge from being
// handed to other hosts in a botnet.
func TestVerifyHandler_ChallengeIsIPBound(t *testing.T) {
	svc := newReplayTestService(t)

	challenge, nonce := issueAndSolve(t, svc, remoteAddrIP(t, "192.168.1.1:12345"))

	resp := postSolution(t, svc, challenge, nonce, "203.0.113.9:4321")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("challenge redeemed from a different IP: status = %d, want 403", resp.StatusCode)
	}
}

// TestVerifyHandler_ChallengeExpires bounds how long a solution stays useful.
func TestVerifyHandler_ChallengeExpires(t *testing.T) {
	svc := newReplayTestService(t)
	const addr = "192.168.1.1:12345"

	challenge, nonce := issueAndSolve(t, svc, remoteAddrIP(t, addr))

	restore := timeNow
	timeNow = func() time.Time { return restore().Add(challengeTTL + time.Minute) }
	t.Cleanup(func() { timeNow = restore })

	resp := postSolution(t, svc, challenge, nonce, addr)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expired challenge accepted: status = %d, want 403", resp.StatusCode)
	}
}

// TestVerifyHandler_RejectsTamperedChallenge confirms the HMAC actually covers
// the token body, not just its shape.
func TestVerifyHandler_RejectsTamperedChallenge(t *testing.T) {
	svc := newReplayTestService(t)
	const addr = "192.168.1.1:12345"

	challenge, _ := issueAndSolve(t, svc, remoteAddrIP(t, addr))

	// Flip the first hex digit of the random nonce portion, keeping the MAC.
	tampered := []byte(challenge)
	if tampered[0] == 'a' {
		tampered[0] = 'b'
	} else {
		tampered[0] = 'a'
	}
	forged := string(tampered)
	nonce := solvePoW(t, forged, svc.config.Difficulty)

	resp := postSolution(t, svc, forged, nonce, addr)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("tampered challenge accepted: status = %d, want 403", resp.StatusCode)
	}
}

// TestChallengeCookieSecureMatchesScheme pins the fix for a hard-coded
// Secure:true, which made browsers discard the clearance cookie on plain-HTTP
// deployments — leaving challenged users in an endless challenge loop.
func TestChallengeCookieSecureMatchesScheme(t *testing.T) {
	for _, tt := range []struct {
		name       string
		tls        bool
		fwdProto   string
		wantSecure bool
	}{
		{name: "plain http", wantSecure: false},
		{name: "direct tls", tls: true, wantSecure: true},
		{name: "behind https proxy", fwdProto: "https", wantSecure: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svc := newReplayTestService(t)
			const addr = "192.168.1.1:12345"
			challenge, nonce := issueAndSolve(t, svc, remoteAddrIP(t, addr))

			form := url.Values{"challenge": {challenge}, "nonce": {nonce}, "redirect": {"/"}}
			req := httptest.NewRequest(http.MethodPost, VerifyPath, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = addr
			if tt.fwdProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.fwdProto)
			}
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			}

			w := httptest.NewRecorder()
			svc.VerifyHandler().ServeHTTP(w, req)

			cookies := w.Result().Cookies()
			if len(cookies) == 0 {
				t.Fatalf("no clearance cookie set (status %d)", w.Code)
			}
			if cookies[0].Secure != tt.wantSecure {
				t.Fatalf("cookie Secure = %v, want %v", cookies[0].Secure, tt.wantSecure)
			}
		})
	}
}
