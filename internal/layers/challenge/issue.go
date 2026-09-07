package challenge

import (
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Challenge issuance and redemption.
//
// The proof-of-work check alone proves only that *somebody* burned CPU on some
// string. It says nothing about whether this server issued that string, when,
// to whom, or whether the same solution has already been spent. Without those
// bindings the layer was trivially defeated: `VerifyHandler` took the challenge
// straight from the POST form and fed it to verifyPoW, and `generateChallenge`
// recorded nothing server-side. An attacker picked their own challenge string,
// ground one nonce offline (2^Difficulty hashes, seconds at the default 20),
// and replayed that single (challenge, nonce) pair from every host, forever,
// receiving a valid clearance cookie every time.
//
// An issued challenge is now an HMAC-signed token:
//
//	<randomHex>.<issuedAtUnix>.<hmacHex>
//
// which binds it to this server's secret, to an issue time (so it expires), and
// to the requesting client IP. Redemption additionally consumes the token, so a
// solution is worth exactly one clearance cookie.
//
// The encoding is deliberately restricted to hex digits and '.', because the
// token is interpolated into a JavaScript string literal in the challenge page.

// challengeTTL bounds how long a solver has to return a solution. It must be
// generous enough for a slow device to finish the work at the configured
// difficulty, and short enough that a stolen token is not useful for long.
const challengeTTL = 10 * time.Minute

// maxRedeemedChallenges caps the replay set so a flood of solved challenges
// cannot grow it without bound. Entries are evicted by expiry first; the cap is
// the backstop.
const maxRedeemedChallenges = 100_000

// redeemedSet tracks spent challenge tokens until they expire, making each
// solution single-use.
type redeemedSet struct {
	mu    sync.Mutex
	spent map[string]int64 // token identity -> unix expiry
}

func newRedeemedSet() *redeemedSet {
	return &redeemedSet{spent: make(map[string]int64)}
}

// redeem records the token as spent and reports whether it was still unspent.
// A false return means the token was already used and must be rejected.
func (rs *redeemedSet) redeem(id string, now, expiry int64) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if exp, ok := rs.spent[id]; ok && exp > now {
		return false
	}

	// Opportunistically drop expired entries so the common path stays bounded
	// without a background sweeper goroutine.
	if len(rs.spent) >= maxRedeemedChallenges {
		for k, exp := range rs.spent {
			if exp <= now {
				delete(rs.spent, k)
			}
		}
		// Everything is still live: refuse rather than grow without limit. A
		// legitimate client retries; an attacker gets no clearance.
		if len(rs.spent) >= maxRedeemedChallenges {
			return false
		}
	}

	rs.spent[id] = expiry
	return true
}

// issueChallenge mints a signed, time-stamped, IP-bound challenge token.
func (s *Service) issueChallenge(clientIP string) (string, error) {
	nonce, err := s.generateChallenge()
	if err != nil {
		return "", err
	}
	issuedAt := timeNow().Unix()
	body := nonce + "." + strconv.FormatInt(issuedAt, 10)
	return body + "." + s.computeHMAC(challengeBinding(body, clientIP)), nil
}

// challengeBinding is the string actually signed. The client IP is mixed in but
// not transmitted, so the token stays hex-and-dots and cannot be re-pointed at
// another address.
func challengeBinding(body, clientIP string) string {
	return "challenge|" + body + "|" + clientIP
}

// verifyChallengeToken checks that this server issued the token, that it is
// still fresh, and that it was issued to this client. It returns the token's
// identity (used for replay tracking) and its expiry.
func (s *Service) verifyChallengeToken(token, clientIP string) (id string, expiry int64, err error) {
	idx := strings.LastIndexByte(token, '.')
	if idx <= 0 || idx == len(token)-1 {
		return "", 0, fmt.Errorf("malformed challenge token")
	}
	body, mac := token[:idx], token[idx+1:]

	expectedMAC := s.computeHMAC(challengeBinding(body, clientIP))
	if !hmac.Equal([]byte(mac), []byte(expectedMAC)) {
		return "", 0, fmt.Errorf("challenge token not issued to this client")
	}

	nonce, issuedAtStr, ok := strings.Cut(body, ".")
	if !ok {
		return "", 0, fmt.Errorf("malformed challenge token body")
	}
	if _, decErr := hex.DecodeString(nonce); decErr != nil {
		return "", 0, fmt.Errorf("malformed challenge nonce")
	}
	issuedAt, parseErr := strconv.ParseInt(issuedAtStr, 10, 64)
	if parseErr != nil {
		return "", 0, fmt.Errorf("malformed challenge issue time")
	}

	now := timeNow().Unix()
	expiry = issuedAt + int64(challengeTTL.Seconds())
	if now > expiry {
		return "", 0, fmt.Errorf("challenge expired")
	}
	// Reject tokens stamped in the future beyond trivial clock jitter.
	if issuedAt > now+60 {
		return "", 0, fmt.Errorf("challenge issued in the future")
	}

	return mac, expiry, nil
}

// timeNow is a seam for tests.
var timeNow = time.Now

// ipString renders a client IP for binding purposes, matching generateToken's
// placeholder for an unknown address.
func ipString(ip net.IP) string {
	if ip == nil {
		return "0.0.0.0"
	}
	return ip.String()
}

// clientIPString resolves the request's client IP as a binding string.
func (s *Service) clientIPString(r *http.Request) string {
	if s.config.ClientIPExtractor != nil {
		return ipString(s.config.ClientIPExtractor(r))
	}
	return ipString(extractClientIP(r))
}

// isRequestHTTPS reports whether the request reached us over TLS, so the
// clearance cookie's Secure attribute matches the deployment.
func isRequestHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") ||
		strings.EqualFold(r.Header.Get("X-Forwarded-Ssl"), "on")
}
