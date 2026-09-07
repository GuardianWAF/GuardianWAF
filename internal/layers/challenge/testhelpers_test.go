package challenge

import (
	"crypto/sha256"
	"fmt"
	"net"
	"testing"
)

// issueAndSolve mints a genuine server-issued challenge for clientIP and
// returns it alongside a nonce satisfying the service's difficulty.
//
// Tests used to invent their own challenge string ("deadbeef0123…") and post it
// straight to VerifyHandler. That worked only because the handler accepted any
// string the client supplied — the very bug that let one offline-ground
// (challenge, nonce) pair be replayed forever. Going through issueChallenge
// keeps these tests exercising the real path.
func issueAndSolve(t *testing.T, svc *Service, clientIP string) (challenge, nonce string) {
	t.Helper()

	challenge, err := svc.issueChallenge(clientIP)
	if err != nil {
		t.Fatalf("issueChallenge: %v", err)
	}
	return challenge, solvePoW(t, challenge, svc.config.Difficulty)
}

// solvePoW brute-forces a nonce for the given challenge and difficulty.
func solvePoW(t *testing.T, challenge string, difficulty int) string {
	t.Helper()

	for i := range 1 << 24 {
		nonce := fmt.Sprintf("%x", i)
		hash := sha256.Sum256([]byte(challenge + nonce))
		if hasLeadingZeroBits(hash[:], difficulty) {
			return nonce
		}
	}
	t.Fatalf("no nonce found for difficulty %d", difficulty)
	return ""
}

// remoteAddrIP is the IP half of the RemoteAddr the challenge tests use, which
// is what extractClientIP derives the binding from.
func remoteAddrIP(t *testing.T, remoteAddr string) string {
	t.Helper()

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", remoteAddr, err)
	}
	return ipString(net.ParseIP(host))
}
