package acme

import (
	"net/http"
	"testing"
)

// Regression (the catalog-closure weak note): allow() swept non-recent
// entries only once the map passed 1000 — but a wide IP rotation keeps
// every entry "recent" (each fresh IP adds a fresh timestamp), so the sweep
// deleted nothing and the map grew with the attacker's IP budget while
// every request paid the O(n) sweep. A hard cap now evicts arbitrary
// entries once over the limit: losing some rate-limit tracking under a
// distributed flood is the correct degradation for a challenge endpoint.
func TestRateMapBoundedUnderIPRotation(t *testing.T) {
	h := NewHTTP01Handler()

	for i := 0; i < 5000; i++ {
		// Vary the HOST — allow() keys its window on SplitHostPort's host part.
		r := &http.Request{RemoteAddr: "10.1." + itoa(i/256) + "." + itoa(i%256) + ":80"}
		h.allow(r)
	}

	h.rlMu.Lock()
	got := len(h.rlReqs)
	h.rlMu.Unlock()

	// 4096 must stay in sync with the production acmeRateMaxIPs cap.
	if got > 4096 {
		t.Fatalf("FAIL: rate map holds %d entries under IP rotation, want <= 4096 — growth is attacker-budgeted and every allow() pays the O(n) sweep", got)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
