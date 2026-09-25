package ato

import (
	"fmt"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (round 2026-09-25-round4-stuffing-cap-blindness): the
// emailToIPs inner set admitted new IPs only while under maxInnerEntries and
// had NO eviction — every outer map evicts oldest-at-cap, this one dropped
// the newcomer. Under the windowed counting introduced by the round-1
// credential-stuffing window fix (2026-09-25-credstuffing-window), one
// attack wave of >= cap distinct IPs saturated the set with entries that
// later aged out of the window; every fresh attacker IP was then rejected at
// the cap, the in-window count stayed 0, and stuffing detection stayed
// permanently blinded for that email while ongoing attempts (<24h) kept it
// warm against Cleanup eviction. The set is now a bounded cache: at capacity
// a fresh IP evicts the least-recently-seen member (the same policy as the
// outer maps), preserving the boundedness contract.

// The defect case: saturation wave (outside window) + ongoing distributed
// attack (inside window) must still trip the threshold.
func TestStuffingCapSaturationDoesNotBlindDetection(t *testing.T) {
	layer := newStuffingLayer(time.Hour, 3)
	stale := time.Now().Add(-2 * time.Hour)
	fresh := time.Now()

	// Wave 1: 1000 distinct IPs — saturates the inner set (cap 1000),
	// all outside the 1h detection window.
	for i := 0; i < 1000; i++ {
		recordStuffingUse(layer, fmt.Sprintf("10.%d.%d.%d", (i>>16)%256, (i>>8)%256, i%256), "victim@corp.test", stale)
	}
	// Wave 2: 5 fresh attacker IPs inside the window — an ongoing
	// distributed attack on the same email.
	for i := 0; i < 5; i++ {
		recordStuffingUse(layer, fmt.Sprintf("10.99.%d.%d", i/256, i%256), "victim@corp.test", fresh)
	}

	if got := layer.tracker.GetUniqueIPsForEmail("victim@corp.test", time.Hour); got < 3 {
		t.Fatalf("windowed unique-IP count = %d, want >= 3 — saturated inner set dropped every fresh attacker IP", got)
	}
	req := httptest.NewRequest("POST", "http://app.legit.test/login", nil)
	ctx := &engine.RequestContext{
		Request:    req,
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("10.98.0.1"),
		BodyString: `{"email":"victim@corp.test"}`,
		Headers:    map[string][]string{},
	}
	if res := layer.checkCredentialStuffing(ctx, "victim@corp.test"); res.Action != engine.ActionBlock {
		t.Fatalf("ongoing distributed attack (5 fresh IPs in window, threshold 3) not blocked — detection blinded by cap saturation")
	}
}

// Eviction targets the least-recently-seen member, not an arbitrary one.
func TestStuffingCapEvictionTargetsOldest(t *testing.T) {
	layer := newStuffingLayer(time.Hour, 3)
	base := time.Now().Add(-2 * time.Hour)
	// 1000 stale IPs with strictly increasing timestamps: the least-recently
	// seen member is uniquely the first (10.0.0.0).
	for i := 0; i < 1000; i++ {
		recordStuffingUse(layer, fmt.Sprintf("10.%d.%d.%d", (i>>16)%256, (i>>8)%256, i%256), "victim@evict.test", base.Add(time.Duration(i)*time.Millisecond))
	}
	recordStuffingUse(layer, "10.99.0.0", "victim@evict.test", time.Now())

	if _, present := layer.tracker.emailToIPs["victim@evict.test"]["10.0.0.0"]; present {
		t.Fatalf("least-recently-seen IP 10.0.0.0 must have been evicted")
	}
	if _, present := layer.tracker.emailToIPs["victim@evict.test"]["10.99.0.0"]; !present {
		t.Fatalf("fresh IP must be admitted at cap")
	}
	if got := len(layer.tracker.emailToIPs["victim@evict.test"]); got != layer.tracker.maxInnerEntries {
		t.Fatalf("inner set size = %d, want == %d (boundedness preserved)", got, layer.tracker.maxInnerEntries)
	}
}

// Control: without prior saturation the same in-window spread blocks.
func TestStuffingCapUnsaturatedStillBlocks(t *testing.T) {
	layer := newStuffingLayer(time.Hour, 3)
	fresh := time.Now()
	for i := 0; i < 3; i++ {
		recordStuffingUse(layer, fmt.Sprintf("10.90.%d.%d", i/256, i%256), "plain@corp.test", fresh)
	}
	req := httptest.NewRequest("POST", "http://app.legit.test/login", nil)
	ctx := &engine.RequestContext{
		Request:    req,
		Path:       "/login",
		Method:     "POST",
		ClientIP:   net.ParseIP("10.91.0.1"),
		BodyString: `{"email":"plain@corp.test"}`,
		Headers:    map[string][]string{},
	}
	if res := layer.checkCredentialStuffing(ctx, "plain@corp.test"); res.Action != engine.ActionBlock {
		t.Fatalf("unsaturated in-window spread at threshold did not block")
	}
}

// Control: the inner set never grows past maxInnerEntries even while
// admitting fresh IPs at cap — the boundedness contract is preserved.
func TestStuffingCapInnerSetStaysBounded(t *testing.T) {
	layer := newStuffingLayer(time.Hour, 3)
	stale := time.Now().Add(-2 * time.Hour)
	fresh := time.Now()
	for i := 0; i < 1000; i++ {
		recordStuffingUse(layer, fmt.Sprintf("10.%d.%d.%d", (i>>16)%256, (i>>8)%256, i%256), "victim@cap.test", stale)
	}
	for i := 0; i < 5; i++ {
		recordStuffingUse(layer, fmt.Sprintf("10.99.%d.%d", i/256, i%256), "victim@cap.test", fresh)
	}
	if got := len(layer.tracker.emailToIPs["victim@cap.test"]); got > layer.tracker.maxInnerEntries {
		t.Fatalf("inner set size = %d, want <= %d", got, layer.tracker.maxInnerEntries)
	}
}
