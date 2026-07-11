package ssrf

import (
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestCoverageGaps(t *testing.T) {
	d := NewDetector(true, 0.1)
	if d.Order() != 0 {
		t.Fatalf("Order() = %d, want 0", d.Order())
	}
	result := d.Process(&engine.RequestContext{Headers: map[string][]string{
		"User-Agent":       {"http://localhost"},
		"X-Original-URL":   {"http://localhost"},
		"X-Forwarded-Host": {"safe"},
	}})
	if result.Action != engine.ActionLog {
		t.Fatalf("low-score action = %v, want log (score %d)", result.Action, result.Score)
	}

	if ParseDecimalIP("4294967296") != nil {
		t.Fatal("decimal uint32 overflow must fail")
	}
	cases := []string{"", "0x", "0xg", "0xabcdefabcdefabcdef", "08", strings.Repeat("9", 21), "-1"}
	for _, input := range cases {
		if _, ok := parseFlexibleUint(input); ok {
			t.Errorf("parseFlexibleUint(%q) unexpectedly succeeded", input)
		}
	}
	if got, ok := parseFlexibleUint("0xA"); !ok || got != 10 {
		t.Fatalf("uppercase hex = %d, %v", got, ok)
	}
	if got, ok := parseFlexibleUint("0Xf"); !ok || got != 15 {
		t.Fatalf("lowercase hex = %d, %v", got, ok)
	}
	if ParseHexSingleIP("0xg") != nil {
		t.Fatal("invalid single hex IP must fail")
	}
	if !isHostBoundary("host", 4) || isHostBoundary("hostx", 4) {
		t.Fatal("host boundary classification failed")
	}
}
