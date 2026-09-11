package dlp

import (
	"strings"
	"testing"
)

// Regression (round 5/25): maskContent substituted matches in reverse slice
// order assuming a position-sorted input, but PatternRegistry.Scan groups
// matches by pattern type in map iteration order — the slice is NOT sorted.
// With a length-changing mask at a lower offset substituted first, later
// offsets went stale and the stale bounds check silently DROPPED the higher
// match: an unmasked credit card survived in a mask_response-protected body.
// Nondeterministic pre-fix (registry map order randomized per call); the
// masking contract must hold on every call.
func TestMaskContent_MultiTypeMatchesAllMasked(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanResponse: true,
		MaskResponse: true,
		MaxBodySize:  1024 * 1024,
		Patterns:     []string{"credit_card", "api_key"},
	})

	// The api-key match (offset 0, 25 chars) masks down to 12 chars: when it
	// was substituted before the later credit-card match, the card's offset
	// shifted by -13 and the stale bounds check dropped its mask entirely.
	content := []byte("apikey=ABCDEFGHIJKLMNOPAK cc=4111111111111111")
	for i := 0; i < 500; i++ {
		result, masked := layer.ScanResponse(content, "application/json")
		if len(result.Matches) != 2 {
			t.Fatalf("FAIL: iteration %d: %d matches, want 2", i, len(result.Matches))
		}
		s := string(masked)
		if strings.Contains(s, "4111111111111111") {
			t.Fatalf("FAIL: iteration %d: unmasked credit card in masked response: %q", i, s)
		}
		if strings.Contains(s, "apikey=ABCDEFGHIJKLMNOPAK") {
			t.Fatalf("FAIL: iteration %d: unmasked api key in masked response: %q", i, s)
		}
		if !strings.Contains(s, "****-****-****-1111") || !strings.Contains(s, "apik****OPAK") {
			t.Fatalf("FAIL: iteration %d: masks missing from output: %q", i, s)
		}
	}
}
