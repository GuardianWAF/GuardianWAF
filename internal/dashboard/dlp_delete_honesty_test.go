package dashboard

// Regression: the DLP pattern DELETE reported "removed" while RemovePattern
//
// Defect: handlePatternDetail's DELETE branch calls RemovePattern, whose
// adapter implementation is a universal no-op (`return nil` — "DLP layer
// doesn't support removing built-in patterns"), yet the handler returns
// 200 {"status":"removed"}. The registry has no removal API at all, so
// nothing is ever removed: the operator's kill-switch lies while the
// pattern keeps scanning. The supported capability is SetEnabled.

import (
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
)

func TestDLPDeleteDisablesHonesty(t *testing.T) {
	layer := dlp.NewLayer(&dlp.Config{Enabled: true, Patterns: []string{"credit_card", "ssn", "iban", "email", "phone"}})
	adapter := &dlpAdapter{layer: layer}
	d := &Dashboard{dlpLayerOverride: adapter}
	h := NewDLPHandler(d)

	// Discover a real (built-in) pattern id from the registry. Custom
	// patterns are not returned by GetPatterns (a separate finding), so we
	// exercise the built-in path to isolate the fake-delete defect.
	// The adapter's enabled-view is broken (a separate finding — Enabled is
	// never populated in DLPPatternInfo); discover the target from the
	// registry directly.
	var target string
	for _, rp := range layer.GetRegistry().GetAllPatterns() {
		if rp.Enabled {
			target = string(rp.Type)
			break
		}
	}
	if target == "" {
		t.Fatal("no enabled pattern in the registry")
	}

	// DELETE it through the handler.
	delReq := httptest.NewRequest("DELETE", "/api/dlp/patterns/"+target, nil)
	delRec := httptest.NewRecorder()
	h.handlePatternDetail(delRec, delReq)

	// The registry has no removal API, so the pattern must still exist —
	// and before the fix it must still be ENABLED (the fake kill-switch).
	// The adapter's enabled-view is broken (a separate finding — Enabled is
	// never populated in DLPPatternInfo); assert against the registry directly.
	reg := layer.GetRegistry().GetPattern(dlp.PatternType(target))
	if reg == nil {
		t.Fatalf("FAIL: pattern %q removed — the registry has no removal API; expected honest disable", target)
	}
	if reg.Enabled {
		t.Fatalf("FAIL: DELETE reported removed (HTTP %d) but pattern %q remains ENABLED in the registry — the kill-switch is fake", delRec.Code, target)
	}
}
