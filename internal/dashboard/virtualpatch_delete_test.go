package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/layers/virtualpatch"
)

// Regression: handlePatchDetail's DELETE branch returned 200 {"status":"deleted"}
// without doing anything — the adapter has no delete capability, so the patch
// remained active while the operator believed the emergency kill-switch had
// fired. The layer re-derives CVE patches on sync, so deletion would not stick
// anyway; the honest behavior is DisablePatchBy plus an accurate response.
func TestVirtualPatchDeleteDisablesHonesty(t *testing.T) {
	layer := virtualpatch.NewLayer(&virtualpatch.Config{
		Enabled:       true,
		AutoUpdate:    false,
		BlockSeverity: []string{"CRITICAL"},
	})
	adapter := &virtualPatchAdapter{layer: layer}
	d := &Dashboard{virtualPatchOverride: adapter}
	h := NewVirtualPatchHandler(d)

	// Seed a patch through the same path the UI uses.
	addReq := httptest.NewRequest("POST", "/api/virtualpatch/patches", strings.NewReader(
		`{"id":"CVE-TEST-1","name":"t","pattern":"^/x$","action":"block","severity":"HIGH"}`))
	addRec := httptest.NewRecorder()
	h.handlePatches(addRec, addReq)
	if addRec.Code != http.StatusOK {
		t.Fatalf("seed add: status %d body %s", addRec.Code, addRec.Body.String())
	}

	// DELETE the patch.
	delReq := httptest.NewRequest("DELETE", "/api/virtualpatch/patches/CVE-TEST-1", nil)
	delRec := httptest.NewRecorder()
	h.handlePatchDetail(delRec, delReq)

	// The layer re-derives CVE patches on sync, so removal would not stick;
	// the patch must still exist and be DISABLED — never still-enabled.
	p := adapter.GetPatch("CVE-TEST-1")
	if p == nil {
		t.Fatalf("FAIL: patch removed — the NVD sync would resurrect it; expected disable")
	}
	if p.Enabled {
		t.Fatalf("FAIL: DELETE reported success but patch CVE-TEST-1 remains ENABLED — the emergency kill-switch is fake")
	}
}
