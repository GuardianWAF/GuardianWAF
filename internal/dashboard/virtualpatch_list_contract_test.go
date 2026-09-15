package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/layers/virtualpatch"
)

// TestVirtualPatchListContract_DisabledPatchesVisible pins the list half of
// the operator kill-switch loop (disable → see → re-enable). handleListPatches
// used to call GetActivePatches (enabled-only), which made its own
// activeOnly filter dead code: after DELETE-style disabling, the patch
// vanished from the list — invisible, unverifiable, and its ID could not be
// rediscovered to re-enable it. The list must draw from GetAllPatches so
// disabled patches stay visible without the filter, and active_only=true
// must still exclude them.
func TestVirtualPatchListContract_DisabledPatchesVisible(t *testing.T) {
	layer := virtualpatch.NewLayer(&virtualpatch.Config{Enabled: true})
	d := &Dashboard{mux: http.NewServeMux(), virtualPatchLayer: layer}
	h := NewVirtualPatchHandler(d)

	add := func(id string) {
		body := `{"id":"` + id + `","name":"` + id + `","pattern":"^/x$","pattern_type":"regex","target":"path","action":"block","severity":"HIGH","score":80}`
		req := httptest.NewRequest(http.MethodPost, "/api/virtualpatch/patches", strings.NewReader(body))
		w := httptest.NewRecorder()
		h.handlePatches(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("setup: add %s failed: %d %s", id, w.Code, w.Body.String())
		}
	}
	add("list-enabled")
	add("list-disabled")
	if !layer.DisablePatchBy("list-disabled", "test") {
		t.Fatalf("setup: DisablePatchBy reported patch not found")
	}

	list := func(query string) (ids map[string]bool, total int) {
		req := httptest.NewRequest(http.MethodGet, "/api/virtualpatch/patches"+query, nil)
		w := httptest.NewRecorder()
		h.handleListPatches(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("list failed: %d %s", w.Code, w.Body.String())
		}
		var resp struct {
			Patches []struct {
				ID      string `json:"id"`
				Enabled bool   `json:"enabled"`
			} `json:"patches"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		ids = make(map[string]bool, len(resp.Patches))
		for _, p := range resp.Patches {
			ids[p.ID] = p.Enabled
		}
		return ids, resp.Total
	}

	// Unfiltered: both patches visible; the disabled one reported as disabled.
	ids, total := list("")
	enabledVal, enabledOK := ids["list-enabled"]
	disabledVal, disabledOK := ids["list-disabled"]
	if !enabledOK || !disabledOK {
		t.Fatalf("unfiltered list must contain enabled AND kill-switched patches, got %v (total %d)", ids, total)
	}
	if !enabledVal {
		t.Fatalf("enabled patch listed as disabled: %v", ids)
	}
	if disabledVal {
		t.Fatalf("kill-switched patch listed as enabled: %v", ids)
	}

	// active_only=true: the kill-switched patch is excluded; the enabled one stays.
	ids, total = list("?active_only=true")
	if _, ok := ids["list-disabled"]; ok {
		t.Fatalf("active_only=true must exclude the kill-switched patch, got %v (total %d)", ids, total)
	}
	if _, ok := ids["list-enabled"]; !ok {
		t.Fatalf("active_only=true must contain the enabled patch, got %v (total %d)", ids, total)
	}
}
