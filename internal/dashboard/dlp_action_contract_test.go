package dashboard

// Regression: handleAddPattern accepted any per-pattern action value while the
//
// Defect: handleAddPattern requires an `action` field and dlpAdapter.AddPattern
// silently discards both action and severity — the DLP architecture has no
// per-pattern action concept (blocking is the layer-level BlockOnMatch flag;
// patterns always mask), so an operator's {"action":"block"} returns 200
// created while the pattern masks forever. The requested severity is also
// discarded (SeverityMedium hardcoded). The API contract lies about
// policy semantics: block-intent patterns silently weaken to mask.
//
// Honest contract after fix: action must be "mask" (400 otherwise, with the
// block_on_match guidance); severity must be one of the registry's known
// values and is translated into the stored pattern.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
)

func TestDLPActionContractHonest(t *testing.T) {
	layer := dlp.NewLayer(&dlp.Config{
		Enabled:  true,
		Patterns: []string{"credit_card", "ssn", "iban", "email", "phone", "api_key", "private_key", "passport", "tax_id"},
	})
	adapter := &dlpAdapter{layer: layer}
	d := &Dashboard{dlpLayerOverride: adapter}
	h := NewDLPHandler(d)

	// (a) A block-intent pattern must be REJECTED: the architecture cannot
	// honor per-pattern blocking, so accepting it silently weakens the
	// operator's policy to mask.
	blockReq := httptest.NewRequest("POST", "/api/dlp/patterns", strings.NewReader(
		`{"id":"leak","name":"leak","pattern":"\\b\\d{16}\\b","action":"block"}`))
	blockRec := httptest.NewRecorder()
	h.handleAddPattern(blockRec, blockReq)
	if blockRec.Code != http.StatusBadRequest {
		t.Fatalf("FAIL: action=%q accepted with HTTP %d — the architecture cannot honor per-pattern blocking (layer-level block_on_match only); the operator's block policy silently weakened to mask", "block", blockRec.Code)
	}

	// (b) Control: a mask-action pattern is still accepted.
	maskReq := httptest.NewRequest("POST", "/api/dlp/patterns", strings.NewReader(
		`{"id":"leak-mask","name":"leak-mask","pattern":"\\b\\d{16}\\b","action":"mask"}`))
	maskRec := httptest.NewRecorder()
	h.handleAddPattern(maskRec, maskReq)
	if maskRec.Code != http.StatusOK {
		t.Fatalf("FAIL: valid mask-action pattern rejected with HTTP %d", maskRec.Code)
	}
}
