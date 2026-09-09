package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
)

// Regression: custom DLP patterns were invisible to the API after add — the
//
// Defect: the DLP registry stores custom patterns with Type=PatternCustom (a
// constant), and dlpAdapter.GetPatterns derives DLPPatternInfo.ID from
// string(p.Type) — so every custom pattern exposes the shared API id
// "custom". A pattern added with its own identity is never discoverable by
// the id the API returned, and distinct customs collide in listings.
func TestDLPCustomPatternIdentity(t *testing.T) {
	layer := dlp.NewLayer(&dlp.Config{
		Enabled:  true,
		Patterns: []string{"credit_card", "ssn", "iban", "email", "phone", "api_key", "private_key", "passport", "tax_id"},
	})
	adapter := &dlpAdapter{layer: layer}
	d := &Dashboard{dlpLayerOverride: adapter}
	h := NewDLPHandler(d)

	// (a) Add a custom pattern with matching id and name (the enforced
	// contract), then require it to be discoverable by that id.
	addReq := httptest.NewRequest("POST", "/api/dlp/patterns", strings.NewReader(
		`{"id":"card-detector","name":"card-detector","pattern":"\\b\\d{16}\\b","action":"mask"}`))
	addRec := httptest.NewRecorder()
	h.handleAddPattern(addRec, addReq)
	if addRec.Code != http.StatusOK {
		t.Fatalf("seed add: status %d", addRec.Code)
	}

	var found *DLPPatternInfo
	for _, p := range adapter.GetPatterns() {
		if p.ID == "card-detector" {
			found = p
			break
		}
	}
	if found == nil {
		t.Fatalf("FAIL: custom pattern added via API is not discoverable by the id the API returned — the registry stores Type=%q for all customs, collapsing every custom pattern's API identity to one shared value", dlp.PatternCustom)
	}

	// (b) An add with mismatched id and name must be rejected: the registry
	// keys custom patterns by name, so a mismatched id is a lie.
	badReq := httptest.NewRequest("POST", "/api/dlp/patterns", strings.NewReader(
		`{"id":"card-detector","name":"card-detector-v2","pattern":"\\b\\d{13,19}\\b","action":"mask"}`))
	badRec := httptest.NewRecorder()
	h.handleAddPattern(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("FAIL: mismatched id/name add accepted with HTTP %d — the registry keys custom patterns by name, so the API would report an id that can never resolve", badRec.Code)
	}
}
