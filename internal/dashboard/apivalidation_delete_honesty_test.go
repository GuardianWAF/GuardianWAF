package dashboard

// Regression: apiValidationAdapter.RemoveSchema discarded the layer's found/not-found bool —
//
// Defect: apiValidationAdapter.RemoveSchema discards the layer's honest
// found/not-found bool (apivalidation.Layer.RemoveSchema returns bool) and
// returns unconditional nil, so DELETE of an unknown schema name is
// reported as 200 {"status":"removed"} — a fake delete. The handler's 404
// path exists (the interface returns error) but can never fire.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/layers/apivalidation"
)

func TestAPISchemaDeleteHonesty(t *testing.T) {
	// A real layer with no schemas loaded — the unknown-name case.
	layer := apivalidation.NewLayer(&apivalidation.Config{Enabled: true})
	d := &Dashboard{apiValidationOverride: &apiValidationAdapter{layer: layer}}
	h := NewAPIValidationHandler(d)

	delReq := httptest.NewRequest("DELETE", "/api/apivalidation/schemas/nope", nil)
	delRec := httptest.NewRecorder()
	h.handleSchemaDetail(delRec, delReq)

	if delRec.Code != http.StatusNotFound {
		t.Fatalf("FAIL: DELETE of unknown schema returned HTTP %d body %s — the layer's found/not-found bool was discarded and every name reports removed", delRec.Code, delRec.Body.String())
	}
}
