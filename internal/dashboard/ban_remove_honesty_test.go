package dashboard

// Regression: handleRemoveBan blessed every unban with 200 "ok" —
//
// Defect (ledgered round 84, source-verified): handleRemoveBan answers 200
// "ok" for any IP — the ban layer's RemoveAutoBan is void, so no
// found/not-found signal exists and an unknown IP's unban reports success
// (the fake-delete class: rounds 63/68/78).

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/ipacl"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

func TestRemoveBanHonesty(t *testing.T) {
	proxy.SetPrivateTargetsAllowed(true)
	eng := newTestEngine(t)

	// Register a live ipacl layer — the test engine ships without one, and
	// the fixture must exercise the defect-arm (the real handler path), not
	// the layer-inactive arm. OrderedLayer is a struct pair
	// {Layer, Order} (engine/layer.go:112), so registration is a literal.
	aclLayer, err := ipacl.NewLayer(&ipacl.Config{Enabled: true})
	if err != nil {
		t.Fatalf("ipacl layer: %v", err)
	}
	eng.AddLayer(engine.OrderedLayer{Layer: aclLayer, Order: engine.OrderIPACL})

	d := New(eng, events.NewMemoryStore(100), "test-key")

	req := authenticatedRequest("DELETE", "/api/v1/bans", `{"ip":"203.0.113.99"}`, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	// No ban was ever created for this IP; the unban must be an honest 404,
	// not a manufactured "ok".
	if w.Code != http.StatusNotFound {
		t.Fatalf("FAIL: unban of a never-banned IP returned HTTP %d body %s — RemoveAutoBan is void and the handler blesses every name as removed", w.Code, w.Body.String())
	}
}
