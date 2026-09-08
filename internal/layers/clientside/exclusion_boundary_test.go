package clientside

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: the exclusion and protected-path checks used a bare
// strings.HasPrefix, so a configured exclusion of "/static" also excluded
// "/staticfoo", "/staticual", and every other prefix sibling — silently
// disabling CSP and Magecart protection for paths that were never meant to
// be excluded. The same over-match injected the agent into sibling paths of
// ProtectedPaths entries. Matching must stop at a path segment boundary.
func TestExclusionBoundarySiblingNotExcluded(t *testing.T) {
	l := NewLayer(&Config{
		Enabled:    true,
		CSP:        CSPConfig{Enabled: true},
		Exclusions: []string{"/static"},
	})

	// The sibling of the excluded prefix must NOT be excluded: CSP metadata
	// must be registered for it.
	ctx := &engine.RequestContext{Method: "GET", Path: "/staticfoo"}
	l.Process(ctx)
	if _, ok := ctx.Metadata["csp_header_value"]; !ok {
		t.Fatalf("FAIL: sibling path /staticfoo was excluded by prefix match — CSP not applied (metadata=%v)", ctx.Metadata)
	}

	// The subtree below the excluded prefix stays excluded.
	ctx2 := &engine.RequestContext{Method: "GET", Path: "/static/app.js"}
	l.Process(ctx2)
	if _, ok := ctx2.Metadata["csp_header_value"]; ok {
		t.Fatalf("FAIL: subtree path /static/app.js was not excluded (metadata=%v)", ctx2.Metadata)
	}

	// The exact path stays excluded.
	ctx3 := &engine.RequestContext{Method: "GET", Path: "/static"}
	l.Process(ctx3)
	if _, ok := ctx3.Metadata["csp_header_value"]; ok {
		t.Fatalf("FAIL: exact excluded path /static was not excluded (metadata=%v)", ctx3.Metadata)
	}
}

func TestProtectedPathSiblingInjectionContract(t *testing.T) {
	l := NewLayer(&Config{
		Enabled: true,
		AgentInjection: AgentConfig{
			Enabled:        true,
			ProtectedPaths: []string{"/checkout"},
		},
	})

	// The protected paths intentionally use bare prefix matching: a sibling
	// like /checkoutpage is a checkout page, and missing it would be a
	// Magecart coverage hole.
	if !l.shouldInject("/checkoutpage") {
		t.Fatalf("FAIL: sibling path /checkoutpage not covered by /checkout (the documented wide-match contract)")
	}
	if !l.shouldInject("/checkout") {
		t.Fatalf("FAIL: exact protected path /checkout not matched")
	}
	if !l.shouldInject("/checkout/step/2") {
		t.Fatalf("FAIL: subtree path /checkout/step/2 not matched")
	}
}
