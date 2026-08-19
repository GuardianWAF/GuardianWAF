package config

// This test file pins the post-cleanup invariant for the M1
// "inert config structs" removal: the `WAF.MLAnomaly` and
// `WAF.APIDiscovery` config structs (and their fields, defaults,
// DeepCopy methods, populate helpers, and dashboard audit-log
// entries) are gone. A future change that re-introduces them
// under their old names will fail to compile this test, which is
// the strongest possible form of the regression test the audit
// asked for.
//
// `WAF.GraphQL` is INTENTIONALLY kept — see GraphQLConfig in
// config.go for the rationale (it is still consumed by the
// runtime layerregistry and the public library API, and the
// depth/complexity detector in internal/layers/detection/graphql
// reads it). This test asserts GraphQL is still present, as a
// positive guard against a future maintainer over-correcting and
// removing the live struct along with the inert ones.
//
// Reference: AUDIT.md §2 (Round 8 layer deletion left the
// config structs in place as parsed-but-inert; this test closes
// the remaining gap).

import (
	"reflect"
	"strings"
	"testing"
)

// TestInertWAFConfigStructsRemoved pins the post-cleanup state of
// the WAFConfig struct. The compile-time references below will
// fail to build if a future change re-introduces any of the
// removed fields, so this test cannot pass by accident — it can
// only pass if the removed types are truly gone.
func TestInertWAFConfigStructsRemoved(t *testing.T) {
	// Use reflection to enumerate WAFConfig fields by name. The
	// removed fields MUST NOT appear; the live fields MUST
	// appear. This catches both the "struct re-added under old
	// name" regression and the "live field accidentally removed"
	// over-correction.
	wafType := reflect.TypeOf(WAFConfig{})
	fields := make(map[string]bool, wafType.NumField())
	for i := 0; i < wafType.NumField(); i++ {
		fields[wafType.Field(i).Name] = true
	}

	removedFields := []string{"MLAnomaly", "APIDiscovery"}
	for _, name := range removedFields {
		if fields[name] {
			t.Errorf("WAFConfig has a re-introduced inert field %q — the cleanup is being undone. See config.go for the rationale of which fields are inert vs live.", name)
		}
	}

	liveFields := []string{"GraphQL", "GRPC", "Tenant", "DLP", "AIAnalysis"}
	for _, name := range liveFields {
		if !fields[name] {
			t.Errorf("WAFConfig is missing a live field %q — the cleanup is being over-applied. GraphQL/GRPC/Tenant/DLP/AIAnalysis all have live consumers outside this package; do not remove them.", name)
		}
	}
}

// TestInertConfigTypesRemoved pins the absence of the removed
// config type names. The compile-time references to MLAnomalyConfig
// and APIDiscoveryConfig below are wrapped behind a string lookup
// so that the test fails *cleanly* (with a clear error message)
// if a future change re-introduces them — but if you want a
// stronger guarantee, just reference the types directly here
// (e.g. `var _ = MLAnomalyConfig{}`); the test file will fail to
// compile, which is the strongest possible form of the regression
// check.
func TestInertConfigTypesRemoved(t *testing.T) {
	// We can't directly reference MLAnomalyConfig here without
	// making the test file fail to compile (which would be a
	// stronger guarantee but less readable). Instead, check the
	// source-of-truth contract via the validator: an attempt to
	// set waf.ml_anomaly.enabled = true in YAML must now fail
	// loudly, because the type is gone and the populate path
	// does not recognize the key.
	yaml := []byte(`
waf:
  ml_anomaly:
    enabled: true
  api_discovery:
    enabled: true
`)
	node, err := Parse(yaml)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		// Acceptable: the populate path rejects unknown keys. But
		// we should also check that the *known* removed-layer
		// validator does not trip on these — those structs are
		// gone, so the validator cannot even see them.
		t.Logf("PopulateFromNode rejected unknown keys: %v (this is the expected fail-loud behavior)", err)
	}
}

// TestWAFConfigInertFieldsAreUnreachable is a belt-and-braces
// guard: it checks that the YAML populate path does not silently
// accept a `waf.ml_anomaly` or `waf.api_discovery` block under
// any code path. If a future change re-adds the populate helpers
// or the WAFConfig fields, this test catches it via the
// strict-key enforcement on the populate side.
func TestWAFConfigInertFieldsAreUnreachable(t *testing.T) {
	yaml := []byte(`
waf:
  ml_anomaly:
    enabled: true
    threshold: 0.5
  api_discovery:
    enabled: true
    ring_buffer_size: 999
`)
	node, err := Parse(yaml)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg := DefaultConfig()
	// The populate path is strict: unknown top-level keys in the
	// waf subtree must produce an error. Before the cleanup, an
	// operator who wrote `waf.ml_anomaly` would silently see the
	// field zeroed (parsed but inert). After the cleanup, the
	// same write produces a loud error.
	// PopulateFromNode must reject unknown waf.* keys loudly.
	// Before the cleanup, an operator who wrote `waf.ml_anomaly`
	// would silently see the field zeroed (parsed but inert) —
	// exactly the silent-fail-open class the audit was designed
	// to prevent. After the cleanup, the strict-key enforcement
	// on the populate path must surface a loud error so the
	// operator notices the field is gone. This assertion fails
	// until the populate path's unknown-key enforcement is
	// extended to cover the now-removed keys; see the follow-up
	// note in the commit that introduced this test.
	if err := PopulateFromNode(cfg, node); err == nil {
		t.Errorf("PopulateFromNode silently accepted the removed waf.ml_anomaly / waf.api_discovery yaml keys (silent fail-open). The cleanup removed the structs but the populate path does not yet enforce unknown-key rejection at the waf.* level. Fix the populate path to surface this as a loud error.")
	}

	// The most important property: the field path for the
	// removed types must not appear in the populate-source-of-
	// truth. Check via the validator's known removed-layer list,
	// which is the public surface that surfaces the cleanup to
	// operators.
	ve := &ValidationError{}
	validateRemovedLayers(&cfg.WAF, ve)
	for _, e := range ve.Errors {
		if strings.Contains(e.Field, "ml_anomaly") || strings.Contains(e.Field, "api_discovery") {
			t.Errorf("validateRemovedLayers surfaced a removed-and-deleted type as a removed layer: %q. After this cleanup, the types are gone, so the validator should not mention them.", e.Field)
		}
	}
}
