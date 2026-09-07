package tenant

import (
	"testing"
)

// Regression: Manager.UpdateTenantRule built rules.Rule{ID: ruleID} and filled
// only the fields present in the update map, then handed the partial rule to
// rules.Layer.UpdateRule — which REPLACES the stored rule wholesale. A
// dashboard partial update like {"id": X, "score": 90} therefore silently
// disabled the rule (Enabled zero-values to false), wiped its conditions and
// action, and left it matching nothing, while reporting success.
//
// Contract: partial-update semantics — fields absent from the update map keep
// their current values.
func TestUpdateTenantRulePartialUpdatePreservesAbsentFields(t *testing.T) {
	m := NewManager(10)

	quota := DefaultQuota()
	ten, err := m.CreateTenant("rule-partial-proof", "proof", []string{"rule-partial-proof.test"}, &quota)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	add := map[string]any{
		"name":   "block-admin-probe",
		"action": "block",
		"score":  float64(80),
		"conditions": []any{
			map[string]any{"field": "path", "op": "contains", "value": "/admin"},
		},
	}
	if err := m.AddTenantRule(ten.ID, add); err != nil {
		t.Fatalf("AddTenantRule: %v", err)
	}

	added := m.rulesManager.GetTenantRules(ten.ID)
	if len(added) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(added))
	}
	// Control: the add path produced a complete, enabled rule.
	if !added[0].Enabled || added[0].Score != 80 || added[0].Action != "block" || len(added[0].Conditions) != 1 {
		t.Fatalf("add path produced incomplete rule: %+v", added[0])
	}

	// Partial update: change ONLY the score.
	if err := m.UpdateTenantRule(ten.ID, map[string]any{"id": added[0].ID, "score": float64(90)}); err != nil {
		t.Fatalf("UpdateTenantRule: %v", err)
	}

	updated := m.rulesManager.GetTenantRules(ten.ID)
	if len(updated) != 1 {
		t.Fatalf("expected 1 rule after update, got %d", len(updated))
	}
	if updated[0].Score != 90 {
		t.Fatalf("score not applied (got %d)", updated[0].Score)
	}
	if !updated[0].Enabled {
		t.Fatalf("partial update disabled the rule (Enabled wiped to false)")
	}
	if updated[0].Action != "block" {
		t.Fatalf("partial update wiped Action (got %q)", updated[0].Action)
	}
	if len(updated[0].Conditions) != 1 {
		t.Fatalf("partial update wiped Conditions (got %d)", len(updated[0].Conditions))
	}
}

// Boundary: updating a nonexistent rule still reports "rule not found".
func TestUpdateTenantRuleUnknownRuleFails(t *testing.T) {
	m := NewManager(10)

	quota := DefaultQuota()
	ten, err := m.CreateTenant("rule-unknown-proof", "proof", []string{"rule-unknown-proof.test"}, &quota)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	err = m.UpdateTenantRule(ten.ID, map[string]any{"id": "no-such-rule", "score": float64(90)})
	if err == nil {
		t.Fatalf("expected error for unknown rule, got nil")
	}
}

// Boundary: a full update (every field present) still applies all fields.
func TestUpdateTenantRuleFullUpdateAppliesAllFields(t *testing.T) {
	m := NewManager(10)

	quota := DefaultQuota()
	ten, err := m.CreateTenant("rule-full-proof", "proof", []string{"rule-full-proof.test"}, &quota)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	add := map[string]any{
		"name":   "original-name",
		"action": "block",
		"score":  float64(50),
		"conditions": []any{
			map[string]any{"field": "path", "op": "contains", "value": "/old"},
		},
	}
	if err := m.AddTenantRule(ten.ID, add); err != nil {
		t.Fatalf("AddTenantRule: %v", err)
	}
	orig := m.rulesManager.GetTenantRules(ten.ID)[0]

	full := map[string]any{
		"id":      orig.ID,
		"name":    "renamed-rule",
		"enabled": true,
		"action":  "log",
		"score":   float64(25),
		"conditions": []any{
			map[string]any{"field": "method", "op": "equals", "value": "POST"},
		},
	}
	if err := m.UpdateTenantRule(ten.ID, full); err != nil {
		t.Fatalf("UpdateTenantRule: %v", err)
	}

	updated := m.rulesManager.GetTenantRules(ten.ID)[0]
	if updated.Name != "renamed-rule" || !updated.Enabled || updated.Action != "log" || updated.Score != 25 || len(updated.Conditions) != 1 || updated.Conditions[0].Value != "POST" {
		t.Fatalf("full update did not apply all fields: %+v", updated)
	}
}
