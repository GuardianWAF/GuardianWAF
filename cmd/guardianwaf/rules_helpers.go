package main

import "github.com/guardianwaf/guardianwaf/internal/layers/rules"

// mapToRule converts a JSON map to a rules.Rule.
func mapToRule(raw map[string]any) rules.Rule {
	r := rules.Rule{}
	if v, ok := raw["id"].(string); ok {
		r.ID = v
	}
	if v, ok := raw["name"].(string); ok {
		r.Name = v
	}
	if v, ok := raw["enabled"].(bool); ok {
		r.Enabled = v
	}
	if v, ok := raw["priority"].(float64); ok {
		r.Priority = int(v)
	}
	if v, ok := raw["action"].(string); ok {
		r.Action = v
	}
	if v, ok := raw["score"].(float64); ok {
		r.Score = int(v)
	}
	if conds, ok := raw["conditions"].([]any); ok {
		for _, c := range conds {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			cond := rules.Condition{}
			if v, ok := cm["field"].(string); ok {
				cond.Field = v
			}
			if v, ok := cm["op"].(string); ok {
				cond.Op = v
			}
			cond.Value = cm["value"]
			r.Conditions = append(r.Conditions, cond)
		}
	}
	return r
}
