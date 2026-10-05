package config

import (
	"reflect"
	"testing"
)

func TestDeepCopyConditionListOwnership(t *testing.T) {
	for _, value := range []any{[]string{"original"}, []any{"original"}} {
		in := &RuleCondition{Field: "method", Op: "in", Value: value}
		out := in.DeepCopy()
		root := (&Config{WAF: WAFConfig{CustomRules: CustomRulesConfig{Rules: []CustomRule{{Conditions: []RuleCondition{*in}}}}}}).DeepCopy()
		gate, done := make(chan struct{}), make(chan struct{})
		go func() {
			<-gate
			switch v := value.(type) {
			case []string:
				v[0] = "changed"
			case []any:
				v[0] = "changed"
			}
			close(done)
		}()
		close(gate)
		<-done
		for _, cp := range []*RuleCondition{out, &root.WAF.CustomRules.Rules[0].Conditions[0]} {
			switch v := cp.Value.(type) {
			case []string:
				if v[0] != "original" {
					t.Fatal("shared string list")
				}
				v[0] = "copy-only"
			case []any:
				if v[0] != "original" {
					t.Fatal("shared any list")
				}
				v[0] = "copy-only"
			}
		}
		switch v := value.(type) {
		case []string:
			if v[0] != "changed" {
				t.Fatal("reverse alias")
			}
		case []any:
			if v[0] != "changed" {
				t.Fatal("reverse alias")
			}
		}
	}
	for _, value := range []any{nil, "scalar", 12, []string(nil), []any(nil), []string{}, []any{}} {
		in := &RuleCondition{Value: value}
		if !reflect.DeepEqual(in, in.DeepCopy()) {
			t.Fatal("scalar/nil/empty value changed")
		}
	}
	if (*RuleCondition)(nil).DeepCopy() != nil {
		t.Fatal("nil receiver")
	}
}
