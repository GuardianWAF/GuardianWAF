package crs

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// @eq is SecLang's NUMERICAL equality operator — the ModSecurity operators
// reference defines it as "a numerical comparison ... 'equal to'"; string
// equality is @streq. The previous implementation used value == argument, so
// rules like `SecRule ARGS "@eq 1"` never fired on numerically-equal
// spellings ("01", "1.0"). These pins drive the real chain
// (rules file -> NewLayer -> Process).
func TestEqOperatorSecLangContract(t *testing.T) {
	layer := newSecLangRuleLayer(t,
		`SecRule ARGS "@eq 1" "id:9204001,phase:2,deny,severity:CRITICAL,msg:'argument numerically equals 1'"`)

	cases := []struct {
		name      string
		target    string
		wantBlock bool
	}{
		{"exact spelling", "/?count=1", true},
		{"leading zero", "/?count=01", true},
		{"float form", "/?count=1.0", true},
		{"different number", "/?count=2", false},
		{"non-numeric value", "/?count=abc", false},
	}
	for _, tc := range cases {
		res := runCRSRequest(t, layer, tc.target)
		if tc.wantBlock && (res.Action != engine.ActionBlock || len(res.Findings) == 0) {
			t.Errorf("%s: @eq 1 must fire on %s (block + finding), got action=%s findings=%d", tc.name, tc.target, res.Action, len(res.Findings))
			continue
		}
		if !tc.wantBlock && (res.Action != engine.ActionPass || len(res.Findings) != 0) {
			t.Errorf("%s: @eq 1 must not fire on %s, got action=%s findings=%d", tc.name, tc.target, res.Action, len(res.Findings))
		}
	}
}
