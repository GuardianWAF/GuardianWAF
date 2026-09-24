package virtualpatch

// Regression (round 2026-09-24-r17-query-encoding-evasion): getValueByType's
// "query" scope matched ONLY ctx.Request.URL.RawQuery — the raw,
// still-percent-encoded query string. The attacker selects the encoding of
// the same payload: "class.module" rides as "class%2Emodule", so the
// shipped Spring4Shell query-scoped contains-patch (and every other
// query-scoped patch) never fired on the encoded form. Post-fix the "query"
// scope also returns the engine's decoded representation (ctx.QueryParams
// keys and values, populated by AcquireContext with url.QueryUnescape plus
// dropped-param recovery); the any-match loop in matchPattern inspects
// every returned value (the round-20 multi-value family, extended to
// representations).

import (
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestQueryScopedPatchesSeeEncodedPayloads(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, BlockSeverity: []string{"CRITICAL"}})

	// Control: the unencoded Spring4Shell payload blocks — proves the
	// harness reaches the shipped query-scoped patch through the real
	// AcquireContext population path.
	plain := httptest.NewRequest("GET", "http://target/?class.module.classLoader=org.springframework.context.support.ClassPathXmlApplicationContext", nil)
	if res := layer.Process(engine.AcquireContext(plain, 1, 1<<20)); res.Action != engine.ActionBlock {
		t.Fatalf("control: unencoded Spring4Shell query payload did not block: action=%v", res.Action)
	}

	// The fixed defect: the SAME payload with the key's dot percent-encoded.
	encoded := httptest.NewRequest("GET", "http://target/?class%2Emodule.classLoader=org.springframework.context.support.ClassPathXmlApplicationContext", nil)
	if res := layer.Process(engine.AcquireContext(encoded, 1, 1<<20)); res.Action != engine.ActionBlock {
		t.Fatalf("percent-encoded Spring4Shell query payload evaded the query-scoped patch: action=%v", res.Action)
	}
}
