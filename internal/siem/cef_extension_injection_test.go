package siem

// Regression tests for round 23/25: escapeCEF must escape '=' as '\=' — CEF
// extension fields are space-delimited key=value pairs, and an unescaped '='
// inside an attacker-controlled value (query/path/user-agent) injects forged
// extension fields into the SIEM line (log forging; the CEF sibling of the
// round-2-old formatJSON escaping fix).

import (
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestCEFExtensionEqualsInjection(t *testing.T) {
	ev := engine.Event{
		Action:   engine.ActionBlock,
		ClientIP: "10.0.0.9:1234",
		Method:   "GET",
		Path:     "/search",
		Query:    "q=x act=forged score=0",
	}

	line := EncodeCEF(ev, "GuardianWAF", "0.5.0")

	// The honest contract: attacker-controlled values cannot inject forged
	// extension fields — every '=' in a value must reach the wire escaped.
	if strings.Contains(line, " act=forged") {
		t.Fatalf("FAIL cef-extension-injection: the attacker-controlled query leaked an unescaped '=' into the CEF extension (a spec-compliant SIEM parses forged fields): %s", line)
	}
	if strings.Contains(strings.SplitN(line, "cn1=", 2)[1], " score=0") {
		t.Fatalf("FAIL cef-extension-injection: forged score field leaked: %s", line)
	}
}

func TestCEFEscapeNoEqualsRaw(t *testing.T) {
	if got := escapeCEF("a=b"); got != `a\=b` {
		t.Fatalf("escapeCEF(%q) = %q, want %q", "a=b", got, `a\=b`)
	}
}
