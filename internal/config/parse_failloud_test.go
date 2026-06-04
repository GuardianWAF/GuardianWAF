package config

import (
	"strings"
	"testing"
)

// TestParseCustomRule_FailsLoudOnBadEnabled ensures a malformed "enabled" value
// is an error instead of silently disabling the rule (a security control would
// otherwise be turned off by a typo like `enabled: ture`).
func TestParseCustomRule_FailsLoudOnBadEnabled(t *testing.T) {
	mustNode := func(y string) *Node {
		n, err := Parse([]byte(y))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return n
	}

	if _, err := parseCustomRule(mustNode("id: r1\nenabled: ture\n")); err == nil {
		t.Fatal("expected error for malformed enabled; got nil (silent-disable regression)")
	} else if !strings.Contains(err.Error(), "enabled") {
		t.Fatalf("expected error mentioning enabled, got: %v", err)
	}

	// Explicit false must still disable, with no error.
	r, err := parseCustomRule(mustNode("id: r1\nenabled: false\n"))
	if err != nil {
		t.Fatalf("enabled: false should not error: %v", err)
	}
	if r.Enabled {
		t.Fatal("enabled: false was not applied")
	}

	// Default (no enabled field) stays enabled.
	r, err = parseCustomRule(mustNode("id: r1\n"))
	if err != nil || !r.Enabled {
		t.Fatalf("default rule should be enabled with no error; got enabled=%v err=%v", r.Enabled, err)
	}
}

// TestParseTenantDefinition_FailsLoudOnBadActive mirrors the rule test for the
// tenant "active" flag.
func TestParseTenantDefinition_FailsLoudOnBadActive(t *testing.T) {
	mustNode := func(y string) *Node {
		n, err := Parse([]byte(y))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return n
	}

	if _, err := parseTenantDefinition(mustNode("id: t1\nactive: notabool\n")); err == nil {
		t.Fatal("expected error for malformed active; got nil (silent-deactivate regression)")
	} else if !strings.Contains(err.Error(), "active") {
		t.Fatalf("expected error mentioning active, got: %v", err)
	}

	td, err := parseTenantDefinition(mustNode("id: t1\nactive: false\n"))
	if err != nil {
		t.Fatalf("active: false should not error: %v", err)
	}
	if td.Active {
		t.Fatal("active: false was not applied")
	}

	td, err = parseTenantDefinition(mustNode("id: t1\n"))
	if err != nil || !td.Active {
		t.Fatalf("default tenant should be active with no error; got active=%v err=%v", td.Active, err)
	}
}
