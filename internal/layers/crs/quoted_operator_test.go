package crs

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests: parseOperator must unquote the operator section BEFORE
// the negation/@ detection. splitQuoted keeps each quoted section's
// surrounding quotes, so the operator section of every standard SecRule line
// (SecRule VAR "@op arg" "actions") arrives as "\"@op arg\"". parseOperator
// used to check strings.HasPrefix(s, "@") BEFORE stripping quotes, so the @
// branch never fired: every rule loaded from CRS files kept the default @rx
// operator with the raw operator text as its argument, and the whole
// file-loaded CRS layer never matched anything.

func TestParseOperatorStripsQuotedSection(t *testing.T) {
	p := NewParser()

	cases := []struct {
		in          string
		wantType    string
		wantArg     string
		wantNegated bool
	}{
		{`"@streq TRACE"`, "@streq", "TRACE", false},
		{`"@contains sqlmap"`, "@contains", "sqlmap", false},
		{`"@rx ^GET$"`, "@rx", "^GET$", false},
		{`"!@streq TRACE"`, "@streq", "TRACE", true},
		{`@streq TRACE`, "@streq", "TRACE", false},         // unquoted still works
		{`!@streq TRACE`, "@streq", "TRACE", true},         // unquoted negation
		{`"@contains a b c"`, "@contains", "a b c", false}, // spaces preserved
	}

	for _, tc := range cases {
		op, err := p.parseOperator(tc.in)
		if err != nil {
			t.Fatalf("parseOperator(%q): %v", tc.in, err)
		}
		if op.Type != tc.wantType {
			t.Errorf("parseOperator(%q) type = %q, want %q", tc.in, op.Type, tc.wantType)
		}
		if op.Argument != tc.wantArg {
			t.Errorf("parseOperator(%q) argument = %q, want %q", tc.in, op.Argument, tc.wantArg)
		}
		if op.Negated != tc.wantNegated {
			t.Errorf("parseOperator(%q) negated = %v, want %v", tc.in, op.Negated, tc.wantNegated)
		}
	}
}

// Edge: a lone quote character must not panic (slice guard) and must not be
// treated as an @ operator.
func TestParseOperatorLoneQuoteDoesNotPanic(t *testing.T) {
	p := NewParser()
	op, err := p.parseOperator(`"`)
	if err != nil {
		t.Fatalf("parseOperator: %v", err)
	}
	if op.Type != "@rx" {
		t.Fatalf("unexpected operator type %q", op.Type)
	}
}

// Integration: rules loaded from a CRS file must match as authored through
// the real Process path.
func TestQuotedOperatorRulesMatchViaLoadRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.conf")
	rules := `SecRule REQUEST_METHOD "@streq TRACE" "id:1001,phase:1,deny,status:405,msg:'TRACE blocked',severity:'CRITICAL'"
SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:1002,phase:1,deny,status:403,msg:'scanner UA blocked',severity:'CRITICAL'"`
	if err := os.WriteFile(path, []byte(rules+"\n"), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	layer := NewLayer(&Config{Enabled: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
	if err := layer.LoadRules(path); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if layer.GetRule("1001") == nil || layer.GetRule("1002") == nil {
		t.Fatal("rules did not parse")
	}

	run := func(method, ua string) engine.Action {
		req := httptest.NewRequest(method, "/anything", nil)
		if ua != "" {
			req.Header.Set("User-Agent", ua)
		}
		ctx := &engine.RequestContext{Method: req.Method, Headers: req.Header, Request: req}
		return layer.Process(ctx).Action
	}

	if a := run("TRACE", "bot/1.0"); a != engine.ActionBlock {
		t.Fatalf("FAIL: file-loaded @streq rule did not deny a TRACE request (action %v)", a)
	}
	if a := run("GET", "sqlmap/1.7"); a != engine.ActionBlock {
		t.Fatalf("FAIL: file-loaded @contains rule did not deny the sqlmap User-Agent (action %v)", a)
	}
	if a := run("GET", "Mozilla/5.0"); a != engine.ActionPass {
		t.Fatalf("FAIL: benign request was blocked (action %v)", a)
	}
}
