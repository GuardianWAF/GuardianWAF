package crs

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/regexsafe"
)

// Regression tests: createTransaction must populate the ARGS collection from
// the query string and urlencoded request bodies. Transaction.RequestArgs is
// initialized empty and nothing used to write it, so ARGS/ARGS_GET/ARGS_POST
// always resolved empty and every ARGS-targeted rule was inert through the
// real Process path.

func TestCreateTransactionPopulatesQueryArgs(t *testing.T) {
	l := NewLayer(DefaultConfig())
	req := httptest.NewRequest("GET", "/login?password=secret%20123&user=bob&user=alice", nil)
	ctx := &engine.RequestContext{Method: req.Method, Headers: req.Header, Request: req}

	tx := l.createTransaction(ctx, regexsafe.NewDeadline())

	if got := tx.RequestArgs["password"]; len(got) != 1 || got[0] != "secret 123" {
		t.Fatalf("password arg = %v, want [secret 123] (URL-decoded)", got)
	}
	if got := tx.RequestArgs["user"]; len(got) != 2 || got[0] != "bob" || got[1] != "alice" {
		t.Fatalf("multi-value user arg = %v, want [bob alice]", got)
	}
}

func TestCreateTransactionPopulatesBodyArgs(t *testing.T) {
	l := NewLayer(DefaultConfig())
	body := "password=secret123&user=alice"
	req := httptest.NewRequest("POST", "/login?user=bob", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := &engine.RequestContext{Method: req.Method, Headers: req.Header, Request: req, Body: []byte(body)}

	tx := l.createTransaction(ctx, regexsafe.NewDeadline())

	// Query and body sources merge for the same key.
	if got := tx.RequestArgs["user"]; len(got) != 2 || got[0] != "bob" || got[1] != "alice" {
		t.Fatalf("merged query+body user arg = %v, want [bob alice]", got)
	}
	if got := tx.RequestArgs["password"]; len(got) != 1 || got[0] != "secret123" {
		t.Fatalf("body password arg = %v, want [secret123]", got)
	}
}

// A malformed query escape must not panic; ParseQuery errors are skipped
// (fail-soft — that source contributes no ARGS).
func TestCreateTransactionMalformedQueryIsLenient(t *testing.T) {
	l := NewLayer(DefaultConfig())
	req := httptest.NewRequest("GET", "/login?a=1%zz&b=2", nil)
	ctx := &engine.RequestContext{Method: req.Method, Headers: req.Header, Request: req}

	tx := l.createTransaction(ctx, regexsafe.NewDeadline())

	if len(tx.RequestArgs) != 0 {
		t.Fatalf("malformed query unexpectedly populated ARGS: %v", tx.RequestArgs)
	}
}

// Only urlencoded bodies feed ARGS — other content types are not form-parsed.
func TestCreateTransactionNonFormBodyNotParsed(t *testing.T) {
	l := NewLayer(DefaultConfig())
	req := httptest.NewRequest("POST", "/api", nil)
	req.Header.Set("Content-Type", "application/json")
	ctx := &engine.RequestContext{Method: req.Method, Headers: req.Header, Request: req, Body: []byte(`{"name":"value"}`)}

	tx := l.createTransaction(ctx, regexsafe.NewDeadline())

	if len(tx.RequestArgs) != 0 {
		t.Fatalf("JSON body leaked into ARGS: %v", tx.RequestArgs)
	}
}

// Integration: an ARGS rule loaded from a file denies a matching query value
// through the real Process path, and passes benign values.
func TestArgsRuleFiresViaLoadRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.conf")
	rules := `SecRule ARGS:password "@contains secret" "id:1001,phase:1,deny,status:403,msg:'flagged value in ARGS',severity:'CRITICAL'"`
	if err := os.WriteFile(path, []byte(rules+"\n"), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	layer := NewLayer(&Config{Enabled: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
	if err := layer.LoadRules(path); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	run := func(target string) engine.Action {
		req := httptest.NewRequest("GET", target, nil)
		ctx := &engine.RequestContext{Method: req.Method, Headers: req.Header, Request: req}
		return layer.Process(ctx).Action
	}

	if a := run("/login?password=secret123"); a != engine.ActionBlock {
		t.Fatalf("FAIL: ARGS rule did not deny password=secret123 (action %v)", a)
	}
	if a := run("/login?password=hello"); a != engine.ActionPass {
		t.Fatalf("FAIL: benign value triggered the ARGS rule (action %v)", a)
	}
}
