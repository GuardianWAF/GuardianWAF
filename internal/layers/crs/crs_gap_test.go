package crs

import (
	"regexp"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestLayer_Order(t *testing.T) {
	layer := NewLayer(DefaultConfig())
	if got := layer.Order(); got != engine.OrderCRS {
		t.Fatalf("Order() = %d, want %d", got, engine.OrderCRS)
	}
}

func TestLoadRuleFile_ErrorPaths(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	if err := layer.loadRuleFile("rules\x00.conf"); err == nil {
		t.Fatal("expected NUL path error")
	}
	if err := layer.loadRuleFile("/definitely/missing/crs-rule.conf"); err == nil {
		t.Fatal("expected missing file error")
	}
}

func TestParser_ParseVariablesPlusPrefixes(t *testing.T) {
	p := NewParser()
	vars, err := p.parseVariables("!+ARGS:user|&+REQUEST_HEADERS:Host")
	if err != nil {
		t.Fatalf("parseVariables error: %v", err)
	}
	if len(vars) != 2 {
		t.Fatalf("expected 2 variables, got %d", len(vars))
	}

	if !vars[0].Exclude || vars[0].Collection != "+ARGS" || vars[0].Key != "user" {
		t.Fatalf("unexpected exclude variable: %+v", vars[0])
	}
	if !vars[1].Count || vars[1].Collection != "+REQUEST_HEADERS" || vars[1].Key != "Host" {
		t.Fatalf("unexpected count variable: %+v", vars[1])
	}
}

func TestParser_ParseActionErrors(t *testing.T) {
	p := NewParser()

	if _, err := p.parseSecAction(`SecAction "phase:not-a-number"`); err == nil {
		t.Fatal("expected invalid phase error")
	}
	if _, err := p.parseSecAction(`SecAction "status:not-a-number"`); err == nil {
		t.Fatal("expected invalid status error")
	}
	if _, err := p.parseSecAction(`SecAction "skip:not-a-number"`); err == nil {
		t.Fatal("expected invalid skip error")
	}
}

func TestOperatorEvaluator_PmfFallback(t *testing.T) {
	eval := NewOperatorEvaluator()

	pmfResult, err := eval.Evaluate(RuleOperator{Type: "@pmf", Argument: "alpha beta"}, "zz beta yy")
	if err != nil {
		t.Fatalf("@pmf evaluate error: %v", err)
	}
	if !pmfResult {
		t.Fatal("expected @pmf to match via phrase match fallback")
	}
}

// TestOperatorEvaluator_IpMatch_IpLiteralOnly pins the @ipMatch SecLang
// contract: the VALUE is an IP literal matched against the argument's
// IP/CIDR list, and non-IP values do not match. The previous implementation
// resolved hostnames via net.LookupIP in the request path — an
// attacker-controllable DNS trigger (latency amplification, outbound
// resolver traffic) that let an attacker-supplied hostname decide a block
// ("localhost" matched an @ipMatch 127.0.0.1 rule). DNS lookups belong to
// @rbl; hostnames reach SecLang pre-resolved via REMOTE_HOST.
func TestOperatorEvaluator_IpMatch_IpLiteralOnly(t *testing.T) {
	eval := NewOperatorEvaluator()

	// IP literals still match.
	for _, v := range []string{"127.0.0.1", "::1"} {
		result, err := eval.Evaluate(RuleOperator{Type: "@ipMatch", Argument: "127.0.0.1 ::1"}, v)
		if err != nil {
			t.Fatalf("@ipMatch evaluate error for %q: %v", v, err)
		}
		if !result {
			t.Errorf("expected literal %q to match", v)
		}
	}

	// Non-IP values never match — no hostname resolution in the operator.
	result, err := eval.Evaluate(RuleOperator{Type: "@ipMatch", Argument: "127.0.0.1 ::1"}, "localhost")
	if err != nil {
		t.Fatalf("@ipMatch evaluate error: %v", err)
	}
	if result {
		t.Fatal("expected hostname value 'localhost' not to match — @ipMatch matches IP literals only")
	}
}

func TestGetCachedRegex_AtCapacityBypassesCache(t *testing.T) {
	oldSize := regexCacheSize.Load()
	regexCacheSize.Store(maxRegexCacheSize)
	defer regexCacheSize.Store(oldSize)

	pattern := "capacity_bypass_unique_pattern_12345"
	re, err := getCachedRegex(pattern)
	if err != nil {
		t.Fatalf("getCachedRegex error: %v", err)
	}
	if re == nil || !re.MatchString(pattern) {
		t.Fatal("expected compiled regex to work when cache is at capacity")
	}
	if got := regexCacheSize.Load(); got != maxRegexCacheSize {
		t.Fatalf("regex cache size changed at capacity: got %d want %d", got, maxRegexCacheSize)
	}
}

func TestMatchWithTimeout_ReturnsSubmatches(t *testing.T) {
	re := regexp.MustCompile(`^(foo)(bar)$`)
	matches := matchWithTimeout(re, "foobar")
	if len(matches) != 3 {
		t.Fatalf("expected 3 submatches, got %v", matches)
	}
	if matches[1] != "foo" || matches[2] != "bar" {
		t.Fatalf("unexpected submatches: %v", matches)
	}
}
