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

func TestOperatorEvaluator_PmfAndHostnameIPMatch(t *testing.T) {
	eval := NewOperatorEvaluator()

	pmfResult, err := eval.Evaluate(RuleOperator{Type: "@pmf", Argument: "alpha beta"}, "zz beta yy")
	if err != nil {
		t.Fatalf("@pmf evaluate error: %v", err)
	}
	if !pmfResult {
		t.Fatal("expected @pmf to match via phrase match fallback")
	}

	ipMatch, err := eval.Evaluate(RuleOperator{Type: "@ipMatch", Argument: "127.0.0.1 ::1"}, "localhost")
	if err != nil {
		t.Fatalf("@ipMatch evaluate error: %v", err)
	}
	if !ipMatch {
		t.Fatal("expected localhost to resolve to 127.0.0.1 or ::1")
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
