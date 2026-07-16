package nosqli

import (
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func score(findings []engine.Finding) int {
	t := 0
	for _, f := range findings {
		t += f.Score
	}
	return t
}

func TestDetect_AttackPayloads(t *testing.T) {
	// Each must reach the block threshold (>=50) on its own.
	attacks := []string{
		`{"username":{"$ne":null},"password":{"$ne":null}}`, // auth bypass
		`{"password":{"$gt":""}}`,                           // auth bypass
		`{"user":{"$ne":""}}`,                               // auth bypass
		"username[$ne]=admin",                               // query operator injection (key)
		"user[$gt]=",                                        // query operator injection
		`{"$where":"sleep(5000)"}`,                          // server-side JS / DoS
		`{"$where":"this.password.length>0"}`,               // server-side JS
		`{"q":{"$function":{"body":"x"}}}`,                  // server-side JS
	}
	for _, a := range attacks {
		if s := score(Detect(a, "body")); s < 50 {
			t.Errorf("attack not blocked (score %d < 50): %q", s, a)
		}
	}
}

func TestDetect_BenignInputs(t *testing.T) {
	benign := []string{
		"hello world",
		`{"name":"john","age":30}`,
		`{"price":{"$gt":100}}`,             // legit range filter
		`{"role":{"$in":["admin","user"]}}`, // legit array filter
		`{"sort":{"createdAt":-1}}`,
		"username=admin&password=secret",
		"q=mongodb tutorial",
		"",
	}
	for _, b := range benign {
		if f := Detect(b, "body"); len(f) != 0 {
			t.Errorf("false positive on benign input %q: %+v", b, f)
		}
	}
}

func TestDetect_RegexOperatorLogsButNotBlock(t *testing.T) {
	// $regex in user input is suspicious (ReDoS/extraction) but appears in legit
	// search APIs too — it should produce a finding, but not block on its own.
	f := Detect(`{"name":{"$regex":".*"}}`, "body")
	if len(f) == 0 {
		t.Fatal("expected a finding for $regex operator")
	}
	if s := score(f); s >= 50 {
		t.Errorf("$regex alone should not block (score %d >= 50)", s)
	}
}

func TestDetect_EmptyInput(t *testing.T) {
	if f := Detect("", "query"); f != nil {
		t.Errorf("expected nil for empty input, got %v", f)
	}
}

func TestDetector_Integration(t *testing.T) {
	det := NewDetector(true, 1.0)
	var _ engine.Detector = det
	if det.DetectorName() != "nosqli" {
		t.Errorf("DetectorName = %q, want nosqli", det.DetectorName())
	}
	if len(det.Patterns()) == 0 {
		t.Error("expected non-empty patterns")
	}

	// Bracket injection arrives in the query-parameter NAME.
	ctx := &engine.RequestContext{
		QueryParams:     map[string][]string{"username[$ne]": {"x"}},
		NormalizedQuery: map[string][]string{"username[$ne]": {"x"}},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}
	if r := det.Process(ctx); r.Score < 50 || len(r.Findings) == 0 {
		t.Errorf("Process did not flag query-key operator injection; score=%d", r.Score)
	}

	det.enabled = false
	if r := det.Process(ctx); r.Action != engine.ActionPass || len(r.Findings) != 0 {
		t.Error("disabled detector should pass")
	}
}

func TestDetector_Multiplier(t *testing.T) {
	ctx := &engine.RequestContext{
		BodyString: `{"$where":"1"}`,
		Headers:    map[string][]string{},
		Cookies:    map[string]string{},
	}
	base := NewDetector(true, 1.0).Process(ctx).Score
	doubled := NewDetector(true, 2.0).Process(ctx).Score
	if base == 0 || doubled != base*2 {
		t.Errorf("multiplier not applied: base=%d doubled=%d", base, doubled)
	}
}

// Merged from nosqli_gap_test.go
func TestDetector_NameAndOrder(t *testing.T) {
	det := NewDetector(true, 1.0)
	if det.Name() != "nosqli-detector" {
		t.Fatalf("Name() = %q, want nosqli-detector", det.Name())
	}
	if det.Order() != 0 {
		t.Fatalf("Order() = %d, want 0", det.Order())
	}
}

func TestDetector_ProcessCleanEnabledPasses(t *testing.T) {
	det := NewDetector(true, 1.0)
	ctx := &engine.RequestContext{
		Headers:           map[string][]string{},
		NormalizedHeaders: map[string][]string{},
		Cookies:           map[string]string{},
	}

	result := det.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("Action = %v, want %v", result.Action, engine.ActionPass)
	}
	if result.Score != 0 {
		t.Fatalf("Score = %d, want 0", result.Score)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("Findings = %d, want 0", len(result.Findings))
	}
}

func TestDetector_ProcessScansCookiesAndRefererWithoutDoubleCountingNormalizedDuplicates(t *testing.T) {
	det := NewDetector(true, 1.0)
	payload := `{"$where":"sleep(1)"}`
	ctx := &engine.RequestContext{
		Path:              payload,
		NormalizedPath:    payload,
		BodyString:        payload,
		NormalizedBody:    payload,
		Headers:           map[string][]string{"Referer": {payload}},
		NormalizedHeaders: map[string][]string{"Referer": {payload}},
		Cookies:           map[string]string{"session": payload},
	}

	result := det.Process(ctx)
	if result.Action != engine.ActionLog {
		t.Fatalf("Action = %v, want %v", result.Action, engine.ActionLog)
	}
	if len(result.Findings) != 4 {
		t.Fatalf("Findings = %d, want 4", len(result.Findings))
	}
	if result.Score != 360 {
		t.Fatalf("Score = %d, want 360", result.Score)
	}

	locations := map[string]int{}
	for _, finding := range result.Findings {
		locations[finding.Location]++
	}
	for _, location := range []string{"path", "body", "header", "cookie"} {
		if locations[location] != 1 {
			t.Fatalf("location %q count = %d, want 1", location, locations[location])
		}
	}
}

func TestMakeFinding_TruncatesLongMatchedValue(t *testing.T) {
	matched := strings.Repeat("x", 205)
	finding := makeFinding(1, engine.SeverityLow, "desc", matched, "body", 0.5)
	if len(finding.MatchedValue) != 200 {
		t.Fatalf("len(MatchedValue) = %d, want 200", len(finding.MatchedValue))
	}
	if !strings.HasSuffix(finding.MatchedValue, "...") {
		t.Fatalf("MatchedValue = %q, want ellipsis suffix", finding.MatchedValue)
	}
}
