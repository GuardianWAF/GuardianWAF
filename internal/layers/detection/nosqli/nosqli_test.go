package nosqli

import (
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
