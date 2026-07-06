package nosqli

import (
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

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
