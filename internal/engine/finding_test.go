package engine

import (
	"strings"
	"testing"
)

func TestTruncateEvidence(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"short string unchanged", "hello", 200, "hello"},
		{"exact length unchanged", "abc", 3, "abc"},
		{"long string truncated", strings.Repeat("a", 250), 200, strings.Repeat("a", 197) + "..."},
		{"empty string", "", 200, ""},
		{"zero maxLen", "hello", 0, ""},
		{"maxLen 1", "hello", 1, "h"},
		{"maxLen 2", "hello", 2, "he"},
		{"maxLen 3", "hello", 3, "hel"},
		{"maxLen 4 with long input", "hello world", 4, "h..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateEvidence(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateEvidence(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestNewScoreAccumulator(t *testing.T) {
	tests := []struct {
		name           string
		paranoiaLevel  int
		wantMultiplier float64
	}{
		{"level 0 clamps to 0.5", 0, 0.5},
		{"level 1", 1, 0.5},
		{"level 2", 2, 1.0},
		{"level 3", 3, 1.5},
		{"level 4", 4, 2.0},
		{"level 5 clamps to 2.0", 5, 2.0},
		{"negative clamps to 0.5", -1, 0.5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa := NewScoreAccumulator(tt.paranoiaLevel)
			if sa.multiplier != tt.wantMultiplier {
				t.Errorf("NewScoreAccumulator(%d).multiplier = %f, want %f", tt.paranoiaLevel, sa.multiplier, tt.wantMultiplier)
			}
			if sa.totalScore != 0 {
				t.Errorf("new accumulator totalScore = %d, want 0", sa.totalScore)
			}
			if len(sa.findings) != 0 {
				t.Errorf("new accumulator findings len = %d, want 0", len(sa.findings))
			}
		})
	}
}

func TestScoreAccumulatorAdd(t *testing.T) {
	sa := NewScoreAccumulator(2) // multiplier = 1.0

	f1 := Finding{
		DetectorName: "sqli",
		Category:     "sqli",
		Severity:     SeverityHigh,
		Score:        40,
		Description:  "SQL injection detected",
		MatchedValue: "' OR 1=1 --",
		Location:     "query",
		Confidence:   0.9,
	}

	sa.Add(f1)
	if sa.RawTotal() != 40 {
		t.Errorf("RawTotal after first Add = %d, want 40", sa.RawTotal())
	}
	if sa.Total() != 40 {
		t.Errorf("Total after first Add = %d, want 40", sa.Total())
	}
	if len(sa.Findings()) != 1 {
		t.Fatalf("Findings count = %d, want 1", len(sa.Findings()))
	}

	f2 := Finding{
		DetectorName: "xss",
		Category:     "xss",
		Severity:     SeverityMedium,
		Score:        30,
		Description:  "XSS detected",
		MatchedValue: "<script>alert(1)</script>",
		Location:     "body",
		Confidence:   0.8,
	}
	sa.Add(f2)

	if sa.RawTotal() != 70 {
		t.Errorf("RawTotal after second Add = %d, want 70", sa.RawTotal())
	}
	if sa.Total() != 70 {
		t.Errorf("Total after second Add = %d, want 70", sa.Total())
	}
	if len(sa.Findings()) != 2 {
		t.Errorf("Findings count = %d, want 2", len(sa.Findings()))
	}
}

func TestScoreAccumulatorAddMultiple(t *testing.T) {
	sa := NewScoreAccumulator(2)
	findings := []Finding{
		{Score: 10, Severity: SeverityLow},
		{Score: 20, Severity: SeverityMedium},
		{Score: 30, Severity: SeverityHigh},
	}
	sa.AddMultiple(findings)

	if sa.RawTotal() != 60 {
		t.Errorf("RawTotal = %d, want 60", sa.RawTotal())
	}
	if len(sa.Findings()) != 3 {
		t.Errorf("Findings count = %d, want 3", len(sa.Findings()))
	}
}

func TestScoreAccumulatorTotalWithParanoiaLevels(t *testing.T) {
	tests := []struct {
		name          string
		paranoiaLevel int
		rawScore      int
		wantTotal     int
	}{
		{"paranoia 1 halves score", 1, 100, 50},
		{"paranoia 2 keeps score", 2, 100, 100},
		{"paranoia 3 multiplies by 1.5", 3, 100, 150},
		{"paranoia 4 doubles score", 4, 100, 200},
		{"paranoia 1 with odd score", 1, 75, 37}, // int(75 * 0.5) = 37
		{"paranoia 3 with small score", 3, 10, 15},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa := NewScoreAccumulator(tt.paranoiaLevel)
			sa.Add(Finding{Score: tt.rawScore})
			if sa.Total() != tt.wantTotal {
				t.Errorf("Total() = %d, want %d", sa.Total(), tt.wantTotal)
			}
			if sa.RawTotal() != tt.rawScore {
				t.Errorf("RawTotal() = %d, want %d", sa.RawTotal(), tt.rawScore)
			}
		})
	}
}

func TestScoreAccumulatorExceeds(t *testing.T) {
	sa := NewScoreAccumulator(2) // multiplier = 1.0
	sa.Add(Finding{Score: 50})

	if sa.Exceeds(50) {
		t.Error("Exceeds(50) = true, want false (score equals threshold)")
	}
	if !sa.Exceeds(49) {
		t.Error("Exceeds(49) = false, want true")
	}
	if sa.Exceeds(100) {
		t.Error("Exceeds(100) = true, want false")
	}

	// With paranoia 4 (multiplier 2.0), raw score 50 -> total 100
	sa2 := NewScoreAccumulator(4)
	sa2.Add(Finding{Score: 50})
	if !sa2.Exceeds(99) {
		t.Error("paranoia 4: Exceeds(99) = false, want true (total=100)")
	}
	if sa2.Exceeds(100) {
		t.Error("paranoia 4: Exceeds(100) = true, want false (total=100, not >100)")
	}
}

func TestScoreAccumulatorHighestSeverity(t *testing.T) {
	t.Run("empty accumulator returns info", func(t *testing.T) {
		sa := NewScoreAccumulator(2)
		if sa.HighestSeverity() != SeverityInfo {
			t.Errorf("HighestSeverity() = %v, want %v", sa.HighestSeverity(), SeverityInfo)
		}
	})

	t.Run("single finding", func(t *testing.T) {
		sa := NewScoreAccumulator(2)
		sa.Add(Finding{Severity: SeverityHigh})
		if sa.HighestSeverity() != SeverityHigh {
			t.Errorf("HighestSeverity() = %v, want %v", sa.HighestSeverity(), SeverityHigh)
		}
	})

	t.Run("mixed severities returns highest", func(t *testing.T) {
		sa := NewScoreAccumulator(2)
		sa.Add(Finding{Severity: SeverityLow})
		sa.Add(Finding{Severity: SeverityCritical})
		sa.Add(Finding{Severity: SeverityMedium})
		if sa.HighestSeverity() != SeverityCritical {
			t.Errorf("HighestSeverity() = %v, want %v", sa.HighestSeverity(), SeverityCritical)
		}
	})

	t.Run("all same severity", func(t *testing.T) {
		sa := NewScoreAccumulator(2)
		sa.Add(Finding{Severity: SeverityMedium})
		sa.Add(Finding{Severity: SeverityMedium})
		if sa.HighestSeverity() != SeverityMedium {
			t.Errorf("HighestSeverity() = %v, want %v", sa.HighestSeverity(), SeverityMedium)
		}
	})
}

func TestScoreAccumulatorReset(t *testing.T) {
	sa := NewScoreAccumulator(3)
	sa.Add(Finding{Score: 50, Severity: SeverityHigh})
	sa.Add(Finding{Score: 30, Severity: SeverityCritical})

	if sa.RawTotal() != 80 {
		t.Fatalf("pre-reset RawTotal = %d, want 80", sa.RawTotal())
	}

	sa.Reset()

	if sa.RawTotal() != 0 {
		t.Errorf("post-reset RawTotal = %d, want 0", sa.RawTotal())
	}
	if sa.Total() != 0 {
		t.Errorf("post-reset Total = %d, want 0", sa.Total())
	}
	if len(sa.Findings()) != 0 {
		t.Errorf("post-reset Findings len = %d, want 0", len(sa.Findings()))
	}
	if sa.HighestSeverity() != SeverityInfo {
		t.Errorf("post-reset HighestSeverity = %v, want %v", sa.HighestSeverity(), SeverityInfo)
	}

	// Verify accumulator still works after reset
	sa.Add(Finding{Score: 10, Severity: SeverityLow})
	if sa.RawTotal() != 10 {
		t.Errorf("post-reset-add RawTotal = %d, want 10", sa.RawTotal())
	}
}

func TestScoreAccumulatorResetPreservesMultiplier(t *testing.T) {
	sa := NewScoreAccumulator(4) // multiplier = 2.0
	sa.Add(Finding{Score: 100})
	sa.Reset()
	sa.Add(Finding{Score: 50})
	if sa.Total() != 100 {
		t.Errorf("Total after reset = %d, want 100 (50 * 2.0)", sa.Total())
	}
}

func TestAddTruncatesMatchedValue(t *testing.T) {
	sa := NewScoreAccumulator(2)
	longValue := strings.Repeat("x", 300)
	sa.Add(Finding{MatchedValue: longValue, Score: 10})

	findings := sa.Findings()
	if len(findings) != 1 {
		t.Fatalf("Findings count = %d, want 1", len(findings))
	}
	if len(findings[0].MatchedValue) > 200 {
		t.Errorf("MatchedValue length = %d, want <= 200", len(findings[0].MatchedValue))
	}
	if !strings.HasSuffix(findings[0].MatchedValue, "...") {
		t.Error("truncated MatchedValue should end with '...'")
	}
}

func TestAddPreservesShortMatchedValue(t *testing.T) {
	sa := NewScoreAccumulator(2)
	sa.Add(Finding{MatchedValue: "short", Score: 5})
	findings := sa.Findings()
	if findings[0].MatchedValue != "short" {
		t.Errorf("MatchedValue = %q, want %q", findings[0].MatchedValue, "short")
	}
}

func TestEmptyAccumulator(t *testing.T) {
	sa := NewScoreAccumulator(2)
	if sa.Total() != 0 {
		t.Errorf("empty Total = %d, want 0", sa.Total())
	}
	if sa.RawTotal() != 0 {
		t.Errorf("empty RawTotal = %d, want 0", sa.RawTotal())
	}
	if sa.Exceeds(0) {
		t.Error("empty Exceeds(0) = true, want false")
	}
	if len(sa.Findings()) != 0 {
		t.Errorf("empty Findings len = %d, want 0", len(sa.Findings()))
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		severity Severity
		want     string
	}{
		{SeverityInfo, "info"},
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
		{Severity(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.severity.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestActionString(t *testing.T) {
	tests := []struct {
		action Action
		want   string
	}{
		{ActionPass, "pass"},
		{ActionBlock, "block"},
		{ActionLog, "log"},
		{ActionChallenge, "challenge"},
		{Action(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.action.String(); got != tt.want {
			t.Errorf("Action(%d).String() = %q, want %q", tt.action, got, tt.want)
		}
	}
}
