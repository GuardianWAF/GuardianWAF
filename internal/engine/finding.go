package engine

// Severity represents the threat severity level
type Severity int

const (
	SeverityInfo     Severity = iota // Informational
	SeverityLow                      // Low risk
	SeverityMedium                   // Medium risk
	SeverityHigh                     // High risk
	SeverityCritical                 // Critical risk
)

// String returns the string representation of a Severity
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Finding represents a single detection result from a layer or detector
type Finding struct {
	DetectorName string   `json:"detector"`
	Category     string   `json:"category"`
	Severity     Severity `json:"severity"`
	Score        int      `json:"score"`
	Description  string   `json:"description"`
	MatchedValue string   `json:"matched_value,omitempty"`
	Location     string   `json:"location"`
	Confidence   float64  `json:"confidence"`
}

// MarshalJSON for Severity so it serializes as string (e.g., "high") not number.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// truncateEvidence truncates s if longer than maxLen, appending "..." to indicate truncation
func truncateEvidence(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// ScoreAccumulator accumulates findings and scores from all layers
type ScoreAccumulator struct {
	findings   []Finding
	totalScore int
	multiplier float64 // paranoia multiplier: 1=0.5x, 2=1.0x, 3=1.5x, 4=2.0x
}

// NewScoreAccumulator creates a new accumulator with the given paranoia level (1-4)
func NewScoreAccumulator(paranoiaLevel int) *ScoreAccumulator {
	m := paranoiaToMultiplier(paranoiaLevel)
	return &ScoreAccumulator{
		findings:   make([]Finding, 0, 8),
		multiplier: m,
	}
}

// paranoiaToMultiplier converts a paranoia level (1-4) to its score multiplier.
// Values outside the 1-4 range are clamped.
func paranoiaToMultiplier(level int) float64 {
	switch {
	case level <= 1:
		return 0.5
	case level == 2:
		return 1.0
	case level == 3:
		return 1.5
	default: // level >= 4
		return 2.0
	}
}

// Add adds a finding to the accumulator
func (sa *ScoreAccumulator) Add(f Finding) {
	f.MatchedValue = truncateEvidence(f.MatchedValue, 200)
	sa.findings = append(sa.findings, f)
	sa.totalScore += f.Score
}

// AddMultiple adds multiple findings
func (sa *ScoreAccumulator) AddMultiple(findings []Finding) {
	for _, f := range findings {
		sa.Add(f)
	}
}

// Total returns the total accumulated score with paranoia multiplier applied
func (sa *ScoreAccumulator) Total() int {
	return int(float64(sa.totalScore) * sa.multiplier)
}

// RawTotal returns the total score without paranoia multiplier
func (sa *ScoreAccumulator) RawTotal() int {
	return sa.totalScore
}

// Exceeds returns true if the accumulated score exceeds the threshold
func (sa *ScoreAccumulator) Exceeds(threshold int) bool {
	return sa.Total() > threshold
}

// Findings returns all accumulated findings
func (sa *ScoreAccumulator) Findings() []Finding {
	return sa.findings
}

// HighestSeverity returns the maximum severity from all findings.
// Returns SeverityInfo if there are no findings.
func (sa *ScoreAccumulator) HighestSeverity() Severity {
	highest := SeverityInfo
	for _, f := range sa.findings {
		if f.Severity > highest {
			highest = f.Severity
		}
	}
	return highest
}

// Reset clears the accumulator for reuse (sync.Pool friendly)
func (sa *ScoreAccumulator) Reset() {
	sa.findings = sa.findings[:0]
	sa.totalScore = 0
}
