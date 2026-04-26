package biometric

import (
	"math"
	"testing"
	"time"
)

// --- analyzeScrollBehavior coverage (currently 0%) ---

func TestAnalyzeScrollBehavior_Cov(t *testing.T) {
	d := NewDetector()
	d.minEvents = 5

	now := time.Now()

	// Case: 3+ scroll events should trigger full analysis
	scrollEvents := []ScrollEvent{
		{X: 0, Y: 0, DeltaX: 0, DeltaY: 10, Timestamp: now},
		{X: 0, Y: 10, DeltaX: 0, DeltaY: 20, Timestamp: now.Add(50 * time.Millisecond)},
		{X: 0, Y: 30, DeltaX: 0, DeltaY: 30, Timestamp: now.Add(100 * time.Millisecond)},
		{X: 0, Y: 60, DeltaX: 0, DeltaY: 5, Timestamp: now.Add(150 * time.Millisecond)},
		{X: 0, Y: 65, DeltaX: 0, DeltaY: 40, Timestamp: now.Add(200 * time.Millisecond)},
	}

	session := &Session{
		ID:           "scroll-session",
		CreatedAt:    now,
		ScrollEvents: scrollEvents,
		MouseEvents:  make([]MouseEvent, d.minEvents), // enough mouse events to pass minEvents check
	}

	analysis := d.AnalyzeSession(session)
	if analysis == nil {
		t.Fatal("expected analysis, got nil")
	}

	// Should have scroll-related indicators
	foundScrollIndicator := false
	for _, ind := range analysis.Indicators {
		if ind.Name == "scroll_velocity" || ind.Name == "smooth_scroll" {
			foundScrollIndicator = true
		}
	}
	if !foundScrollIndicator {
		t.Error("expected scroll velocity or smooth scroll indicator")
	}
}

// --- analyzeScrollVelocity coverage (currently 0%) ---

func TestAnalyzeScrollVelocity_Cov(t *testing.T) {
	now := time.Now()

	// Case: high variance (human-like) - returns 25
	events1 := []ScrollEvent{
		{DeltaX: 0, DeltaY: 5, Timestamp: now},
		{DeltaX: 0, DeltaY: 100, Timestamp: now.Add(16 * time.Millisecond)},
		{DeltaX: 0, DeltaY: 3, Timestamp: now.Add(32 * time.Millisecond)},
		{DeltaX: 0, DeltaY: 200, Timestamp: now.Add(48 * time.Millisecond)},
		{DeltaX: 0, DeltaY: 1, Timestamp: now.Add(64 * time.Millisecond)},
	}
	score1 := analyzeScrollVelocity(events1)
	if score1 != 25 {
		t.Errorf("expected 25 for high variance, got %f", score1)
	}

	// Case: low variance (bot-like) - returns -10
	events2 := []ScrollEvent{
		{DeltaX: 0, DeltaY: 10, Timestamp: now},
		{DeltaX: 0, DeltaY: 11, Timestamp: now.Add(16 * time.Millisecond)},
		{DeltaX: 0, DeltaY: 10, Timestamp: now.Add(32 * time.Millisecond)},
		{DeltaX: 0, DeltaY: 11, Timestamp: now.Add(48 * time.Millisecond)},
		{DeltaX: 0, DeltaY: 10, Timestamp: now.Add(64 * time.Millisecond)},
	}
	score2 := analyzeScrollVelocity(events2)
	if score2 != -10 {
		t.Errorf("expected -10 for low variance, got %f", score2)
	}

	// Case: fewer than 5 events
	events3 := []ScrollEvent{
		{DeltaX: 0, DeltaY: 10, Timestamp: now},
		{DeltaX: 0, DeltaY: 20, Timestamp: now.Add(16 * time.Millisecond)},
	}
	score3 := analyzeScrollVelocity(events3)
	if score3 != 0 {
		t.Errorf("expected 0 for insufficient events, got %f", score3)
	}
}

// --- analyzeClickPatterns additional coverage (currently 21.7%) ---

func TestAnalyzeClickPatterns_HighVariance_Cov(t *testing.T) {
	now := time.Now()

	// Create events with click type and high interval variance
	events := []MouseEvent{
		{Type: "click", Timestamp: now},
		{Type: "click", Timestamp: now.Add(50 * time.Millisecond)},
		{Type: "click", Timestamp: now.Add(500 * time.Millisecond)},
		{Type: "click", Timestamp: now.Add(600 * time.Millisecond)},
		{Type: "click", Timestamp: now.Add(2000 * time.Millisecond)},
		{Type: "click", Timestamp: now.Add(2100 * time.Millisecond)},
	}
	score := analyzeClickPatterns(events)
	if score != 25 {
		t.Errorf("expected 25 for high click variance, got %f", score)
	}
}

func TestAnalyzeClickPatterns_SingleInterval_Cov(t *testing.T) {
	now := time.Now()
	events := []MouseEvent{
		{Type: "click", Timestamp: now},
		{Type: "click", Timestamp: now.Add(100 * time.Millisecond)},
	}
	score := analyzeClickPatterns(events)
	// Only 2 clicks => 1 interval => len(intervals) < 2 => returns 0
	if score != 0 {
		t.Errorf("expected 0 for single interval, got %f", score)
	}
}

// --- analyzeBezierCurves additional coverage (currently 80%) ---

func TestAnalyzeBezierCurves_NoCurve_Cov(t *testing.T) {
	// All linear movements => cross product always 0 => ratio <= 0.3 => -20
	movements := []Movement{
		{FromX: 0, FromY: 0, ToX: 10, ToY: 0},
		{FromX: 10, FromY: 0, ToX: 20, ToY: 0},
		{FromX: 20, FromY: 0, ToX: 30, ToY: 0},
		{FromX: 30, FromY: 0, ToX: 40, ToY: 0},
		{FromX: 40, FromY: 0, ToX: 50, ToY: 0},
		{FromX: 50, FromY: 0, ToX: 60, ToY: 0},
	}
	score := analyzeBezierCurves(movements)
	if score != -20 {
		t.Errorf("expected -20 for no curves, got %f", score)
	}
}

// --- calculateOverallScore edge cases (currently 81.2%) ---

func TestCalculateOverallScore_ZeroWeight_Cov(t *testing.T) {
	d := NewDetector()
	indicators := []Indicator{
		{Name: "test", Score: 30, Weight: 0},
		{Name: "test2", Score: 20, Weight: 0},
	}
	score := d.calculateOverallScore(indicators)
	if score != 50 {
		t.Errorf("expected 50 for zero total weight, got %f", score)
	}
}

func TestCalculateOverallScore_HighPositive_Cov(t *testing.T) {
	d := NewDetector()
	indicators := []Indicator{
		{Name: "test1", Score: 100, Weight: 1.0},
		{Name: "test2", Score: 100, Weight: 1.0},
	}
	score := d.calculateOverallScore(indicators)
	// score = 50 + 100/2 = 100, clamped to 100
	if score != 100 {
		t.Errorf("expected 100 for high positive, got %f", score)
	}
}

func TestCalculateOverallScore_HighNegative_Cov(t *testing.T) {
	d := NewDetector()
	indicators := []Indicator{
		{Name: "test1", Score: -100, Weight: 1.0},
		{Name: "test2", Score: -100, Weight: 1.0},
	}
	score := d.calculateOverallScore(indicators)
	// score = 50 + (-100)/2 = 0, clamped to 0
	if score != 0 {
		t.Errorf("expected 0 for high negative, got %f", score)
	}
}

// --- calculateConfidence edge cases (currently 77.8%) ---

func TestCalculateConfidence_ManyEvents_Cov(t *testing.T) {
	d := NewDetector()

	session := &Session{
		MouseEvents:  make([]MouseEvent, 80),
		KeyEvents:    make([]KeyEvent, 40),
		ScrollEvents: make([]ScrollEvent, 10),
	}
	indicators := make([]Indicator, 6) // > 5 triggers +0.2

	confidence := d.calculateConfidence(session, indicators)
	// 130 events / 100 = 1.3, clamped to 1.0, + 0.2 = 1.2, clamped to 1.0
	if confidence != 1.0 {
		t.Errorf("expected 1.0 for many events + indicators, got %f", confidence)
	}
}

// --- extractMovements edge case: single event ---

func TestExtractMovements_SingleEvent_Cov(t *testing.T) {
	events := []MouseEvent{
		{X: 0, Y: 0, Type: "move", Timestamp: time.Now()},
	}
	movements := extractMovements(events)
	if len(movements) != 0 {
		t.Errorf("expected 0 movements for single event, got %d", len(movements))
	}
}

// --- analyzeSpeedVariance: few speeds edge case ---

func TestAnalyzeSpeedVariance_FewSpeeds_Cov(t *testing.T) {
	now := time.Now()
	movements := []Movement{
		{FromX: 0, ToX: 10, Duration: 0, Distance: 10, Timestamp: now}, // Duration=0, skipped
		{FromX: 10, ToX: 20, Duration: 100 * time.Millisecond, Distance: 10, Timestamp: now},
		{FromX: 20, ToX: 30, Duration: 0, Distance: 10, Timestamp: now}, // Duration=0, skipped
		{FromX: 30, ToX: 40, Duration: 200 * time.Millisecond, Distance: 10, Timestamp: now},
		{FromX: 40, ToX: 50, Duration: 0, Distance: 10, Timestamp: now}, // Duration=0, skipped
	}
	// Only 2 speeds < 3 => returns 0
	score := analyzeSpeedVariance(movements)
	if score != 0 {
		t.Errorf("expected 0 for fewer than 3 speeds, got %f", score)
	}
}

// --- analyzeNaturalPauses: all pauses ratio > 0.5 ---

func TestAnalyzeNaturalPauses_AllPauses_Cov(t *testing.T) {
	now := time.Now()
	events := []MouseEvent{
		{Timestamp: now},
		{Timestamp: now.Add(200 * time.Millisecond)}, // pause
		{Timestamp: now.Add(400 * time.Millisecond)}, // pause
		{Timestamp: now.Add(600 * time.Millisecond)}, // pause
		{Timestamp: now.Add(800 * time.Millisecond)}, // pause
		{Timestamp: now.Add(1000 * time.Millisecond)}, // pause
		{Timestamp: now.Add(1200 * time.Millisecond)}, // pause
		{Timestamp: now.Add(1400 * time.Millisecond)}, // pause
		{Timestamp: now.Add(1600 * time.Millisecond)}, // pause
		{Timestamp: now.Add(1800 * time.Millisecond)}, // pause
	}
	score := analyzeNaturalPauses(events)
	// ratio = 9/9 = 1.0, which is NOT in (0.1, 0.5), so returns -10
	if score != -10 {
		t.Errorf("expected -10 for all pauses (ratio > 0.5), got %f", score)
	}
}

// --- comprehensive session test with scroll + keyboard + mouse ---

func TestAnalyzeSession_AllBehaviors_Cov(t *testing.T) {
	d := NewDetector()
	d.minEvents = 5

	now := time.Now()

	// Mouse events: varied curved movement
	mouseEvents := []MouseEvent{
		{X: 0, Y: 0, Type: "move", Timestamp: now},
		{X: 15, Y: 20, Type: "move", Timestamp: now.Add(50 * time.Millisecond)},
		{X: 40, Y: 50, Type: "move", Timestamp: now.Add(150 * time.Millisecond)},
		{X: 70, Y: 80, Type: "move", Timestamp: now.Add(200 * time.Millisecond)},
		{X: 100, Y: 110, Type: "move", Timestamp: now.Add(400 * time.Millisecond)},
		{X: 130, Y: 130, Type: "move", Timestamp: now.Add(450 * time.Millisecond)},
		{X: 100, Y: 150, Type: "click", Button: 0, Timestamp: now.Add(500 * time.Millisecond)},
		{X: 100, Y: 150, Type: "click", Button: 0, Timestamp: now.Add(1500 * time.Millisecond)},
		{X: 100, Y: 150, Type: "click", Button: 0, Timestamp: now.Add(1600 * time.Millisecond)},
		{X: 100, Y: 150, Type: "click", Button: 0, Timestamp: now.Add(3000 * time.Millisecond)},
	}

	// Keyboard events: varied rhythm with backspace
	keyEvents := []KeyEvent{
		{Key: "h", Type: "press", Timestamp: now},
		{Key: "e", Type: "press", Timestamp: now.Add(120 * time.Millisecond)},
		{Key: "l", Type: "press", Timestamp: now.Add(250 * time.Millisecond)},
		{Key: "l", Type: "press", Timestamp: now.Add(300 * time.Millisecond)},
		{Key: "o", Type: "press", Timestamp: now.Add(450 * time.Millisecond)},
		{Key: "Backspace", Type: "press", Timestamp: now.Add(550 * time.Millisecond)},
		{Key: "w", Type: "press", Timestamp: now.Add(700 * time.Millisecond)},
		{Key: "o", Type: "press", Timestamp: now.Add(800 * time.Millisecond)},
		{Key: "r", Type: "press", Timestamp: now.Add(950 * time.Millisecond)},
		{Key: "l", Type: "press", Timestamp: now.Add(1100 * time.Millisecond)},
		{Key: "d", Type: "press", Timestamp: now.Add(1300 * time.Millisecond)},
	}

	// Scroll events: varied velocity
	scrollEvents := []ScrollEvent{
		{X: 0, Y: 0, DeltaX: 0, DeltaY: 5, Timestamp: now},
		{X: 0, Y: 5, DeltaX: 0, DeltaY: 120, Timestamp: now.Add(100 * time.Millisecond)},
		{X: 0, Y: 125, DeltaX: 0, DeltaY: 3, Timestamp: now.Add(200 * time.Millisecond)},
		{X: 0, Y: 128, DeltaX: 0, DeltaY: 80, Timestamp: now.Add(300 * time.Millisecond)},
		{X: 0, Y: 208, DeltaX: 0, DeltaY: 2, Timestamp: now.Add(400 * time.Millisecond)},
	}

	session := &Session{
		ID:           "full-behavior-session",
		CreatedAt:    now,
		MouseEvents:  mouseEvents,
		KeyEvents:    keyEvents,
		ScrollEvents: scrollEvents,
	}

	analysis := d.AnalyzeSession(session)
	if analysis == nil {
		t.Fatal("expected analysis, got nil")
	}

	// Should have many indicators (mouse, keyboard, scroll)
	found := map[string]bool{}
	for _, ind := range analysis.Indicators {
		found[ind.Name] = true
	}

	expected := []string{"linear_movement", "speed_variance", "natural_pauses", "click_patterns",
		"bezier_curves", "typing_rhythm", "key_consistency", "backspace_usage",
		"scroll_velocity", "smooth_scroll"}

	for _, name := range expected {
		if !found[name] {
			t.Errorf("expected indicator %s not found", name)
		}
	}

	// Confidence = events/100 + bonus for indicators
	// 26 events/100 = 0.26, + 0.2 for >5 indicators = 0.46
	if analysis.Confidence < 0.4 {
		t.Errorf("expected confidence >= 0.4, got %f", analysis.Confidence)
	}

	t.Logf("HumanScore: %f, IsBot: %v, Confidence: %f, Indicators: %d",
		analysis.HumanScore, analysis.IsBot, analysis.Confidence, len(analysis.Indicators))
}

// --- verify score boundary at threshold ---

func TestAnalyzeSession_ScoreAtThreshold_Cov(t *testing.T) {
	d := NewDetector()

	// A session with exactly threshold events (20 mouse + 0 keys => insufficient_data)
	session := &Session{
		ID:          "threshold-test",
		CreatedAt:   time.Now(),
		MouseEvents: make([]MouseEvent, 19), // below minEvents of 20
		KeyEvents:   make([]KeyEvent, 10),    // exactly 10 => pass the keyboard check
	}

	analysis := d.AnalyzeSession(session)
	if analysis == nil {
		t.Fatal("expected analysis, got nil")
	}

	// Since MouseEvents < minEvents (20) but KeyEvents >= 10, it should not be insufficient_data
	// Actually: "len(session.MouseEvents) < d.minEvents && len(session.KeyEvents) < 10"
	// MouseEvents=19 < 20 AND KeyEvents=10 NOT < 10, so the overall condition is false
	// This means it proceeds to analyze keyboard behavior
	foundInsufficient := false
	for _, ind := range analysis.Indicators {
		if ind.Name == "insufficient_data" {
			foundInsufficient = true
		}
	}
	if foundInsufficient {
		t.Error("should not have insufficient_data since KeyEvents >= 10")
	}
}

// --- detectLinearMovement edge: exactly 50% linear ---

func TestDetectLinearMovement_ExactlyHalf_Cov(t *testing.T) {
	movements := []Movement{
		{FromX: 0, FromY: 0, ToX: 10, ToY: 0},  // linear (horizontal)
		{FromX: 10, FromY: 0, ToX: 20, ToY: 10}, // non-linear
		{FromX: 20, FromY: 10, ToX: 30, ToY: 10}, // linear (horizontal)
		{FromX: 30, FromY: 10, ToX: 40, ToY: 20}, // non-linear
		{FromX: 40, FromY: 20, ToX: 50, ToY: 20}, // linear (horizontal)
	}
	score := detectLinearMovement(movements)
	// ratio = 3/5 = 0.6 > 0.5 => negative score
	expected := -50 * 0.6
	if math.Abs(score-expected) > 1 {
		t.Errorf("expected %f for 60%% linear, got %f", expected, score)
	}
}

// --- verify Indicator Score/Weight fields ---

func TestIndicator_Fields_Cov(t *testing.T) {
	ind := Indicator{
		Name:        "test_indicator",
		Score:       -50.5,
		Weight:      1.5,
		Description: "test description",
	}
	if ind.Name != "test_indicator" {
		t.Errorf("Name mismatch")
	}
	if ind.Score != -50.5 {
		t.Errorf("Score mismatch")
	}
	if ind.Weight != 1.5 {
		t.Errorf("Weight mismatch")
	}
	if ind.Description != "test description" {
		t.Errorf("Description mismatch")
	}
}

// --- Movement struct field coverage ---

func TestMovement_Fields_Cov(t *testing.T) {
	now := time.Now()
	m := Movement{
		FromX:     10,
		FromY:     20,
		ToX:       30,
		ToY:       40,
		Duration:  100 * time.Millisecond,
		Distance:  28.28,
		Timestamp: now,
	}
	if m.FromX != 10 || m.FromY != 20 || m.ToX != 30 || m.ToY != 40 {
		t.Error("movement coordinates mismatch")
	}
	if m.Duration != 100*time.Millisecond {
		t.Error("duration mismatch")
	}
	if m.Distance != 28.28 {
		t.Error("distance mismatch")
	}
}

// --- Analysis struct field coverage ---

func TestAnalysis_Fields_Cov(t *testing.T) {
	a := &Analysis{
		HumanScore:  75.5,
		IsBot:       false,
		Confidence:  0.85,
		ProcessedAt: time.Now(),
	}
	if a.HumanScore != 75.5 {
		t.Error("HumanScore mismatch")
	}
	if a.IsBot {
		t.Error("IsBot should be false")
	}
	if a.Confidence != 0.85 {
		t.Error("Confidence mismatch")
	}
}
