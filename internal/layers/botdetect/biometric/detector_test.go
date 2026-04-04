package biometric

import (
	"math"
	"testing"
	"time"
)

func TestNewDetector(t *testing.T) {
	d := NewDetector()

	if d == nil {
		t.Fatal("expected detector, got nil")
	}
	if d.minEvents != 20 {
		t.Errorf("minEvents = %d, want %d", d.minEvents, 20)
	}
	if d.scoreThreshold != 50 {
		t.Errorf("scoreThreshold = %f, want %f", d.scoreThreshold, 50.0)
	}
	if d.timeWindow != 5*time.Minute {
		t.Errorf("timeWindow = %v, want %v", d.timeWindow, 5*time.Minute)
	}
}

func TestDetector_AnalyzeSession_InsufficientData(t *testing.T) {
	d := NewDetector()

	session := &Session{
		ID:        "test-session",
		CreatedAt: time.Now(),
		// Not enough events
		MouseEvents:  []MouseEvent{},
		KeyEvents:    []KeyEvent{},
		ScrollEvents: []ScrollEvent{},
	}

	analysis := d.AnalyzeSession(session)

	if analysis == nil {
		t.Fatal("expected analysis, got nil")
	}
	if analysis.IsBot {
		t.Error("expected not bot when insufficient data")
	}
	if len(analysis.Indicators) == 0 {
		t.Error("expected indicators about insufficient data")
	}
	if analysis.Indicators[0].Name != "insufficient_data" {
		t.Errorf("expected insufficient_data indicator, got %s", analysis.Indicators[0].Name)
	}
}

func TestDetector_AnalyzeSession_MouseBehavior(t *testing.T) {
	d := NewDetector()
	d.minEvents = 5

	// Create bot-like mouse movements (linear, perfect timing)
	now := time.Now()
	mouseEvents := []MouseEvent{}
	for i := 0; i < 10; i++ {
		mouseEvents = append(mouseEvents, MouseEvent{
			X:         i * 10,
			Y:         50, // Perfectly horizontal - bot-like
			Type:      "move",
			Timestamp: now.Add(time.Duration(i*50) * time.Millisecond),
		})
	}

	session := &Session{
		ID:          "bot-session",
		CreatedAt:   now,
		MouseEvents: mouseEvents,
	}

	analysis := d.AnalyzeSession(session)

	if analysis == nil {
		t.Fatal("expected analysis, got nil")
	}

	// Should have linear movement indicator
	foundLinear := false
	for _, ind := range analysis.Indicators {
		if ind.Name == "linear_movement" {
			foundLinear = true
			if ind.Score >= 0 {
				t.Error("expected negative score for linear movement (bot-like)")
			}
		}
	}
	if !foundLinear {
		t.Error("expected linear_movement indicator")
	}
}

func TestDetector_AnalyzeSession_HumanLikeBehavior(t *testing.T) {
	d := NewDetector()
	d.minEvents = 5

	// Create human-like mouse movements (curved, varied timing)
	now := time.Now()
	mouseEvents := []MouseEvent{}
	positions := []struct{ x, y int }{
		{0, 0},
		{15, 20},
		{35, 45},
		{60, 70},
		{90, 85},
		{120, 100},
	}

	for i, pos := range positions {
		// Varied timing - human-like
		var delay time.Duration
		if i%2 == 0 {
			delay = time.Duration(i*80) * time.Millisecond
		} else {
			delay = time.Duration(i*120) * time.Millisecond
		}

		mouseEvents = append(mouseEvents, MouseEvent{
			X:         pos.x,
			Y:         pos.y,
			Type:      "move",
			Timestamp: now.Add(delay),
		})
	}

	session := &Session{
		ID:          "human-session",
		CreatedAt:   now,
		MouseEvents: mouseEvents,
	}

	analysis := d.AnalyzeSession(session)

	if analysis == nil {
		t.Fatal("expected analysis, got nil")
	}
}

func TestDetector_AnalyzeSession_KeyboardBehavior(t *testing.T) {
	d := NewDetector()

	now := time.Now()
	keyEvents := []KeyEvent{}

	// Human-like typing with backspace (mistake correction)
	// Need at least 10 key events for analysis
	keystrokes := []struct {
		key   string
		delay time.Duration
	}{
		{"h", 0},
		{"e", 150},
		{"l", 200},
		{"x", 180},         // mistake
		{"Backspace", 300}, // correction
		{"l", 250},
		{"o", 190},
		{" ", 300},         // space
		{"w", 450},
		{"o", 500},
		{"r", 550},
		{"l", 650},
		{"d", 700},
	}

	for _, ks := range keystrokes {
		keyEvents = append(keyEvents, KeyEvent{
			Key:       ks.key,
			Type:      "press",
			Timestamp: now.Add(ks.delay * time.Millisecond),
		})
	}

	session := &Session{
		ID:        "session-with-keys",
		CreatedAt: now,
		KeyEvents: keyEvents,
	}

	analysis := d.AnalyzeSession(session)

	if analysis == nil {
		t.Fatal("expected analysis, got nil")
	}

	// Should have backspace indicator or typing_rhythm indicator
	foundRelevantIndicator := false
	for _, ind := range analysis.Indicators {
		if ind.Name == "backspace_usage" || ind.Name == "typing_rhythm" || ind.Name == "key_consistency" {
			foundRelevantIndicator = true
		}
	}
	if !foundRelevantIndicator {
		t.Error("expected keyboard-related indicator")
	}
}

func TestDetector_AnalyzeSession_ScrollBehavior(t *testing.T) {
	d := NewDetector()

	now := time.Now()
	scrollEvents := []ScrollEvent{}

	// Human-like scroll with varied deltas
	deltas := []int{3, 7, 12, 8, 5, 15, 9}
	for i, delta := range deltas {
		scrollEvents = append(scrollEvents, ScrollEvent{
			X:         0,
			Y:         i * 100,
			DeltaY:    delta,
			Timestamp: now.Add(time.Duration(i*200) * time.Millisecond),
		})
	}

	session := &Session{
		ID:           "session-with-scroll",
		CreatedAt:    now,
		ScrollEvents: scrollEvents,
	}

	analysis := d.AnalyzeSession(session)

	if analysis == nil {
		t.Fatal("expected analysis, got nil")
	}
}

func TestExtractMovements(t *testing.T) {
	now := time.Now()
	events := []MouseEvent{
		{X: 0, Y: 0, Type: "move", Timestamp: now},
		{X: 10, Y: 10, Type: "move", Timestamp: now.Add(100 * time.Millisecond)},
		{X: 20, Y: 20, Type: "click", Timestamp: now.Add(200 * time.Millisecond)},
		{X: 30, Y: 30, Type: "move", Timestamp: now.Add(300 * time.Millisecond)},
	}

	movements := extractMovements(events)

	// Should only extract move->move pairs
	if len(movements) != 1 {
		t.Errorf("expected 1 movement, got %d", len(movements))
	}

	if len(movements) > 0 {
		m := movements[0]
		if m.FromX != 0 || m.FromY != 0 {
			t.Errorf("expected From (0,0), got (%d,%d)", m.FromX, m.FromY)
		}
		if m.ToX != 10 || m.ToY != 10 {
			t.Errorf("expected To (10,10), got (%d,%d)", m.ToX, m.ToY)
		}
	}
}

func TestDetectLinearMovement(t *testing.T) {
	tests := []struct {
		name      string
		movements []Movement
		wantScore float64
	}{
		{
			name:      "empty movements",
			movements: []Movement{},
			wantScore: 0,
		},
		{
			name: "few movements",
			movements: []Movement{
				{FromX: 0, FromY: 0, ToX: 10, ToY: 0},
				{FromX: 10, FromY: 0, ToX: 20, ToY: 0},
			},
			wantScore: 0,
		},
		{
			name: "mostly linear",
			movements: []Movement{
				{FromX: 0, FromY: 0, ToX: 10, ToY: 0},
				{FromX: 10, FromY: 0, ToX: 20, ToY: 0},
				{FromX: 20, FromY: 0, ToX: 30, ToY: 0},
				{FromX: 30, FromY: 0, ToX: 40, ToY: 0},
				{FromX: 40, FromY: 0, ToX: 50, ToY: 5},
				{FromX: 50, FromY: 5, ToX: 60, ToY: 10},
			},
			wantScore: -25, // ~50% linear, negative score
		},
		{
			name: "mostly non-linear",
			movements: []Movement{
				{FromX: 0, FromY: 0, ToX: 10, ToY: 15},
				{FromX: 10, FromY: 15, ToX: 25, ToY: 20},
				{FromX: 25, FromY: 20, ToX: 40, ToY: 35},
				{FromX: 40, FromY: 35, ToX: 55, ToY: 50},
				{FromX: 55, FromY: 50, ToX: 70, ToY: 65},
				{FromX: 70, FromY: 65, ToX: 85, ToY: 80},
			},
			wantScore: 30, // Positive score for non-linear
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectLinearMovement(tt.movements)
			if math.Abs(got-tt.wantScore) > 10 {
				t.Errorf("detectLinearMovement() = %f, want approximately %f", got, tt.wantScore)
			}
		})
	}
}

func TestAnalyzeSpeedVariance(t *testing.T) {
	tests := []struct {
		name      string
		movements []Movement
		wantPositive bool
	}{
		{
			name:         "empty movements",
			movements:    []Movement{},
			wantPositive: false,
		},
		{
			name: "consistent speed (bot-like)",
			movements: []Movement{
				{FromX: 0, ToX: 10, Duration: 100 * time.Millisecond, Distance: 10},
				{FromX: 10, ToX: 20, Duration: 100 * time.Millisecond, Distance: 10},
				{FromX: 20, ToX: 30, Duration: 100 * time.Millisecond, Distance: 10},
				{FromX: 30, ToX: 40, Duration: 100 * time.Millisecond, Distance: 10},
				{FromX: 40, ToX: 50, Duration: 100 * time.Millisecond, Distance: 10},
			},
			wantPositive: false, // Low variance, negative score
		},
		{
			name: "varied speed (human-like)",
			movements: []Movement{
				{FromX: 0, ToX: 500, Duration: 10 * time.Millisecond, Distance: 500},    // extremely fast
				{FromX: 500, ToX: 510, Duration: 1000 * time.Millisecond, Distance: 10}, // very slow
				{FromX: 510, ToX: 1010, Duration: 10 * time.Millisecond, Distance: 500}, // extremely fast
				{FromX: 1010, ToX: 1020, Duration: 2000 * time.Millisecond, Distance: 10}, // very slow
				{FromX: 1020, ToX: 1520, Duration: 10 * time.Millisecond, Distance: 500}, // extremely fast
			},
			wantPositive: true, // High variance, positive score
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzeSpeedVariance(tt.movements)
			if tt.wantPositive && got <= 0 {
				t.Errorf("analyzeSpeedVariance() = %f, expected positive for human-like", got)
			}
			if !tt.wantPositive && got > 0 {
				t.Errorf("analyzeSpeedVariance() = %f, expected non-positive for bot-like", got)
			}
		})
	}
}

func TestAnalyzeNaturalPauses(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		events   []MouseEvent
		expected float64
	}{
		{
			name:     "no events",
			events:   []MouseEvent{},
			expected: 0,
		},
		{
			name: "no pauses (bot-like)",
			events: []MouseEvent{
				{X: 0, Timestamp: now},
				{X: 10, Timestamp: now.Add(50 * time.Millisecond)},
				{X: 20, Timestamp: now.Add(100 * time.Millisecond)},
				{X: 30, Timestamp: now.Add(150 * time.Millisecond)},
				{X: 40, Timestamp: now.Add(200 * time.Millisecond)},
				{X: 50, Timestamp: now.Add(250 * time.Millisecond)},
				{X: 60, Timestamp: now.Add(300 * time.Millisecond)},
				{X: 70, Timestamp: now.Add(350 * time.Millisecond)},
				{X: 80, Timestamp: now.Add(400 * time.Millisecond)},
				{X: 90, Timestamp: now.Add(450 * time.Millisecond)},
				{X: 100, Timestamp: now.Add(500 * time.Millisecond)},
			},
			expected: -10,
		},
		{
			name: "natural pauses (human-like)",
			events: []MouseEvent{
				{X: 0, Timestamp: now},
				{X: 10, Timestamp: now.Add(50 * time.Millisecond)},
				{X: 20, Timestamp: now.Add(300 * time.Millisecond)}, // pause > 100ms
				{X: 30, Timestamp: now.Add(350 * time.Millisecond)},
				{X: 40, Timestamp: now.Add(600 * time.Millisecond)}, // pause > 100ms
				{X: 50, Timestamp: now.Add(650 * time.Millisecond)},
				{X: 60, Timestamp: now.Add(850 * time.Millisecond)}, // pause > 100ms
				{X: 70, Timestamp: now.Add(900 * time.Millisecond)},
				{X: 80, Timestamp: now.Add(1100 * time.Millisecond)}, // pause > 100ms
				{X: 90, Timestamp: now.Add(1150 * time.Millisecond)},
				{X: 100, Timestamp: now.Add(1200 * time.Millisecond)},
			},
			expected: 30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzeNaturalPauses(tt.events)
			if got != tt.expected {
				t.Errorf("analyzeNaturalPauses() = %f, want %f", got, tt.expected)
			}
		})
	}
}

func TestAnalyzeTypingRhythm(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name         string
		events       []KeyEvent
		wantPositive bool
	}{
		{
			name:         "few events",
			events:       []KeyEvent{{Key: "a"}},
			wantPositive: false,
		},
		{
			name: "consistent rhythm (bot-like)",
			events: []KeyEvent{
				{Key: "a", Type: "press", Timestamp: now},
				{Key: "b", Type: "press", Timestamp: now.Add(100 * time.Millisecond)},
				{Key: "c", Type: "press", Timestamp: now.Add(200 * time.Millisecond)},
				{Key: "d", Type: "press", Timestamp: now.Add(300 * time.Millisecond)},
				{Key: "e", Type: "press", Timestamp: now.Add(400 * time.Millisecond)},
				{Key: "f", Type: "press", Timestamp: now.Add(500 * time.Millisecond)},
				{Key: "g", Type: "press", Timestamp: now.Add(600 * time.Millisecond)},
				{Key: "h", Type: "press", Timestamp: now.Add(700 * time.Millisecond)},
				{Key: "i", Type: "press", Timestamp: now.Add(800 * time.Millisecond)},
				{Key: "j", Type: "press", Timestamp: now.Add(900 * time.Millisecond)},
			},
			wantPositive: false,
		},
		{
			name: "varied rhythm (human-like)",
			events: []KeyEvent{
				{Key: "a", Type: "press", Timestamp: now},
				{Key: "b", Type: "press", Timestamp: now.Add(50 * time.Millisecond)},
				{Key: "c", Type: "press", Timestamp: now.Add(200 * time.Millisecond)},
				{Key: "d", Type: "press", Timestamp: now.Add(220 * time.Millisecond)},
				{Key: "e", Type: "press", Timestamp: now.Add(500 * time.Millisecond)},
				{Key: "f", Type: "press", Timestamp: now.Add(550 * time.Millisecond)},
				{Key: "g", Type: "press", Timestamp: now.Add(800 * time.Millisecond)},
				{Key: "h", Type: "press", Timestamp: now.Add(850 * time.Millisecond)},
				{Key: "i", Type: "press", Timestamp: now.Add(1200 * time.Millisecond)},
				{Key: "j", Type: "press", Timestamp: now.Add(1250 * time.Millisecond)},
			},
			wantPositive: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzeTypingRhythm(tt.events)
			if tt.wantPositive && got <= 0 {
				t.Errorf("analyzeTypingRhythm() = %f, expected positive for human-like", got)
			}
			if !tt.wantPositive && got > 0 {
				t.Errorf("analyzeTypingRhythm() = %f, expected non-positive for bot-like", got)
			}
		})
	}
}

func TestAnalyzeBackspaceUsage(t *testing.T) {
	tests := []struct {
		name     string
		events   []KeyEvent
		expected float64
	}{
		{
			name: "no backspace few events",
			events: []KeyEvent{
				{Key: "a"}, {Key: "b"}, {Key: "c"},
			},
			expected: 0, // Not enough events for perfect typing penalty
		},
		{
			name: "no backspace many events",
			events: []KeyEvent{
				{Key: "a"}, {Key: "b"}, {Key: "c"}, {Key: "d"}, {Key: "e"},
				{Key: "f"}, {Key: "g"}, {Key: "h"}, {Key: "i"}, {Key: "j"},
				{Key: "k"}, {Key: "l"}, {Key: "m"}, {Key: "n"}, {Key: "o"},
				{Key: "p"}, {Key: "q"}, {Key: "r"}, {Key: "s"}, {Key: "t"},
				{Key: "u"},
			},
			expected: -10, // Perfect typing is suspicious with many events
		},
		{
			name: "with backspace",
			events: []KeyEvent{
				{Key: "a"}, {Key: "b"}, {Key: "Backspace"}, {Key: "c"},
			},
			expected: 20,
		},
		{
			name: "only backspace",
			events: []KeyEvent{
				{Key: "Backspace"},
			},
			expected: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzeBackspaceUsage(tt.events)
			if got != tt.expected {
				t.Errorf("analyzeBackspaceUsage() = %f, want %f", got, tt.expected)
			}
		})
	}
}

func TestDetectSmoothScroll(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		events   []ScrollEvent
		expected float64
	}{
		{
			name:     "few events",
			events:   []ScrollEvent{{DeltaY: 10}},
			expected: 0,
		},
		{
			name: "identical deltas (bot-like)",
			events: []ScrollEvent{
				{DeltaY: 100, Timestamp: now},
				{DeltaY: 100, Timestamp: now.Add(16 * time.Millisecond)},
				{DeltaY: 100, Timestamp: now.Add(32 * time.Millisecond)},
				{DeltaY: 100, Timestamp: now.Add(48 * time.Millisecond)},
				{DeltaY: 100, Timestamp: now.Add(64 * time.Millisecond)},
				{DeltaY: 100, Timestamp: now.Add(80 * time.Millisecond)},
			},
			expected: -40,
		},
		{
			name: "varied deltas (human-like)",
			events: []ScrollEvent{
				{DeltaY: 50, Timestamp: now},
				{DeltaY: 120, Timestamp: now.Add(20 * time.Millisecond)},
				{DeltaY: 80, Timestamp: now.Add(40 * time.Millisecond)},
				{DeltaY: 150, Timestamp: now.Add(60 * time.Millisecond)},
				{DeltaY: 60, Timestamp: now.Add(80 * time.Millisecond)},
				{DeltaY: 90, Timestamp: now.Add(100 * time.Millisecond)},
			},
			expected: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectSmoothScroll(tt.events)
			if got != tt.expected {
				t.Errorf("detectSmoothScroll() = %f, want %f", got, tt.expected)
			}
		})
	}
}

func TestCalculateOverallScore(t *testing.T) {
	d := NewDetector()

	tests := []struct {
		name      string
		indicators []Indicator
		minScore  float64
		maxScore  float64
	}{
		{
			name:       "empty indicators",
			indicators: []Indicator{},
			minScore:   45,
			maxScore:   55,
		},
		{
			name: "positive indicators",
			indicators: []Indicator{
				{Name: "test1", Score: 30, Weight: 1.0},
				{Name: "test2", Score: 40, Weight: 1.0},
			},
			minScore: 60,
			maxScore: 100,
		},
		{
			name: "negative indicators",
			indicators: []Indicator{
				{Name: "test1", Score: -30, Weight: 1.0},
				{Name: "test2", Score: -40, Weight: 1.0},
			},
			minScore: 0,
			maxScore: 40,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := d.calculateOverallScore(tt.indicators)
			if got < tt.minScore || got > tt.maxScore {
				t.Errorf("calculateOverallScore() = %f, want between %f and %f", got, tt.minScore, tt.maxScore)
			}
		})
	}
}

func TestCalculateConfidence(t *testing.T) {
	d := NewDetector()

	tests := []struct {
		name       string
		session    *Session
		indicators []Indicator
		minConf    float64
	}{
		{
			name:       "empty session",
			session:    &Session{},
			indicators: []Indicator{},
			minConf:    0,
		},
		{
			name: "many events",
			session: &Session{
				MouseEvents: make([]MouseEvent, 50),
				KeyEvents:   make([]KeyEvent, 30),
			},
			indicators: []Indicator{},
			minConf:    0.5,
		},
		{
			name: "many indicators",
			session: &Session{
				MouseEvents: make([]MouseEvent, 30),
			},
			indicators: make([]Indicator, 6),
			minConf:    0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := d.calculateConfidence(tt.session, tt.indicators)
			if got < tt.minConf {
				t.Errorf("calculateConfidence() = %f, want at least %f", got, tt.minConf)
			}
			if got > 1.0 {
				t.Errorf("calculateConfidence() = %f, want <= 1.0", got)
			}
		})
	}
}
