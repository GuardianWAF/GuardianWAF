// Package biometric provides biometric bot detection using behavioral analysis.
package biometric

import (
	"math"
	"time"
)

// Session tracks user behavior for a single session.
type Session struct {
	ID          string
	CreatedAt   time.Time
	MouseEvents []MouseEvent
	KeyEvents   []KeyEvent
	ScrollEvents []ScrollEvent
}

// MouseEvent represents a mouse movement or click.
type MouseEvent struct {
	X         int       `json:"x"`
	Y         int       `json:"y"`
	Type      string    `json:"type"` // "move", "click", "down", "up"
	Timestamp time.Time `json:"ts"`
	Button    int       `json:"button,omitempty"` // 0=left, 1=middle, 2=right
}

// KeyEvent represents a keyboard event.
type KeyEvent struct {
	Key       string    `json:"key"`
	Type      string    `json:"type"` // "down", "up", "press"
	Timestamp time.Time `json:"ts"`
	Code      string    `json:"code,omitempty"`
}

// ScrollEvent represents a scroll action.
type ScrollEvent struct {
	X         int       `json:"x"`
	Y         int       `json:"y"`
	DeltaX    int       `json:"dx"`
	DeltaY    int       `json:"dy"`
	Timestamp time.Time `json:"ts"`
}

// Analysis contains biometric analysis results.
type Analysis struct {
	HumanScore   float64        // 0-100, higher = more human
	IsBot        bool
	Confidence   float64
	Indicators   []Indicator
	ProcessedAt  time.Time
}

// Indicator represents a specific bot/human indicator.
type Indicator struct {
	Name        string  `json:"name"`
	Score       float64 `json:"score"`   // -100 to +100
	Weight      float64 `json:"weight"`  // Indicator importance
	Description string  `json:"description"`
}

// Detector performs biometric bot detection.
type Detector struct {
	minEvents    int     // Minimum events for analysis
	timeWindow   time.Duration
	scoreThreshold float64
}

// NewDetector creates a new biometric detector.
func NewDetector() *Detector {
	return &Detector{
		minEvents:      20,
		timeWindow:     5 * time.Minute,
		scoreThreshold: 50,
	}
}

// AnalyzeSession analyzes a session for bot behavior.
func (d *Detector) AnalyzeSession(session *Session) *Analysis {
	analysis := &Analysis{
		HumanScore:  50, // Start neutral
		Confidence:  0,
		Indicators:  []Indicator{},
		ProcessedAt: time.Now(),
	}

	// Check minimum events
	if len(session.MouseEvents) < d.minEvents && len(session.KeyEvents) < 10 {
		analysis.Indicators = append(analysis.Indicators, Indicator{
			Name:        "insufficient_data",
			Score:       0,
			Weight:      0,
			Description: "Not enough events for analysis",
		})
		return analysis
	}

	// Analyze mouse behavior
	if len(session.MouseEvents) >= d.minEvents {
		mouseScore := d.analyzeMouseBehavior(session.MouseEvents)
		analysis.Indicators = append(analysis.Indicators, mouseScore...)
	}

	// Analyze keyboard behavior
	if len(session.KeyEvents) >= 5 {
		keyScore := d.analyzeKeyboardBehavior(session.KeyEvents)
		analysis.Indicators = append(analysis.Indicators, keyScore...)
	}

	// Analyze scroll behavior
	if len(session.ScrollEvents) >= 3 {
		scrollScore := d.analyzeScrollBehavior(session.ScrollEvents)
		analysis.Indicators = append(analysis.Indicators, scrollScore...)
	}

	// Calculate overall score
	analysis.HumanScore = d.calculateOverallScore(analysis.Indicators)
	analysis.IsBot = analysis.HumanScore < d.scoreThreshold
	analysis.Confidence = d.calculateConfidence(session, analysis.Indicators)

	return analysis
}

// analyzeMouseBehavior analyzes mouse movement patterns.
func (d *Detector) analyzeMouseBehavior(events []MouseEvent) []Indicator {
	indicators := []Indicator{}

	if len(events) < 10 {
		return indicators
	}

	// Calculate movement statistics
	movements := extractMovements(events)

	// Check for linear movement (bot indicator)
	linearScore := detectLinearMovement(movements)
	indicators = append(indicators, Indicator{
		Name:        "linear_movement",
		Score:       linearScore,
		Weight:      1.5,
		Description: "Too-perfect linear mouse movement",
	})

	// Check movement speed consistency
	speedVariance := analyzeSpeedVariance(movements)
	indicators = append(indicators, Indicator{
		Name:        "speed_variance",
		Score:       speedVariance,
		Weight:      1.0,
		Description: "Mouse speed consistency",
	})

	// Check for natural pauses
	pauseScore := analyzeNaturalPauses(events)
	indicators = append(indicators, Indicator{
		Name:        "natural_pauses",
		Score:       pauseScore,
		Weight:      1.2,
		Description: "Natural movement pauses",
	})

	// Check click patterns
	clickScore := analyzeClickPatterns(events)
	indicators = append(indicators, Indicator{
		Name:        "click_patterns",
		Score:       clickScore,
		Weight:      1.0,
		Description: "Natural click timing",
	})

	// Check Bezier curves (human movements follow curves)
	curveScore := analyzeBezierCurves(movements)
	indicators = append(indicators, Indicator{
		Name:        "bezier_curves",
		Score:       curveScore,
		Weight:      1.3,
		Description: "Curved movement paths",
	})

	return indicators
}

// analyzeKeyboardBehavior analyzes typing patterns.
func (d *Detector) analyzeKeyboardBehavior(events []KeyEvent) []Indicator {
	indicators := []Indicator{}

	if len(events) < 5 {
		return indicators
	}

	// Check typing rhythm
	rhythmScore := analyzeTypingRhythm(events)
	indicators = append(indicators, Indicator{
		Name:        "typing_rhythm",
		Score:       rhythmScore,
		Weight:      1.2,
		Description: "Natural typing rhythm",
	})

	// Check for consistent timing (bot indicator)
	consistencyScore := analyzeKeyConsistency(events)
	indicators = append(indicators, Indicator{
		Name:        "key_consistency",
		Score:       consistencyScore,
		Weight:      1.0,
		Description: "Key press timing consistency",
	})

	// Check for backspace usage (humans make mistakes)
	backspaceScore := analyzeBackspaceUsage(events)
	indicators = append(indicators, Indicator{
		Name:        "backspace_usage",
		Score:       backspaceScore,
		Weight:      0.8,
		Description: "Natural error correction",
	})

	return indicators
}

// analyzeScrollBehavior analyzes scroll patterns.
func (d *Detector) analyzeScrollBehavior(events []ScrollEvent) []Indicator {
	indicators := []Indicator{}

	if len(events) < 3 {
		return indicators
	}

	// Check scroll velocity
	velocityScore := analyzeScrollVelocity(events)
	indicators = append(indicators, Indicator{
		Name:        "scroll_velocity",
		Score:       velocityScore,
		Weight:      1.0,
		Description: "Natural scroll velocity",
	})

	// Check for smooth scroll (bot indicator)
	smoothScore := detectSmoothScroll(events)
	indicators = append(indicators, Indicator{
		Name:        "smooth_scroll",
		Score:       smoothScore,
		Weight:      1.2,
		Description: "Scroll smoothness",
	})

	return indicators
}

// Movement represents a mouse movement.
type Movement struct {
	FromX     int
	FromY     int
	ToX       int
	ToY       int
	Duration  time.Duration
	Distance  float64
	Timestamp time.Time
}

// extractMovements converts events to movements.
func extractMovements(events []MouseEvent) []Movement {
	movements := []Movement{}

	for i := 1; i < len(events); i++ {
		prev := events[i-1]
		curr := events[i]

		if prev.Type == "move" && curr.Type == "move" {
			dx := curr.X - prev.X
			dy := curr.Y - prev.Y
			distance := math.Sqrt(float64(dx*dx + dy*dy))
			duration := curr.Timestamp.Sub(prev.Timestamp)

			movements = append(movements, Movement{
				FromX:     prev.X,
				FromY:     prev.Y,
				ToX:       curr.X,
				ToY:       curr.Y,
				Duration:  duration,
				Distance:  distance,
				Timestamp: curr.Timestamp,
			})
		}
	}

	return movements
}

// detectLinearMovement detects perfect linear movement (bot indicator).
func detectLinearMovement(movements []Movement) float64 {
	if len(movements) < 5 {
		return 0
	}

	linearCount := 0
	for _, m := range movements {
		// Check if movement is perfectly horizontal or vertical
		if m.FromX == m.ToX || m.FromY == m.ToY {
			linearCount++
		}
	}

	ratio := float64(linearCount) / float64(len(movements))
	// More than 50% linear is suspicious
	if ratio > 0.5 {
		return -50 * ratio // Negative score
	}
	return 30 * (1 - ratio) // Positive score for non-linear
}

// analyzeSpeedVariance checks for natural speed variance.
func analyzeSpeedVariance(movements []Movement) float64 {
	if len(movements) < 5 {
		return 0
	}

	// Calculate speeds
	speeds := []float64{}
	for _, m := range movements {
		if m.Duration > 0 {
			speed := m.Distance / float64(m.Duration.Milliseconds())
			speeds = append(speeds, speed)
		}
	}

	if len(speeds) < 3 {
		return 0
	}

	// Calculate variance
	mean := 0.0
	for _, s := range speeds {
		mean += s
	}
	mean /= float64(len(speeds))

	variance := 0.0
	for _, s := range speeds {
		variance += (s - mean) * (s - mean)
	}
	variance /= float64(len(speeds))

	// High variance is human-like
	if variance > 100 {
		return 40
	}
	if variance > 50 {
		return 20
	}
	return -20 // Low variance is bot-like
}

// analyzeNaturalPauses checks for natural pause patterns.
func analyzeNaturalPauses(events []MouseEvent) float64 {
	if len(events) < 10 {
		return 0
	}

	// Look for pauses > 100ms
	pauseCount := 0
	for i := 1; i < len(events); i++ {
		gap := events[i].Timestamp.Sub(events[i-1].Timestamp)
		if gap > 100*time.Millisecond {
			pauseCount++
		}
	}

	ratio := float64(pauseCount) / float64(len(events)-1)
	if math.IsNaN(ratio) || math.IsInf(ratio, 0) {
		return 0
	}
	// Some pauses are natural
	if ratio > 0.1 && ratio < 0.5 {
		return 30
	}
	// Too many or too few pauses is suspicious
	return -10
}

// analyzeClickPatterns analyzes click timing.
func analyzeClickPatterns(events []MouseEvent) float64 {
	clicks := []time.Time{}
	for _, e := range events {
		if e.Type == "click" {
			clicks = append(clicks, e.Timestamp)
		}
	}

	if len(clicks) < 3 {
		return 0
	}

	// Check for consistent timing (bot-like)
	intervals := []time.Duration{}
	for i := 1; i < len(clicks); i++ {
		intervals = append(intervals, clicks[i].Sub(clicks[i-1]))
	}

	// Calculate variance
	if len(intervals) < 2 {
		return 0
	}

	mean := 0.0
	for _, iv := range intervals {
		mean += float64(iv.Milliseconds())
	}
	mean /= float64(len(intervals))

	variance := 0.0
	for _, iv := range intervals {
		diff := float64(iv.Milliseconds()) - mean
		variance += diff * diff
	}
	variance /= float64(len(intervals))

	// High variance is human-like
	if variance > 1000 {
		return 25
	}
	return -15
}

// analyzeBezierCurves checks for curved movement paths.
func analyzeBezierCurves(movements []Movement) float64 {
	// Simplified: check if movements change direction
	if len(movements) < 5 {
		return 0
	}

	curveCount := 0
	for i := 2; i < len(movements); i++ {
		// Check for direction change
		m1 := movements[i-2]
		m2 := movements[i-1]
		m3 := movements[i]

		dx1 := m2.FromX - m1.FromX
		dy1 := m2.FromY - m1.FromY
		dx2 := m3.FromX - m2.FromX
		dy2 := m3.FromY - m2.FromY

		// Cross product to detect direction change
		cross := dx1*dy2 - dy1*dx2
		if cross != 0 {
			curveCount++
		}
	}

	ratio := float64(curveCount) / float64(len(movements)-2)
	if math.IsNaN(ratio) || math.IsInf(ratio, 0) {
		return 0
	}
	if ratio > 0.3 {
		return 35
	}
	return -20
}

// analyzeTypingRhythm checks for natural typing patterns.
func analyzeTypingRhythm(events []KeyEvent) float64 {
	if len(events) < 10 {
		return 0
	}

	// Get press events
	presses := []KeyEvent{}
	for _, e := range events {
		if e.Type == "press" {
			presses = append(presses, e)
		}
	}

	if len(presses) < 5 {
		return 0
	}

	// Calculate intervals
	intervals := []float64{}
	for i := 1; i < len(presses); i++ {
		iv := presses[i].Timestamp.Sub(presses[i-1].Timestamp).Milliseconds()
		intervals = append(intervals, float64(iv))
	}

	// Calculate variance
	mean := 0.0
	for _, iv := range intervals {
		mean += iv
	}
	mean /= float64(len(intervals))

	variance := 0.0
	for _, iv := range intervals {
		variance += (iv - mean) * (iv - mean)
	}
	variance /= float64(len(intervals))

	// Natural typing has variance
	if variance > 10000 {
		return 30
	}
	return -20
}

// analyzeKeyConsistency checks for consistent timing.
func analyzeKeyConsistency(events []KeyEvent) float64 {
	// Similar to typing rhythm but looking for too-perfect timing
	rhythmScore := analyzeTypingRhythm(events)
	return -rhythmScore // Inverse
}

// analyzeBackspaceUsage checks for error correction.
func analyzeBackspaceUsage(events []KeyEvent) float64 {
	backspaceCount := 0
	for _, e := range events {
		if e.Key == "Backspace" {
			backspaceCount++
		}
	}

	// Some backspace usage is natural
	if backspaceCount > 0 {
		return 20
	}
	// Perfect typing is suspicious
	if len(events) > 20 {
		return -10
	}
	return 0
}

// analyzeScrollVelocity checks scroll patterns.
func analyzeScrollVelocity(events []ScrollEvent) float64 {
	if len(events) < 5 {
		return 0
	}

	// Calculate velocity variance
	velocities := []float64{}
	for _, e := range events {
		velocity := math.Sqrt(float64(e.DeltaX*e.DeltaX + e.DeltaY*e.DeltaY))
		velocities = append(velocities, velocity)
	}

	// High variance is natural
	mean := 0.0
	for _, v := range velocities {
		mean += v
	}
	mean /= float64(len(velocities))

	variance := 0.0
	for _, v := range velocities {
		variance += (v - mean) * (v - mean)
	}
	variance /= float64(len(velocities))

	if variance > 100 {
		return 25
	}
	return -10
}

// detectSmoothScroll detects perfectly smooth scrolling.
func detectSmoothScroll(events []ScrollEvent) float64 {
	if len(events) < 5 {
		return 0
	}

	// Check for identical deltas (bot-like)
	identicalCount := 0
	for i := 1; i < len(events); i++ {
		if events[i].DeltaY == events[i-1].DeltaY && events[i].DeltaY != 0 {
			identicalCount++
		}
	}

	ratio := float64(identicalCount) / float64(len(events)-1)
	if ratio > 0.5 {
		return -40 // Too smooth is suspicious
	}
	return 20
}

// calculateOverallScore calculates weighted score from indicators.
func (d *Detector) calculateOverallScore(indicators []Indicator) float64 {
	if len(indicators) == 0 {
		return 50 // Neutral
	}

	totalWeight := 0.0
	weightedScore := 0.0

	for _, ind := range indicators {
		totalWeight += ind.Weight
		weightedScore += ind.Score * ind.Weight
	}

	if totalWeight == 0 {
		return 50
	}

	score := weightedScore / totalWeight

	// Normalize to 0-100
	score = 50 + score/2
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// calculateConfidence calculates confidence level.
func (d *Detector) calculateConfidence(session *Session, indicators []Indicator) float64 {
	totalEvents := len(session.MouseEvents) + len(session.KeyEvents) + len(session.ScrollEvents)

	// More events = higher confidence
	confidence := float64(totalEvents) / 100.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	// More indicators = higher confidence
	if len(indicators) > 5 {
		confidence += 0.2
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}
