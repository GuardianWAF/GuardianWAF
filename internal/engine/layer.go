package engine

import (
	"time"
)

// Action represents the WAF decision for a request
type Action int

const (
	ActionPass      Action = iota // Allow the request
	ActionBlock                   // Block the request (403)
	ActionLog                     // Allow but log as suspicious
	ActionChallenge               // Challenge the client (bot detection)
)

// String returns the string representation of an Action
func (a Action) String() string {
	switch a {
	case ActionPass:
		return "pass"
	case ActionBlock:
		return "block"
	case ActionLog:
		return "log"
	case ActionChallenge:
		return "challenge"
	default:
		return "unknown"
	}
}

// MarshalJSON serializes Action as a JSON string (e.g., "block") instead of a number.
func (a Action) MarshalJSON() ([]byte, error) {
	return []byte(`"` + a.String() + `"`), nil
}

// LayerResult holds the outcome of a single layer's processing
type LayerResult struct {
	Action   Action
	Findings []Finding
	Score    int
	Duration time.Duration
}

// Layer is the interface all WAF processing layers implement
type Layer interface {
	Name() string
	Process(ctx *RequestContext) LayerResult
}

// Detector interface extends Layer with introspection methods
type Detector interface {
	Layer
	DetectorName() string
	Patterns() []string
}

// LayerOrder constants define execution order in the pipeline
const (
	OrderIPACL     = 100
	OrderRateLimit = 200
	OrderSanitizer = 300
	OrderDetection = 400
	OrderBotDetect = 500
	OrderResponse  = 600
)

// OrderedLayer wraps a Layer with its execution order
type OrderedLayer struct {
	Layer Layer
	Order int
}
