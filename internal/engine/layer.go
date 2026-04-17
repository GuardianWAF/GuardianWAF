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

// UnmarshalJSON deserializes Action from a JSON string.
func (a *Action) UnmarshalJSON(data []byte) error {
	s := string(data)
	switch s {
	case `"pass"`:
		*a = ActionPass
	case `"block"`:
		*a = ActionBlock
	case `"log"`:
		*a = ActionLog
	case `"challenge"`:
		*a = ActionChallenge
	default:
		*a = ActionPass
	}
	return nil
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
	OrderSIEM        = 1  // SIEM event forwarding (passive, first)
	OrderCluster     = 75
	OrderWebSocket   = 76
	OrderGRPC        = 78
	OrderZeroTrust   = 85  // Zero Trust identity verification (mTLS/device attestation)
	OrderIPACL       = 100
	OrderThreatIntel = 125
	OrderCORS        = 150
	OrderRules       = 150
	OrderCanary      = 95
	OrderCache       = 140 // Caching layer (memory/Redis)
	OrderReplay      = 145
	OrderRateLimit   = 200
	OrderATO         = 250
	OrderAPISecurity = 275
	OrderAPIValidation = 280
	OrderGraphQL      = 285 // GraphQL query depth/complexity/introspection limits
	OrderSanitizer   = 300
	OrderDiscovery   = 310 // Passive API discovery (OpenAPI generation)
	OrderCRS         = 350 // OWASP CRS after sanitization
	OrderDetection   = 400
	OrderVirtualPatch = 450 // Virtual patches after detection
	OrderChallenge    = 430 // JS proof-of-work challenge (bot mitigation)
	OrderAnomaly      = 473 // ML anomaly detection (ONNX) before DLP
	OrderRemediation  = 480 // AI remediation layer (generated rules) after anomaly
	OrderDLP          = 475 // DLP before bot detection
	OrderBotDetect   = 500
	OrderClientSide  = 590 // Client-side protection before response
	OrderResponse    = 600
)

// OrderedLayer wraps a Layer with its execution order
type OrderedLayer struct {
	Layer Layer
	Order int
}
