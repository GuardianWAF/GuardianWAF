package engine

import "time"

// Event represents a WAF event for logging and storage.
type Event struct {
	ID         string        // Unique event ID
	Timestamp  time.Time     // When the event occurred
	RequestID  string        // Corresponding request ID
	ClientIP   string        // Client IP address
	Method     string        // HTTP method
	Path       string        // Request path
	Query      string        // Query string
	Action     Action        // WAF decision (pass/block/log)
	Score      int           // Total accumulated score
	Findings   []Finding     // All findings from detection
	Duration   time.Duration // Processing duration
	StatusCode int           // HTTP response status code
	UserAgent  string        // User-Agent header
}

// NewEvent creates an Event from a RequestContext after pipeline processing.
// statusCode is the HTTP response status code returned to the client.
func NewEvent(ctx *RequestContext, statusCode int) Event {
	var clientIP string
	if ctx.ClientIP != nil {
		clientIP = ctx.ClientIP.String()
	}

	var query string
	if ctx.Request != nil {
		query = ctx.Request.URL.RawQuery
	}

	var userAgent string
	if vals, ok := ctx.Headers["User-Agent"]; ok && len(vals) > 0 {
		userAgent = vals[0]
	}

	var findings []Finding
	var score int
	if ctx.Accumulator != nil {
		findings = make([]Finding, len(ctx.Accumulator.Findings()))
		copy(findings, ctx.Accumulator.Findings())
		score = ctx.Accumulator.Total()
	}

	return Event{
		ID:         generateRequestID(),
		Timestamp:  ctx.StartTime,
		RequestID:  ctx.RequestID,
		ClientIP:   clientIP,
		Method:     ctx.Method,
		Path:       ctx.Path,
		Query:      query,
		Action:     ctx.Action,
		Score:      score,
		Findings:   findings,
		Duration:   time.Since(ctx.StartTime),
		StatusCode: statusCode,
		UserAgent:  userAgent,
	}
}
