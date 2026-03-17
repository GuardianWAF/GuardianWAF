package engine

import (
	"sync"
	"time"
)

// UAParser is a function type for parsing User-Agent strings into structured data.
// Set via SetUAParser to avoid circular imports with the botdetect package.
type UAParser func(ua string) (browser, brVersion, os, deviceType string, isBot bool)

var (
	uaParserMu sync.RWMutex
	uaParser   UAParser
)

// SetUAParser registers a User-Agent parser function.
// Called once at startup from the main package after importing botdetect.
func SetUAParser(parser UAParser) {
	uaParserMu.Lock()
	defer uaParserMu.Unlock()
	uaParser = parser
}

func getUAParser() UAParser {
	uaParserMu.RLock()
	defer uaParserMu.RUnlock()
	return uaParser
}

// Event represents a WAF event for logging and storage.
type Event struct {
	ID         string        `json:"id"`
	Timestamp  time.Time     `json:"timestamp"`
	RequestID  string        `json:"request_id"`
	ClientIP   string        `json:"client_ip"`
	Method     string        `json:"method"`
	Path       string        `json:"path"`
	Query      string        `json:"query"`
	Action     Action        `json:"action"`
	Score      int           `json:"score"`
	Findings   []Finding     `json:"findings"`
	Duration   time.Duration `json:"duration_ns"`
	StatusCode int           `json:"status_code"`
	UserAgent  string        `json:"user_agent"`

	// Parsed User-Agent fields (populated by NewEvent)
	Browser    string `json:"browser"`
	BrVersion  string `json:"browser_version"`
	OS         string `json:"os"`
	DeviceType string `json:"device_type"`
	IsBot      bool   `json:"is_bot"`

	// Request metadata
	ContentType string `json:"content_type,omitempty"`
	Referer     string `json:"referer,omitempty"`
	Host        string `json:"host,omitempty"`
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

	ev := Event{
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

	// Parse User-Agent into structured fields
	if parser := getUAParser(); parser != nil && userAgent != "" {
		ev.Browser, ev.BrVersion, ev.OS, ev.DeviceType, ev.IsBot = parser(userAgent)
	}

	// Extract additional request metadata
	if vals, ok := ctx.Headers["Content-Type"]; ok && len(vals) > 0 {
		ev.ContentType = vals[0]
	}
	if vals, ok := ctx.Headers["Referer"]; ok && len(vals) > 0 {
		ev.Referer = vals[0]
	}
	if ctx.Request != nil {
		ev.Host = ctx.Request.Host
	}

	return ev
}
