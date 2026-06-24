package engine

import (
	"net"
	"net/http"
)

// EventStorer is the interface for event persistence.
// This is defined in the engine package to avoid circular imports with the events package.
// The events.MemoryStore and events.FileStore types satisfy this interface.
type EventStorer interface {
	Store(event Event) error
	Close() error
}

// EventPublisher is the interface for event publish/subscribe.
// The events.EventBus type satisfies this interface.
type EventPublisher interface {
	Subscribe(ch chan<- Event)
	Publish(event Event)
	Close()
}

// Stats holds runtime statistics for the engine.
type Stats struct {
	TotalRequests      int64
	BlockedRequests    int64
	ChallengedRequests int64
	LoggedRequests     int64
	PassedRequests     int64
	EventStoreErrors   int64
	AvgLatencyUs       int64 // average latency in microseconds
	LatencySumUs       int64
	LatencyBuckets     []LatencyBucket
	LayerTiming        []LayerTimingStats
	GeoIPReady         bool
	GeoIPRanges        int64
}

// LatencyBucket describes one cumulative request latency histogram bucket.
type LatencyBucket struct {
	UpperBoundMicros int64
	Count            int64
}

// LayerTimingStats holds cumulative runtime statistics for one pipeline layer.
type LayerTimingStats struct {
	Layer          string
	Count          int64
	DurationSumUs  int64
	LatencyBuckets []LatencyBucket
}

// PipelineLayerInfo describes one layer in the active engine pipeline.
type PipelineLayerInfo struct {
	Name  string `json:"name"`
	Order int    `json:"order"`
}

// ChallengeChecker is the interface for the JS challenge service.
// Implemented by challenge.Service to avoid circular imports.
type ChallengeChecker interface {
	HasValidCookie(r *http.Request, clientIP net.IP) bool
	ServeChallengePage(w http.ResponseWriter, r *http.Request)
}

// AccessLogFunc is called for every request with structured access log data.
type AccessLogFunc func(entry AccessLogEntry)

// AccessLogEntry holds structured access log data for a single request.
type AccessLogEntry struct {
	Timestamp  string `json:"timestamp"`
	ClientIP   string `json:"client_ip"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Action     string `json:"action"`
	Score      int    `json:"score"`
	Duration   string `json:"duration_us"`
	UserAgent  string `json:"user_agent"`
	Findings   int    `json:"findings"`
	RequestID  string `json:"request_id"`
	TenantID   string `json:"tenant_id,omitempty"`
}
