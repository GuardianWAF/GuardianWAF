package events

import (
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// EventStore is the interface for event persistence.
type EventStore interface {
	Store(event engine.Event) error
	Query(filter EventFilter) ([]engine.Event, int, error) // events, total count, error
	Get(id string) (*engine.Event, error)
	Recent(n int) ([]engine.Event, error)
	Count(filter EventFilter) (int, error)
	Close() error
}

// DropReporter is implemented by stores that can report events dropped after
// they were accepted for storage or could not be accepted because buffers were full.
type DropReporter interface {
	DroppedEvents() int64
}

// EventFilter specifies criteria for querying events.
type EventFilter struct {
	Limit       int
	Offset      int
	Since       time.Time
	Until       time.Time
	Action      string // "", "blocked", "logged", "passed"
	ClientIP    string
	RuleID      string
	MinScore    int
	Path        string // prefix match
	SortBy      string // "timestamp", "score"
	SortOrder   string // "asc", "desc"
	CountryCode string // ISO country code filter
	TenantID    string // restrict to a single tenant's events (multi-tenant isolation)
}
