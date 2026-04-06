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

// EventFilter specifies criteria for querying events.
type EventFilter struct {
	Limit       int
	Offset      int
	Since       time.Time
	Until       time.Time
	Action      string // "", "blocked", "logged", "passed"
	ClientIP    string
	MinScore    int
	Path        string // prefix match
	SortBy      string // "timestamp", "score"
	SortOrder   string // "asc", "desc"
	CountryCode string // ISO country code filter
}
