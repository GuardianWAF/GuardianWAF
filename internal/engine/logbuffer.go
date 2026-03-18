package engine

import (
	"fmt"
	"sync"
	"time"
)

// LogEntry represents a single log message.
type LogEntry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

// LogBuffer is a thread-safe ring buffer for capturing log messages.
type LogBuffer struct {
	mu      sync.RWMutex
	entries []LogEntry
	maxSize int
	pos     int
	full    bool
}

// NewLogBuffer creates a log buffer with the given max entries.
func NewLogBuffer(maxSize int) *LogBuffer {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &LogBuffer{
		entries: make([]LogEntry, maxSize),
		maxSize: maxSize,
	}
}

// Add appends a log entry to the buffer.
func (lb *LogBuffer) Add(level, message string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.entries[lb.pos] = LogEntry{
		Time:    time.Now(),
		Level:   level,
		Message: message,
	}
	lb.pos = (lb.pos + 1) % lb.maxSize
	if lb.pos == 0 {
		lb.full = true
	}
}

// Info logs an info message.
func (lb *LogBuffer) Info(msg string) {
	lb.Add("info", msg)
}

// Warn logs a warning message.
func (lb *LogBuffer) Warn(msg string) {
	lb.Add("warn", msg)
}

// Error(msg string) logs an error message.
func (lb *LogBuffer) Error(msg string) {
	lb.Add("error", msg)
}

// Infof logs a formatted info message.
func (lb *LogBuffer) Infof(format string, args ...any) {
	lb.Add("info", fmt.Sprintf(format, args...))
}

// Warnf logs a formatted warning message.
func (lb *LogBuffer) Warnf(format string, args ...any) {
	lb.Add("warn", fmt.Sprintf(format, args...))
}

// Errorf logs a formatted error message.
func (lb *LogBuffer) Errorf(format string, args ...any) {
	lb.Add("error", fmt.Sprintf(format, args...))
}

// Recent returns the most recent N log entries in reverse chronological order.
func (lb *LogBuffer) Recent(n int) []LogEntry {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	total := lb.pos
	if lb.full {
		total = lb.maxSize
	}
	if n <= 0 || n > total {
		n = total
	}

	result := make([]LogEntry, 0, n)

	// Read in reverse from current position
	for i := range n {
		idx := (lb.pos - 1 - i + lb.maxSize) % lb.maxSize
		entry := lb.entries[idx]
		if entry.Time.IsZero() {
			break
		}
		result = append(result, entry)
	}

	return result
}

// Len returns the number of entries in the buffer.
func (lb *LogBuffer) Len() int {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	if lb.full {
		return lb.maxSize
	}
	return lb.pos
}
