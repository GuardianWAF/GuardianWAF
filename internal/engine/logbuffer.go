package engine

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

// LogEntry represents a single log message.
type LogEntry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

// LogLevel represents a log severity level.
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
)

// ParseLogLevel converts a string to a LogLevel.
func ParseLogLevel(s string) LogLevel {
	switch s {
	case "debug":
		return LogLevelDebug
	case "warn", "warning":
		return LogLevelWarn
	case "error":
		return LogLevelError
	default:
		return LogLevelInfo
	}
}

func levelToInt(level string) LogLevel {
	switch level {
	case "debug":
		return LogLevelDebug
	case "info":
		return LogLevelInfo
	case "warn":
		return LogLevelWarn
	case "error":
		return LogLevelError
	default:
		return LogLevelInfo
	}
}

// LogBuffer is a thread-safe ring buffer for capturing log messages.
type LogBuffer struct {
	mu       sync.RWMutex
	entries  []LogEntry
	maxSize  int
	pos      int
	full     bool
	minLevel LogLevel
}

// NewLogBuffer creates a log buffer with the given max entries.
func NewLogBuffer(maxSize int) *LogBuffer {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &LogBuffer{
		entries:  make([]LogEntry, maxSize),
		maxSize:  maxSize,
		minLevel: LogLevelInfo, // default: info
	}
}

// SetLevel sets the minimum log level. Messages below this level are discarded.
func (lb *LogBuffer) SetLevel(level string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.minLevel = ParseLogLevel(level)
}

// Add appends a log entry to the buffer if it meets the minimum level.
func (lb *LogBuffer) Add(level, message string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if levelToInt(level) < lb.minLevel {
		return
	}

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

// Debug logs a debug message.
func (lb *LogBuffer) Debug(msg string) {
	lb.Add("debug", msg)
}

// Debugf logs a formatted debug message.
func (lb *LogBuffer) Debugf(format string, args ...any) {
	lb.Add("debug", fmt.Sprintf(format, args...))
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

// ErrorStack logs an error message with a goroutine stack trace appended.
func (lb *LogBuffer) ErrorStack(msg string) {
	lb.Add("error", msg+"\n"+string(debug.Stack()))
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

// ErrorWithStack logs an error message with a runtime stack trace.
func (lb *LogBuffer) ErrorWithStack(msg string) {
	const depth = 32
	pcs := make([]uintptr, depth)
	n := runtime.Callers(2, pcs)
	pcs = pcs[:n]
	buf := make([]byte, 4096)
	n = runtime.Stack(buf, false)
	lb.Add("error", msg+"\n"+string(buf[:n]))
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
