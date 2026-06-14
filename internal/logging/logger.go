// Package logging provides a structured logger for GuardianWAF.
// All internal packages should use Logger from this package instead of
// the standard library log or fmt packages for diagnostics.
package logging

import (
	"log/slog"
	"os"
)

// Logger is the project's structured logger. It should be used by all
// internal packages instead of log.Printf or fmt.Printf.
var Logger *slog.Logger

func init() {
	// Default to text handler in dev, JSON in production (when $JSON_LOG=1).
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	var handler slog.Handler = slog.NewTextHandler(os.Stdout, opts)
	if os.Getenv("JSON_LOG") == "1" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	Logger = slog.New(handler).With(slog.String("service", "guardianwaf"))
}

// NewLogger returns a logger scoped to the given component name.
// Use this instead of log.Printf or fmt.Printf for diagnostics.
func NewLogger(component string) *slog.Logger {
	return Logger.With(slog.String("component", component))
}
