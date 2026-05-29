package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

func newEventStore(cfg *config.Config) (events.EventStore, error) {
	if cfg == nil {
		return events.NewMemoryStore(1000), nil
	}
	switch cfg.Events.Storage {
	case "", "memory":
		return events.NewMemoryStore(cfg.Events.MaxEvents), nil
	case "file":
		if cfg.Events.FilePath == "" {
			return nil, fmt.Errorf("events.file_path must not be empty when events.storage is file")
		}
		if dir := filepath.Dir(cfg.Events.FilePath); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("creating event store directory %q: %w", dir, err)
			}
		}
		store, err := events.NewPersistentMemoryStore(cfg.Events.MaxEvents, cfg.Events.FilePath)
		if err != nil {
			return nil, fmt.Errorf("opening persistent event store %q: %w", cfg.Events.FilePath, err)
		}
		return store, nil
	default:
		return nil, fmt.Errorf("unsupported events.storage %q", cfg.Events.Storage)
	}
}
