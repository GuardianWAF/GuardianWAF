package events

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestPersistentMemoryStore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	ps, err := NewPersistentMemoryStore(100, path)
	if err != nil {
		t.Fatal(err)
	}

	// Store some events
	for i := range 5 {
		ps.Store(engine.Event{ID: string(rune('A' + i)), Score: i * 10})
	}
	ps.Close()

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("persistence file should exist")
	}

	// Reload from file
	ps2, err := NewPersistentMemoryStore(100, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ps2.Close()

	recent, err := ps2.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 5 {
		t.Fatalf("expected 5 events, got %d", len(recent))
	}
	// Most recent first
	if recent[0].ID != "E" {
		t.Errorf("first event ID = %q, want %q", recent[0].ID, "E")
	}
}

func TestPersistentMemoryStore_Truncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	// Store 10 events with capacity 5
	ps, _ := NewPersistentMemoryStore(5, path)
	for i := range 10 {
		ps.Store(engine.Event{ID: string(rune('A' + i))})
	}
	ps.Close()

	// Reload — only last 5 should be present
	ps2, _ := NewPersistentMemoryStore(5, path)
	defer ps2.Close()

	recent, _ := ps2.Recent(10)
	if len(recent) != 5 {
		t.Fatalf("expected 5 events, got %d", len(recent))
	}
	if recent[0].ID != "J" {
		t.Errorf("most recent = %q, want %q", recent[0].ID, "J")
	}
	if recent[4].ID != "F" {
		t.Errorf("oldest = %q, want %q", recent[4].ID, "F")
	}
}

func TestPersistentMemoryStore_NoPath(t *testing.T) {
	ps, err := NewPersistentMemoryStore(10, "")
	if err != nil {
		t.Fatal(err)
	}
	ps.Store(engine.Event{ID: "test"})
	ps.Close()

	recent, _ := ps.Recent(1)
	if len(recent) != 1 || recent[0].ID != "test" {
		t.Error("should work without file path")
	}
}
