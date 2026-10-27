package events

import (
	"bufio"
	"bytes"
	"encoding/json"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStoreSnapshotsFindingsBeforeDelayedWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fs := &FileStore{file: f, writer: bufio.NewWriter(f), ch: make(chan engine.Event, 4), done: make(chan struct{}), filePath: path, maxSize: defaultMaxSize}
	control := engine.Event{ID: "control", Findings: []engine.Finding{{Description: "control"}}}
	input := engine.Event{ID: "mutable", Findings: []engine.Finding{{Description: "accepted"}}}
	if err := fs.Store(control); err != nil {
		t.Fatal(err)
	}
	if err := fs.Store(input); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	go func() { <-release; fs.writeLoop() }()
	input.Findings[0].Description = "caller changed"
	close(release) // Force the consumer to start only after the caller mutation.
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		ID       string `json:"id"`
		Findings []struct {
			Description string `json:"description"`
		} `json:"findings"`
	}
	var rows []row
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var ev row
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, ev)
	}
	if len(rows) != 2 || rows[0].Findings[0].Description != "control" {
		t.Fatal("unaffected control failed", rows)
	}
	t.Log("CONTROL: unchanged event persisted correctly")
	t.Logf("EXPECTED: accepted; ACTUAL: %s", rows[1].Findings[0].Description)
	if rows[1].Findings[0].Description != "accepted" {
		t.Fatal("PROBLEM CONFIRMED")
	}
	t.Log("FIX VERIFIED")
}

func TestFileStoreSnapshotsFindingsBeforeDelayedWriteEdges(t *testing.T) {
	for _, findings := range [][]engine.Finding{nil, {}, {{Description: "one"}, {Description: "two"}}} {
		path := filepath.Join(t.TempDir(), "events.jsonl")
		fs, err := NewFileStore(path, defaultMaxSize)
		if err != nil {
			t.Fatal(err)
		}
		if err = fs.Store(engine.Event{ID: "edge", Findings: findings}); err != nil {
			t.Fatal(err)
		}
		if err = fs.Close(); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Findings []struct {
				Description string `json:"description"`
			} `json:"findings"`
		}
		if err = json.Unmarshal(bytes.TrimSpace(raw), &got); err != nil {
			t.Fatal(err)
		}
		if len(got.Findings) != len(findings) {
			t.Fatalf("findings length got %d want %d", len(got.Findings), len(findings))
		}
		for i := range findings {
			if got.Findings[i].Description != findings[i].Description {
				t.Fatal("description changed")
			}
		}
	}
}
