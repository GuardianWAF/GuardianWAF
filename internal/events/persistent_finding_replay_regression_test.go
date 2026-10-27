package events

import (
	"encoding/json"
	"fmt"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestPersistentMemoryStoreReplaysFindingSeverities(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	ps, err := NewPersistentMemoryStore(20, path)
	if err != nil {
		t.Fatal(err)
	}
	want := []engine.Event{{ID: "plain"}, {ID: "empty", Findings: []engine.Finding{}}}
	for severity := engine.SeverityInfo; severity <= engine.SeverityCritical; severity++ {
		want = append(want, engine.Event{ID: fmt.Sprint(severity), Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Path: "/example", TenantID: "team", Score: 70, Findings: []engine.Finding{{DetectorName: "example", Category: "example", Severity: severity, Score: 70, Description: "evidence", MatchedValue: "value", Location: "body", Confidence: 0.8}}})
	}
	for _, ev := range want {
		if err := ps.Store(ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := ps.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		ps, err = NewPersistentMemoryStore(20, path)
		if err != nil {
			t.Fatal(err)
		}
		for _, ev := range want {
			actual, err := ps.Get(ev.ID)
			if err != nil || !reflect.DeepEqual(actual, &ev) {
				t.Fatalf("EXPECTED: %#v | ACTUAL: %#v err=%v", ev, actual, err)
			}
		}
		if err := ps.Close(); err != nil {
			t.Fatal(err)
		}
	}
	legacy := []byte(`{"id":"legacy","findings":[{"detector":"example","severity":3,"score":70}]}` + "\n")
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	ps, err = NewPersistentMemoryStore(20, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	ev, err := ps.Get("legacy")
	if err != nil || ev.Findings[0].Severity != engine.SeverityHigh {
		t.Fatalf("numeric compatibility: %v %v", ev, err)
	}
	var decoded engine.Event
	if err := unmarshalPersistedEvent([]byte(`{"findings":[{"severity":"invalid"}]}`), &decoded); err == nil {
		t.Fatal("invalid severity accepted")
	}
	if err := unmarshalPersistedEvent([]byte(`{"findings":[{"severity":null},{}]}`), &decoded); err != nil || len(decoded.Findings) != 2 {
		t.Fatalf("missing/null severity: %v %v", decoded, err)
	}
	data, err := json.Marshal(want[5])
	if err != nil {
		t.Fatal(err)
	}
	if err := unmarshalPersistedEvent(data, &decoded); err != nil || !reflect.DeepEqual(decoded, want[5]) {
		t.Fatalf("multiple fields: %v %v", decoded, err)
	}
}
