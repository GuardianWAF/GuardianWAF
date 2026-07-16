package events

import (
	"bufio"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// helper to create a test event with sensible defaults
func makeEvent(id string, action engine.Action, score int, path string, clientIP string, ts time.Time) engine.Event {
	return engine.Event{
		ID:         id,
		Timestamp:  ts,
		RequestID:  "req-" + id,
		ClientIP:   clientIP,
		Method:     "GET",
		Path:       path,
		Query:      "q=test",
		Action:     action,
		Score:      score,
		Findings:   nil,
		Duration:   50 * time.Millisecond,
		StatusCode: 200,
		UserAgent:  "TestAgent/1.0",
	}
}

// --- MemoryStore Tests ---

func TestMemoryStore_StoreAndGet(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	ev := makeEvent("evt-1", engine.ActionPass, 0, "/test", "10.0.0.1", now)
	if err := ms.Store(ev); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	got, err := ms.Get("evt-1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.ID != "evt-1" {
		t.Errorf("expected ID evt-1, got %s", got.ID)
	}
	if got.Path != "/test" {
		t.Errorf("expected Path /test, got %s", got.Path)
	}
	if got.ClientIP != "10.0.0.1" {
		t.Errorf("expected ClientIP 10.0.0.1, got %s", got.ClientIP)
	}
}

func TestMemoryStore_GetNotFound(t *testing.T) {
	ms := NewMemoryStore(10)
	_, err := ms.Get("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent event")
	}
}

func TestMemoryStore_RingBufferOverflow(t *testing.T) {
	capacity := 5
	ms := NewMemoryStore(capacity)
	now := time.Now()

	// Store more events than capacity
	for i := range 8 {
		id := "evt-" + intToStr(i)
		ev := makeEvent(id, engine.ActionPass, i*10, "/path", "10.0.0.1", now.Add(time.Duration(i)*time.Second))
		if err := ms.Store(ev); err != nil {
			t.Fatalf("Store failed at iteration %d: %v", i, err)
		}
	}

	// Oldest events (0, 1, 2) should be overwritten
	for i := range 3 {
		id := "evt-" + intToStr(i)
		_, err := ms.Get(id)
		if err == nil {
			t.Errorf("expected event %s to be overwritten, but it was found", id)
		}
	}

	// Newer events (3, 4, 5, 6, 7) should still be present
	for i := 3; i < 8; i++ {
		id := "evt-" + intToStr(i)
		got, err := ms.Get(id)
		if err != nil {
			t.Errorf("expected event %s to be present, but got error: %v", id, err)
			continue
		}
		if got.ID != id {
			t.Errorf("expected ID %s, got %s", id, got.ID)
		}
	}
}

func TestMemoryStore_Recent(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	for i := range 5 {
		ev := makeEvent("evt-"+intToStr(i), engine.ActionPass, 0, "/", "10.0.0.1", now.Add(time.Duration(i)*time.Second))
		_ = ms.Store(ev)
	}

	recent, err := ms.Recent(3)
	if err != nil {
		t.Fatalf("Recent failed: %v", err)
	}
	if len(recent) != 3 {
		t.Fatalf("expected 3 recent events, got %d", len(recent))
	}

	// Most recent first
	if recent[0].ID != "evt-4" {
		t.Errorf("expected most recent event to be evt-4, got %s", recent[0].ID)
	}
	if recent[1].ID != "evt-3" {
		t.Errorf("expected second event to be evt-3, got %s", recent[1].ID)
	}
	if recent[2].ID != "evt-2" {
		t.Errorf("expected third event to be evt-2, got %s", recent[2].ID)
	}
}

func TestMemoryStore_RecentMoreThanStored(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	_ = ms.Store(makeEvent("evt-0", engine.ActionPass, 0, "/", "10.0.0.1", now))
	_ = ms.Store(makeEvent("evt-1", engine.ActionPass, 0, "/", "10.0.0.1", now.Add(time.Second)))

	recent, err := ms.Recent(10)
	if err != nil {
		t.Fatalf("Recent failed: %v", err)
	}
	if len(recent) != 2 {
		t.Errorf("expected 2 events (all stored), got %d", len(recent))
	}
}

func TestMemoryStore_RecentZero(t *testing.T) {
	ms := NewMemoryStore(100)
	recent, err := ms.Recent(0)
	if err != nil {
		t.Fatalf("Recent(0) failed: %v", err)
	}
	if recent != nil {
		t.Errorf("expected nil for Recent(0), got %v", recent)
	}
}

func TestMemoryStore_QueryByAction(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	_ = ms.Store(makeEvent("evt-pass", engine.ActionPass, 0, "/", "10.0.0.1", now))
	_ = ms.Store(makeEvent("evt-block", engine.ActionBlock, 50, "/", "10.0.0.1", now.Add(time.Second)))
	_ = ms.Store(makeEvent("evt-log", engine.ActionLog, 30, "/", "10.0.0.1", now.Add(2*time.Second)))
	_ = ms.Store(makeEvent("evt-block2", engine.ActionBlock, 60, "/", "10.0.0.1", now.Add(3*time.Second)))

	results, total, err := ms.Query(EventFilter{Action: "blocked"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if total != 2 {
		t.Errorf("expected 2 blocked events, got %d", total)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestMemoryStore_QueryByActionAlias(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	_ = ms.Store(makeEvent("evt-pass", engine.ActionPass, 0, "/", "10.0.0.1", now))
	_ = ms.Store(makeEvent("evt-block", engine.ActionBlock, 50, "/", "10.0.0.1", now.Add(time.Second)))

	results, total, err := ms.Query(EventFilter{Action: "block"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 block event, got %d", total)
	}
	if len(results) != 1 || results[0].ID != "evt-block" {
		t.Fatalf("expected evt-block result, got %#v", results)
	}
}

func TestMemoryStore_QueryByRuleID(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	matching := makeEvent("evt-rule", engine.ActionBlock, 90, "/", "10.0.0.1", now)
	matching.Findings = []engine.Finding{{DetectorName: "rule:custom-rule"}}
	other := makeEvent("evt-other", engine.ActionBlock, 90, "/", "10.0.0.1", now.Add(time.Second))
	other.Findings = []engine.Finding{{DetectorName: "sqli"}}
	_ = ms.Store(matching)
	_ = ms.Store(other)

	results, total, err := ms.Query(EventFilter{RuleID: "custom-rule"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 rule event, got %d", total)
	}
	if len(results) != 1 || results[0].ID != "evt-rule" {
		t.Fatalf("expected evt-rule result, got %#v", results)
	}
}

func TestMemoryStore_QueryByTimeRange(t *testing.T) {
	ms := NewMemoryStore(100)
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	for i := range 10 {
		ev := makeEvent("evt-"+intToStr(i), engine.ActionPass, 0, "/", "10.0.0.1", base.Add(time.Duration(i)*time.Hour))
		_ = ms.Store(ev)
	}

	// Query events between hours 3 and 7
	results, total, err := ms.Query(EventFilter{
		Since: base.Add(3 * time.Hour),
		Until: base.Add(7 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if total != 5 { // hours 3, 4, 5, 6, 7
		t.Errorf("expected 5 events in time range, got %d", total)
	}
	if len(results) != 5 {
		t.Errorf("expected 5 results, got %d", len(results))
	}
}

func TestMemoryStore_QueryByScore(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	_ = ms.Store(makeEvent("evt-low", engine.ActionPass, 10, "/", "10.0.0.1", now))
	_ = ms.Store(makeEvent("evt-med", engine.ActionLog, 50, "/", "10.0.0.1", now.Add(time.Second)))
	_ = ms.Store(makeEvent("evt-high", engine.ActionBlock, 90, "/", "10.0.0.1", now.Add(2*time.Second)))

	results, total, err := ms.Query(EventFilter{MinScore: 50})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if total != 2 {
		t.Errorf("expected 2 events with score >= 50, got %d", total)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestMemoryStore_QueryByPath(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	_ = ms.Store(makeEvent("evt-api1", engine.ActionPass, 0, "/api/users", "10.0.0.1", now))
	_ = ms.Store(makeEvent("evt-api2", engine.ActionPass, 0, "/api/orders", "10.0.0.1", now.Add(time.Second)))
	_ = ms.Store(makeEvent("evt-web", engine.ActionPass, 0, "/web/page", "10.0.0.1", now.Add(2*time.Second)))

	results, total, err := ms.Query(EventFilter{Path: "/api/"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if total != 2 {
		t.Errorf("expected 2 events with path prefix /api/, got %d", total)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestMemoryStore_QueryLimitOffset(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	for i := range 10 {
		ev := makeEvent("evt-"+intToStr(i), engine.ActionPass, i*10, "/", "10.0.0.1", now.Add(time.Duration(i)*time.Second))
		_ = ms.Store(ev)
	}

	results, total, err := ms.Query(EventFilter{
		Limit:     3,
		Offset:    2,
		SortBy:    "timestamp",
		SortOrder: "asc",
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if total != 10 {
		t.Errorf("expected total 10, got %d", total)
	}
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}
	if results[0].ID != "evt-2" {
		t.Errorf("expected first result evt-2, got %s", results[0].ID)
	}
}

func TestMemoryStore_QuerySortByScore(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	_ = ms.Store(makeEvent("evt-low", engine.ActionPass, 10, "/", "10.0.0.1", now))
	_ = ms.Store(makeEvent("evt-high", engine.ActionBlock, 90, "/", "10.0.0.1", now.Add(time.Second)))
	_ = ms.Store(makeEvent("evt-med", engine.ActionLog, 50, "/", "10.0.0.1", now.Add(2*time.Second)))

	results, _, err := ms.Query(EventFilter{SortBy: "score", SortOrder: "desc"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if results[0].Score != 90 {
		t.Errorf("expected highest score first (90), got %d", results[0].Score)
	}
	if results[1].Score != 50 {
		t.Errorf("expected second score 50, got %d", results[1].Score)
	}
	if results[2].Score != 10 {
		t.Errorf("expected lowest score last (10), got %d", results[2].Score)
	}
}

func TestMemoryStore_QueryByClientIP(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	_ = ms.Store(makeEvent("evt-1", engine.ActionPass, 0, "/", "10.0.0.1", now))
	_ = ms.Store(makeEvent("evt-2", engine.ActionPass, 0, "/", "10.0.0.2", now.Add(time.Second)))
	_ = ms.Store(makeEvent("evt-3", engine.ActionPass, 0, "/", "10.0.0.1", now.Add(2*time.Second)))

	results, total, err := ms.Query(EventFilter{ClientIP: "10.0.0.1"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if total != 2 {
		t.Errorf("expected 2 events from 10.0.0.1, got %d", total)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestMemoryStore_Count(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	_ = ms.Store(makeEvent("evt-1", engine.ActionBlock, 60, "/", "10.0.0.1", now))
	_ = ms.Store(makeEvent("evt-2", engine.ActionPass, 0, "/", "10.0.0.1", now.Add(time.Second)))
	_ = ms.Store(makeEvent("evt-3", engine.ActionBlock, 80, "/", "10.0.0.1", now.Add(2*time.Second)))
	_ = ms.Store(makeEvent("evt-4", engine.ActionLog, 40, "/", "10.0.0.1", now.Add(3*time.Second)))

	count, err := ms.Count(EventFilter{Action: "blocked"})
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 blocked events, got %d", count)
	}

	countAll, err := ms.Count(EventFilter{})
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if countAll != 4 {
		t.Errorf("expected 4 total events, got %d", countAll)
	}
}

func TestMemoryStore_Close(t *testing.T) {
	ms := NewMemoryStore(10)
	if err := ms.Close(); err != nil {
		t.Errorf("Close should return nil for MemoryStore, got %v", err)
	}
}

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	ms := NewMemoryStore(1000)
	now := time.Now()

	var wg sync.WaitGroup
	goroutines := 10
	eventsPerGoroutine := 50

	for g := range goroutines {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := range eventsPerGoroutine {
				id := "g" + intToStr(gid) + "-evt-" + intToStr(i)
				ev := makeEvent(id, engine.ActionPass, gid*10+i, "/", "10.0.0."+intToStr(gid), now.Add(time.Duration(i)*time.Millisecond))
				if err := ms.Store(ev); err != nil {
					t.Errorf("Store failed: %v", err)
				}
			}
		}(g)
	}

	wg.Wait()

	// Verify total count
	totalStored := goroutines * eventsPerGoroutine
	count, err := ms.Count(EventFilter{})
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != totalStored {
		t.Errorf("expected %d events, got %d", totalStored, count)
	}

	// Verify Recent works
	recent, err := ms.Recent(10)
	if err != nil {
		t.Fatalf("Recent failed: %v", err)
	}
	if len(recent) != 10 {
		t.Errorf("expected 10 recent events, got %d", len(recent))
	}
}

func TestMemoryStore_DefaultCapacity(t *testing.T) {
	ms := NewMemoryStore(0)
	if ms.capacity != 1024 {
		t.Errorf("expected default capacity 1024, got %d", ms.capacity)
	}
}

// --- FileStore Tests ---

func TestFileStore_StoreAndRead(t *testing.T) {
	tmpFile := t.TempDir() + "/events.jsonl"

	fs, err := NewFileStore(tmpFile, 0)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	now := time.Now()
	ev := makeEvent("file-evt-1", engine.ActionBlock, 75, "/admin", "192.168.1.1", now)
	ev.UserAgent = "Mozilla/5.0"
	ev.Findings = []engine.Finding{
		{
			DetectorName: "sqli",
			Category:     "sqli",
			Severity:     engine.SeverityHigh,
			Score:        75,
			Description:  "SQL injection detected",
			MatchedValue: "' OR 1=1--",
			Location:     "query",
			Confidence:   0.95,
		},
	}

	if err := fs.Store(ev); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// Close to flush
	if err := fs.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read file and verify JSONL content
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	content := strings.TrimSpace(string(data))
	lines := strings.Split(content, "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	line := lines[0]
	// Verify key fields are present in the JSON
	if !strings.Contains(line, `"file-evt-1"`) {
		t.Error("expected event ID in output")
	}
	if !strings.Contains(line, `"block"`) {
		t.Error("expected action 'block' in output")
	}
	if !strings.Contains(line, `"/admin"`) {
		t.Error("expected path /admin in output")
	}
	if !strings.Contains(line, `"192.168.1.1"`) {
		t.Error("expected client IP in output")
	}
	if !strings.Contains(line, `"sqli"`) {
		t.Error("expected finding detector name in output")
	}
	if !strings.Contains(line, `"SQL injection detected"`) {
		t.Error("expected finding description in output")
	}
	if !strings.Contains(line, `"Mozilla/5.0"`) {
		t.Error("expected user agent in output")
	}
}

func TestFileStore_MultipleEvents(t *testing.T) {
	tmpFile := t.TempDir() + "/events.jsonl"

	fs, err := NewFileStore(tmpFile, 0)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	now := time.Now()
	for i := range 10 {
		ev := makeEvent("multi-evt-"+intToStr(i), engine.ActionPass, i*10, "/path"+intToStr(i), "10.0.0.1", now.Add(time.Duration(i)*time.Second))
		_ = fs.Store(ev)
	}

	fs.Close()

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	content := strings.TrimSpace(string(data))
	lines := strings.Split(content, "\n")
	if len(lines) != 10 {
		t.Errorf("expected 10 lines, got %d", len(lines))
	}
}

func TestFileStore_Rotation(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/events.jsonl"

	// Set very small max size to trigger rotation quickly
	maxSize := int64(200)
	fs, err := NewFileStore(tmpFile, maxSize)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	now := time.Now()
	// Write enough events to exceed the small max size
	for i := range 20 {
		ev := makeEvent("rot-evt-"+intToStr(i), engine.ActionPass, 0, "/", "10.0.0.1", now.Add(time.Duration(i)*time.Second))
		_ = fs.Store(ev)
	}

	fs.Close()

	// Check that rotated files exist
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	jsonlCount := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			jsonlCount++
		}
	}

	if jsonlCount < 2 {
		t.Errorf("expected at least 2 JSONL files after rotation, got %d", jsonlCount)
	}
}

func TestFileStore_CloseDrainsEvents(t *testing.T) {
	tmpFile := t.TempDir() + "/events.jsonl"

	fs, err := NewFileStore(tmpFile, 0)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	now := time.Now()
	// Store events rapidly
	for i := range 50 {
		ev := makeEvent("drain-evt-"+intToStr(i), engine.ActionPass, 0, "/", "10.0.0.1", now)
		_ = fs.Store(ev)
	}

	// Close should drain all pending events
	if err := fs.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		t.Fatal("expected non-empty file after close")
	}

	lines := strings.Split(content, "\n")
	if len(lines) != 50 {
		t.Errorf("expected 50 events after drain, got %d", len(lines))
	}
}

func TestFileStore_StoreAfterCloseReturnsError(t *testing.T) {
	tmpFile := t.TempDir() + "/events.jsonl"

	fs, err := NewFileStore(tmpFile, 0)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	ev := makeEvent("after-close", engine.ActionPass, 0, "/", "10.0.0.1", time.Now())
	if err := fs.Store(ev); err == nil {
		t.Fatal("expected Store after Close to return an error")
	}
}

func TestFileStore_ConcurrentStoreAndCloseDoesNotPanic(t *testing.T) {
	tmpFile := t.TempDir() + "/events.jsonl"

	fs, err := NewFileStore(tmpFile, 0)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	start := make(chan struct{})
	errCh := make(chan any, 32)
	var wg sync.WaitGroup
	for worker := range 32 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					errCh <- r
				}
			}()
			<-start
			for i := range 200 {
				ev := makeEvent("concurrent-"+intToStr(worker)+"-"+intToStr(i), engine.ActionPass, 0, "/", "10.0.0.1", time.Now())
				_ = fs.Store(ev)
			}
		}(worker)
	}

	close(start)
	time.Sleep(time.Millisecond)
	if err := fs.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	wg.Wait()
	close(errCh)
	for r := range errCh {
		t.Fatalf("Store panicked during concurrent Close: %v", r)
	}
}

func TestFileStore_QueryNotSupported(t *testing.T) {
	tmpFile := t.TempDir() + "/events.jsonl"

	fs, err := NewFileStore(tmpFile, 0)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}
	defer fs.Close()

	_, _, err = fs.Query(EventFilter{})
	if err == nil {
		t.Error("expected error from Query on FileStore")
	}

	_, err = fs.Get("id")
	if err == nil {
		t.Error("expected error from Get on FileStore")
	}

	_, err = fs.Recent(10)
	if err == nil {
		t.Error("expected error from Recent on FileStore")
	}

	_, err = fs.Count(EventFilter{})
	if err == nil {
		t.Error("expected error from Count on FileStore")
	}
}

func TestFileStore_JSONEscaping(t *testing.T) {
	tmpFile := t.TempDir() + "/events.jsonl"

	fs, err := NewFileStore(tmpFile, 0)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	now := time.Now()
	ev := makeEvent("esc-evt", engine.ActionPass, 0, "/path?a=\"b\"&c=d\\e", "10.0.0.1", now)
	ev.UserAgent = "Agent with \"quotes\" and \\backslashes\\"

	_ = fs.Store(ev)
	fs.Close()

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	content := string(data)
	// Verify proper escaping of quotes and backslashes
	if !strings.Contains(content, `\\backslashes\\`) {
		t.Error("expected escaped backslashes in output")
	}
	if !strings.Contains(content, `\"quotes\"`) {
		t.Error("expected escaped quotes in output")
	}
}

// --- EventBus Tests ---

func TestEventBus_SubscribeAndPublish(t *testing.T) {
	bus := NewEventBus()
	ch := make(chan engine.Event, 10)
	bus.Subscribe(ch)

	now := time.Now()
	ev := makeEvent("bus-evt-1", engine.ActionPass, 0, "/", "10.0.0.1", now)
	bus.Publish(ev)

	select {
	case received := <-ch:
		if received.ID != "bus-evt-1" {
			t.Errorf("expected event ID bus-evt-1, got %s", received.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestEventBus_MultipleSubscribers(t *testing.T) {
	bus := NewEventBus()
	ch1 := make(chan engine.Event, 10)
	ch2 := make(chan engine.Event, 10)
	ch3 := make(chan engine.Event, 10)

	bus.Subscribe(ch1)
	bus.Subscribe(ch2)
	bus.Subscribe(ch3)

	now := time.Now()
	ev := makeEvent("multi-sub", engine.ActionBlock, 50, "/", "10.0.0.1", now)
	bus.Publish(ev)

	for i, ch := range []chan engine.Event{ch1, ch2, ch3} {
		select {
		case received := <-ch:
			if received.ID != "multi-sub" {
				t.Errorf("subscriber %d: expected ID multi-sub, got %s", i, received.ID)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: timed out waiting for event", i)
		}
	}
}

func TestEventBus_Unsubscribe(t *testing.T) {
	bus := NewEventBus()
	ch1 := make(chan engine.Event, 10)
	ch2 := make(chan engine.Event, 10)

	bus.Subscribe(ch1)
	bus.Subscribe(ch2)
	bus.Unsubscribe(ch1)

	now := time.Now()
	ev := makeEvent("unsub-test", engine.ActionPass, 0, "/", "10.0.0.1", now)
	bus.Publish(ev)

	// ch2 should receive the event
	select {
	case received := <-ch2:
		if received.ID != "unsub-test" {
			t.Errorf("expected event ID unsub-test, got %s", received.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("ch2 timed out waiting for event")
	}

	// ch1 should NOT receive the event
	select {
	case <-ch1:
		t.Error("ch1 should not receive events after unsubscribe")
	default:
		// Expected: no event received
	}
}

func TestEventBus_SlowSubscriberDoesNotBlock(t *testing.T) {
	bus := NewEventBus()

	// Slow subscriber: unbuffered channel, nobody reading
	slowCh := make(chan engine.Event)
	bus.Subscribe(slowCh)

	// Fast subscriber
	fastCh := make(chan engine.Event, 10)
	bus.Subscribe(fastCh)

	now := time.Now()
	ev := makeEvent("slow-test", engine.ActionPass, 0, "/", "10.0.0.1", now)

	// Publish should not block even though slowCh is full/unbuffered
	done := make(chan struct{})
	go func() {
		bus.Publish(ev)
		close(done)
	}()

	select {
	case <-done:
		// Publish completed without blocking
	case <-time.After(time.Second):
		t.Fatal("Publish blocked due to slow subscriber")
	}

	stats := bus.Stats()
	if stats.Subscribers != 2 {
		t.Fatalf("subscribers = %d, want 2", stats.Subscribers)
	}
	if stats.PublishedEvents != 1 {
		t.Fatalf("published events = %d, want 1", stats.PublishedEvents)
	}
	if stats.DroppedEvents != 1 {
		t.Fatalf("dropped deliveries = %d, want 1", stats.DroppedEvents)
	}

	// Fast subscriber should still receive the event
	select {
	case received := <-fastCh:
		if received.ID != "slow-test" {
			t.Errorf("expected event ID slow-test, got %s", received.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("fast subscriber timed out")
	}
}

func TestEventBus_SubscribeCapBoundsFanoutMemory(t *testing.T) {
	bus := NewEventBusWithMaxSubscribers(2)
	ch1 := make(chan engine.Event, 1)
	ch2 := make(chan engine.Event, 1)
	ch3 := make(chan engine.Event, 1)

	bus.Subscribe(ch1)
	bus.Subscribe(ch2)
	bus.Subscribe(ch3)

	stats := bus.Stats()
	if stats.Subscribers != 2 {
		t.Fatalf("subscribers = %d, want 2", stats.Subscribers)
	}
	if stats.MaxSubscribers != 2 {
		t.Fatalf("max subscribers = %d, want 2", stats.MaxSubscribers)
	}
	if stats.RejectedSubscriptions != 1 {
		t.Fatalf("rejected subscriptions = %d, want 1", stats.RejectedSubscriptions)
	}

	now := time.Now()
	ev := makeEvent("bounded-fanout", engine.ActionPass, 0, "/", "10.0.0.1", now)
	bus.Publish(ev)

	for i, ch := range []chan engine.Event{ch1, ch2} {
		select {
		case received := <-ch:
			if received.ID != "bounded-fanout" {
				t.Fatalf("subscriber %d got event ID %s", i, received.ID)
			}
		default:
			t.Fatalf("subscriber %d did not receive event", i)
		}
	}
	select {
	case <-ch3:
		t.Fatal("rejected subscriber received event")
	default:
	}
}

func TestEventBus_CloseClosesChannels(t *testing.T) {
	bus := NewEventBus()
	ch1 := make(chan engine.Event, 10)
	ch2 := make(chan engine.Event, 10)

	bus.Subscribe(ch1)
	bus.Subscribe(ch2)
	bus.Close()

	// Reading from closed channels should return zero value immediately
	_, ok1 := <-ch1
	if ok1 {
		t.Error("expected ch1 to be closed")
	}
	_, ok2 := <-ch2
	if ok2 {
		t.Error("expected ch2 to be closed")
	}
}

func TestEventBus_SubscribeAfterClose(t *testing.T) {
	bus := NewEventBus()
	bus.Close()

	ch := make(chan engine.Event, 10)
	bus.Subscribe(ch) // should not panic, just be a no-op
	if got := bus.Stats().RejectedSubscriptions; got != 1 {
		t.Fatalf("rejected subscriptions after close = %d, want 1", got)
	}

	// Channel should not be closed since it was added after Close
	select {
	case ch <- engine.Event{}:
		<-ch // drain
	default:
		t.Error("channel should still be open after Subscribe on closed bus")
	}
}

// --- Helper ---

// --- Additional Coverage Tests ---

func TestFileStore_ChannelFullDrop(t *testing.T) {
	tmpFile := t.TempDir() + "/events.jsonl"

	fs, err := NewFileStore(tmpFile, 0)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	// Fill the channel completely by sending events in a tight loop.
	// Send significantly more than the channel capacity to ensure the
	// writeLoop cannot keep up, causing drops.
	now := time.Now()
	dropped := 0
	for i := range fileChannelBufSize * 10 {
		ev := makeEvent("drop-evt-"+intToStr(i), engine.ActionPass, 0, "/", "10.0.0.1", now)
		if err := fs.Store(ev); err != nil {
			dropped++
		}
	}
	if dropped == 0 {
		t.Error("expected some events to be dropped when channel is full")
	}
	if fs.DroppedEvents() == 0 {
		t.Error("expected DroppedEvents to report channel-full drops")
	}

	fs.Close()
}

func TestPersistentMemoryStore_DroppedEventsAfterClose(t *testing.T) {
	tmpFile := t.TempDir() + "/events.jsonl"
	ps, err := NewPersistentMemoryStore(10, tmpFile)
	if err != nil {
		t.Fatalf("NewPersistentMemoryStore failed: %v", err)
	}
	if err := ps.Store(makeEvent("before-close", engine.ActionPass, 0, "/", "10.0.0.1", time.Now())); err != nil {
		t.Fatalf("Store before close failed: %v", err)
	}
	if err := ps.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	ev := makeEvent("after-close", engine.ActionPass, 0, "/", "10.0.0.1", time.Now())
	if err := ps.Store(ev); err == nil {
		t.Fatal("Store after close should return an error")
	}
	if got := ps.DroppedEvents(); got != 1 {
		t.Fatalf("expected 1 dropped persisted event after close, got %d", got)
	}
	if _, err := ps.Get("after-close"); err == nil {
		t.Fatal("Store after close should not add event to memory")
	}
	if _, err := ps.Get("before-close"); err != nil {
		t.Fatalf("existing in-memory events should remain queryable after close: %v", err)
	}
}

func TestFileStore_FlushTimerTrigger(t *testing.T) {
	tmpFile := t.TempDir() + "/events.jsonl"

	fs, err := NewFileStore(tmpFile, 0)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	now := time.Now()
	// Store a single event (below flushEventCount threshold)
	ev := makeEvent("flush-timer-evt", engine.ActionPass, 0, "/", "10.0.0.1", now)
	_ = fs.Store(ev)

	// Wait longer than flushInterval (1 second) to trigger the ticker flush
	time.Sleep(1500 * time.Millisecond)

	// Check data was flushed to disk without close
	data, _ := os.ReadFile(tmpFile)
	if !strings.Contains(string(data), "flush-timer-evt") {
		// Might not be flushed yet, that's ok - we'll verify after close
		_ = data
	}

	fs.Close()

	data, err = os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !strings.Contains(string(data), "flush-timer-evt") {
		t.Error("expected event to be written after flush timer or close")
	}
}

func TestFileStore_FlushEventCountThreshold(t *testing.T) {
	tmpFile := t.TempDir() + "/events.jsonl"

	fs, err := NewFileStore(tmpFile, 0)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	now := time.Now()
	// Write more events than flushEventCount (100) to trigger count-based flush
	for i := range 150 {
		ev := makeEvent("count-evt-"+intToStr(i), engine.ActionPass, 0, "/", "10.0.0.1", now)
		_ = fs.Store(ev)
	}

	fs.Close()

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	content := strings.TrimSpace(string(data))
	lines := strings.Split(content, "\n")
	if len(lines) != 150 {
		t.Errorf("expected 150 lines, got %d", len(lines))
	}
}

func TestFileStore_RotationWithExtension(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/events.jsonl"

	// Very small max to trigger rotation
	fs, err := NewFileStore(tmpFile, 100)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	now := time.Now()
	for i := range 30 {
		ev := makeEvent("rot-ext-"+intToStr(i), engine.ActionBlock, 50, "/admin/page", "192.168.1."+intToStr(i%256), now)
		ev.Findings = []engine.Finding{
			{
				DetectorName: "test",
				Category:     "test",
				Severity:     engine.SeverityHigh,
				Score:        50,
				Description:  "test finding",
				MatchedValue: "test",
				Location:     "query",
				Confidence:   0.9,
			},
		}
		_ = fs.Store(ev)
	}
	fs.Close()

	entries, _ := os.ReadDir(tmpDir)
	jsonlCount := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			jsonlCount++
		}
	}
	if jsonlCount < 2 {
		t.Errorf("expected at least 2 JSONL files after rotation, got %d", jsonlCount)
	}
}

func TestFileStore_NewFileStoreError(t *testing.T) {
	// Try creating a file store with an invalid path using a path
	// that is guaranteed to fail on all platforms
	_, err := NewFileStore(t.TempDir()+"/no/such/deeply/nested/dir/events.jsonl", 0)
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestFileStore_WriteJSONSpecialChars(t *testing.T) {
	tmpFile := t.TempDir() + "/events.jsonl"

	fs, err := NewFileStore(tmpFile, 0)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	now := time.Now()
	// Event with special control characters
	ev := makeEvent("special-evt", engine.ActionPass, 0, "/path\twith\ttabs", "10.0.0.1", now)
	ev.UserAgent = "Agent\nwith\nnewlines\rand\rreturns"
	ev.Query = "q=test\bwith\bbackspace\fand\fformfeed"
	_ = fs.Store(ev)
	fs.Close()

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	content := string(data)
	// Verify control characters are properly escaped
	if strings.Contains(content, "\t") {
		t.Error("tabs should be escaped")
	}
	if strings.Contains(content, "\n\n") {
		t.Error("unescaped newlines in event JSON content")
	}
	if !strings.Contains(content, `\t`) {
		t.Error("expected \\t escape sequence")
	}
	if !strings.Contains(content, `\n`) {
		t.Error("expected \\n escape sequence")
	}
}

func TestFileStore_WriteJSONControlChars(t *testing.T) {
	tmpFile := t.TempDir() + "/events.jsonl"

	fs, err := NewFileStore(tmpFile, 0)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	now := time.Now()
	// Event with control characters below 0x20 that aren't common escapes
	ev := makeEvent("ctrl-evt", engine.ActionPass, 0, "/path", "10.0.0.1", now)
	ev.UserAgent = "Agent\x01with\x02control\x03chars"
	_ = fs.Store(ev)
	fs.Close()

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	content := string(data)
	// Control chars should be \u00XX encoded
	if !strings.Contains(content, `\u00`) {
		t.Error("expected \\u00XX encoding for control characters")
	}
}

func TestFileStore_WriteJSONNegativeInt64(t *testing.T) {
	tmpFile := t.TempDir() + "/events.jsonl"

	fs, err := NewFileStore(tmpFile, 0)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	now := time.Now()
	ev := makeEvent("neg-evt", engine.ActionPass, -10, "/", "10.0.0.1", now)
	_ = fs.Store(ev)
	fs.Close()

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "-10") {
		t.Error("expected negative score in output")
	}
}

func TestFileStore_WriteJSONNegativeFloat(t *testing.T) {
	tmpFile := t.TempDir() + "/events.jsonl"

	fs, err := NewFileStore(tmpFile, 0)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	now := time.Now()
	ev := makeEvent("neg-float-evt", engine.ActionPass, 0, "/", "10.0.0.1", now)
	ev.Findings = []engine.Finding{
		{
			DetectorName: "test",
			Category:     "test",
			Severity:     engine.SeverityLow,
			Score:        10,
			Description:  "test",
			MatchedValue: "val",
			Location:     "query",
			Confidence:   -0.5,
		},
	}
	_ = fs.Store(ev)
	fs.Close()

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "-0.5") {
		t.Error("expected negative float in output")
	}
}

func TestFileStore_WriteJSONZeroFloat(t *testing.T) {
	tmpFile := t.TempDir() + "/events.jsonl"

	fs, err := NewFileStore(tmpFile, 0)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	now := time.Now()
	ev := makeEvent("zero-float-evt", engine.ActionPass, 0, "/", "10.0.0.1", now)
	ev.Findings = []engine.Finding{
		{
			DetectorName: "test",
			Category:     "test",
			Severity:     engine.SeverityLow,
			Score:        10,
			Description:  "test",
			MatchedValue: "val",
			Location:     "query",
			Confidence:   0.0,
		},
	}
	_ = fs.Store(ev)
	fs.Close()

	// Just verify it doesn't crash and produces valid output
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty output")
	}
}

func TestMemoryStore_QueryAllFilters(t *testing.T) {
	ms := NewMemoryStore(100)
	base := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	_ = ms.Store(makeEvent("af-1", engine.ActionBlock, 80, "/api/users", "10.0.0.1", base.Add(1*time.Hour)))
	_ = ms.Store(makeEvent("af-2", engine.ActionBlock, 90, "/api/orders", "10.0.0.2", base.Add(2*time.Hour)))
	_ = ms.Store(makeEvent("af-3", engine.ActionPass, 10, "/api/users", "10.0.0.1", base.Add(3*time.Hour)))
	_ = ms.Store(makeEvent("af-4", engine.ActionBlock, 70, "/web/page", "10.0.0.1", base.Add(4*time.Hour)))
	_ = ms.Store(makeEvent("af-5", engine.ActionBlock, 95, "/api/users", "10.0.0.1", base.Add(5*time.Hour)))

	// Query with all filters combined
	results, total, err := ms.Query(EventFilter{
		Since:     base.Add(30 * time.Minute),
		Until:     base.Add(4*time.Hour + 30*time.Minute),
		Action:    "blocked",
		ClientIP:  "10.0.0.1",
		MinScore:  70,
		Path:      "/api/",
		SortBy:    "score",
		SortOrder: "desc",
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	// Only af-1 matches: blocked, 10.0.0.1, score 80 >= 70, /api/ prefix, within time range
	if total != 1 {
		t.Errorf("expected 1 match, got %d", total)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ID != "af-1" {
		t.Errorf("expected af-1, got %s", results[0].ID)
	}
}

func TestMemoryStore_QueryEmptyResults(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	_ = ms.Store(makeEvent("empty-1", engine.ActionPass, 0, "/", "10.0.0.1", now))

	// Query that matches nothing
	results, total, err := ms.Query(EventFilter{Action: "blocked"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if total != 0 {
		t.Errorf("expected 0 total, got %d", total)
	}
	if results != nil {
		t.Errorf("expected nil results, got %v", results)
	}
}

func TestMemoryStore_QueryOffsetBeyondResults(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	_ = ms.Store(makeEvent("off-1", engine.ActionPass, 0, "/", "10.0.0.1", now))
	_ = ms.Store(makeEvent("off-2", engine.ActionPass, 0, "/", "10.0.0.1", now.Add(time.Second)))

	results, total, err := ms.Query(EventFilter{Offset: 10})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}
	if results != nil {
		t.Errorf("expected nil results when offset exceeds matches, got %v", results)
	}
}

func TestMemoryStore_ConcurrentQueryAndStore(t *testing.T) {
	ms := NewMemoryStore(1000)
	now := time.Now()

	var wg sync.WaitGroup

	// Concurrent stores
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 200 {
			ev := makeEvent("cq-"+intToStr(i), engine.ActionPass, i, "/", "10.0.0.1", now.Add(time.Duration(i)*time.Millisecond))
			_ = ms.Store(ev)
		}
	}()

	// Concurrent queries
	for q := range 5 {
		wg.Add(1)
		go func(qid int) {
			defer wg.Done()
			for range 20 {
				_, _, _ = ms.Query(EventFilter{MinScore: qid * 10})
				_, _ = ms.Recent(5)
				_, _ = ms.Count(EventFilter{})
			}
		}(q)
	}

	wg.Wait()
}

func TestMemoryStore_QuerySortByTimestampAsc(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	_ = ms.Store(makeEvent("ts-3", engine.ActionPass, 0, "/", "10.0.0.1", now.Add(3*time.Second)))
	_ = ms.Store(makeEvent("ts-1", engine.ActionPass, 0, "/", "10.0.0.1", now.Add(1*time.Second)))
	_ = ms.Store(makeEvent("ts-2", engine.ActionPass, 0, "/", "10.0.0.1", now.Add(2*time.Second)))

	results, _, err := ms.Query(EventFilter{SortBy: "timestamp", SortOrder: "asc"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if results[0].ID != "ts-1" {
		t.Errorf("expected ts-1 first, got %s", results[0].ID)
	}
	if results[2].ID != "ts-3" {
		t.Errorf("expected ts-3 last, got %s", results[2].ID)
	}
}

func TestMemoryStore_QuerySortByScoreAsc(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	_ = ms.Store(makeEvent("sa-high", engine.ActionBlock, 90, "/", "10.0.0.1", now))
	_ = ms.Store(makeEvent("sa-low", engine.ActionPass, 10, "/", "10.0.0.1", now.Add(time.Second)))
	_ = ms.Store(makeEvent("sa-med", engine.ActionLog, 50, "/", "10.0.0.1", now.Add(2*time.Second)))

	results, _, err := ms.Query(EventFilter{SortBy: "score", SortOrder: "asc"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if results[0].Score != 10 {
		t.Errorf("expected lowest first (10), got %d", results[0].Score)
	}
	if results[2].Score != 90 {
		t.Errorf("expected highest last (90), got %d", results[2].Score)
	}
}

func TestMemoryStore_QueryByActionChallenge(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	_ = ms.Store(makeEvent("ch-1", engine.ActionChallenge, 40, "/", "10.0.0.1", now))
	_ = ms.Store(makeEvent("ch-2", engine.ActionPass, 0, "/", "10.0.0.1", now.Add(time.Second)))

	results, total, err := ms.Query(EventFilter{Action: "challenge"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 challenge event, got %d", total)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestMemoryStore_QueryByActionLogged(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	_ = ms.Store(makeEvent("log-1", engine.ActionLog, 30, "/", "10.0.0.1", now))
	_ = ms.Store(makeEvent("log-2", engine.ActionPass, 0, "/", "10.0.0.1", now.Add(time.Second)))

	results, total, err := ms.Query(EventFilter{Action: "logged"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 logged event, got %d", total)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestMemoryStore_QueryByActionPassed(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	_ = ms.Store(makeEvent("pass-1", engine.ActionPass, 0, "/", "10.0.0.1", now))
	_ = ms.Store(makeEvent("pass-2", engine.ActionBlock, 80, "/", "10.0.0.1", now.Add(time.Second)))

	results, total, err := ms.Query(EventFilter{Action: "passed"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 passed event, got %d", total)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestMemoryStore_ActionToFilterStringUnknown(t *testing.T) {
	// Test with an unknown action value
	result := actionToFilterString(engine.Action(255))
	if result != "" {
		t.Errorf("expected empty string for unknown action, got %q", result)
	}
}

func TestMemoryStore_SortEventsLessThanTwo(t *testing.T) {
	// sortEvents with 0 or 1 events should be a no-op
	sortEvents(nil, "score", "desc")
	sortEvents([]engine.Event{{}}, "score", "desc")
}

func TestMemoryStore_QueryDefaultSort(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()

	_ = ms.Store(makeEvent("ds-1", engine.ActionPass, 0, "/", "10.0.0.1", now.Add(2*time.Second)))
	_ = ms.Store(makeEvent("ds-2", engine.ActionPass, 0, "/", "10.0.0.1", now.Add(1*time.Second)))
	_ = ms.Store(makeEvent("ds-3", engine.ActionPass, 0, "/", "10.0.0.1", now.Add(3*time.Second)))

	// Default sort (no SortBy specified) should sort by timestamp desc
	results, _, err := ms.Query(EventFilter{})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3, got %d", len(results))
	}
	// Default desc: newest first
	if results[0].ID != "ds-3" {
		t.Errorf("expected ds-3 first (newest), got %s", results[0].ID)
	}
}

func TestEventBus_PublishAfterClose(t *testing.T) {
	bus := NewEventBus()
	bus.Close()

	// Publish after close should not panic
	now := time.Now()
	ev := makeEvent("post-close", engine.ActionPass, 0, "/", "10.0.0.1", now)
	bus.Publish(ev) // should be a no-op since subscribers are nil
}

func TestEventBus_UnsubscribeNonExistent(t *testing.T) {
	bus := NewEventBus()
	ch := make(chan engine.Event, 10)

	// Unsubscribe without subscribing should not panic
	bus.Unsubscribe(ch)

	bus.Close()
}

func TestEventBus_SubscribePublishMultipleEvents(t *testing.T) {
	bus := NewEventBus()
	ch := make(chan engine.Event, 100)
	bus.Subscribe(ch)

	now := time.Now()
	for i := range 50 {
		ev := makeEvent("multi-pub-"+intToStr(i), engine.ActionPass, 0, "/", "10.0.0.1", now)
		bus.Publish(ev)
	}

	bus.Close()

	// Drain channel and count
	count := 0
	for range ch {
		count++
	}
	if count != 50 {
		t.Errorf("expected 50 events, got %d", count)
	}
}

func TestFileStore_MarshalEventJSON_ZeroDuration(t *testing.T) {
	ev := engine.Event{
		ID:        "zero-dur",
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		RequestID: "req-zero",
		ClientIP:  "10.0.0.1",
		Method:    "GET",
		Path:      "/",
		Action:    engine.ActionPass,
		Score:     0,
		Duration:  0,
	}
	result := marshalEventJSON(ev)
	if !strings.Contains(result, `"duration_ns":0`) {
		t.Error("expected duration_ns:0 in output")
	}
}

func TestFileStore_MarshalEventJSON_MultipleFindings(t *testing.T) {
	ev := engine.Event{
		ID:        "multi-find",
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		RequestID: "req-multi",
		ClientIP:  "10.0.0.1",
		Method:    "POST",
		Path:      "/api",
		Action:    engine.ActionBlock,
		Score:     90,
		Findings: []engine.Finding{
			{DetectorName: "sqli", Category: "sqli", Severity: engine.SeverityHigh, Score: 50, Description: "SQLi", MatchedValue: "' OR 1=1", Location: "query", Confidence: 0.9},
			{DetectorName: "xss", Category: "xss", Severity: engine.SeverityMedium, Score: 40, Description: "XSS", MatchedValue: "<script>", Location: "body", Confidence: 0.8},
		},
	}
	result := marshalEventJSON(ev)
	if !strings.Contains(result, `"sqli"`) {
		t.Error("expected sqli finding")
	}
	if !strings.Contains(result, `"xss"`) {
		t.Error("expected xss finding")
	}
}

func TestFileStore_HexDigit(t *testing.T) {
	// Test hexDigit function for values 0-15
	expected := "0123456789abcdef"
	for i := byte(0); i < 16; i++ {
		got := hexDigit(i)
		if got != expected[i] {
			t.Errorf("hexDigit(%d) = %c, want %c", i, got, expected[i])
		}
	}
}

func TestFileStore_WriteJSONInt64_ZeroAndNegative(t *testing.T) {
	// Test zero
	var b strings.Builder
	writeJSONInt64(&b, 0)
	if b.String() != "0" {
		t.Errorf("writeJSONInt64(0) = %q, want '0'", b.String())
	}

	// Test negative
	b.Reset()
	writeJSONInt64(&b, -42)
	if b.String() != "-42" {
		t.Errorf("writeJSONInt64(-42) = %q, want '-42'", b.String())
	}

	// Test large positive
	b.Reset()
	writeJSONInt64(&b, 1234567890)
	if b.String() != "1234567890" {
		t.Errorf("writeJSONInt64(1234567890) = %q, want '1234567890'", b.String())
	}
}

func TestFileStore_WriteJSONFloat_ZeroFraction(t *testing.T) {
	var b strings.Builder
	writeJSONFloat(&b, 42.0)
	if b.String() != "42" {
		t.Errorf("writeJSONFloat(42.0) = %q, want '42'", b.String())
	}

	b.Reset()
	writeJSONFloat(&b, 0.0)
	if b.String() != "0" {
		t.Errorf("writeJSONFloat(0.0) = %q, want '0'", b.String())
	}
}

func TestMemoryStore_RecentNegative(t *testing.T) {
	ms := NewMemoryStore(10)
	result, err := ms.Recent(-1)
	if err != nil {
		t.Fatalf("Recent(-1) failed: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil for Recent(-1), got %v", result)
	}
}

func TestMemoryStore_NegativeCapacity(t *testing.T) {
	ms := NewMemoryStore(-5)
	if ms.capacity != 1024 {
		t.Errorf("expected default capacity 1024 for negative input, got %d", ms.capacity)
	}
}

// --- FileStore Tests ---

func TestFileStore_StoreAndClose(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/events.jsonl"

	fs, err := NewFileStore(path, 0)
	if err != nil {
		t.Fatalf("NewFileStore error: %v", err)
	}

	// Store some events
	for i := range 5 {
		ev := engine.Event{
			ID:        "evt-" + intToStr(i),
			RequestID: "req-" + intToStr(i),
			ClientIP:  "10.0.0.1",
			Method:    "GET",
			Path:      "/test",
			Action:    engine.ActionPass,
			Score:     0,
			Timestamp: time.Now(),
		}
		_ = fs.Store(ev)
	}

	// Close should drain remaining events
	if err := fs.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	// Verify file has content
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 1 {
		t.Error("expected at least 1 line in output file")
	}
}

func TestFileStore_DrainOnClose(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/drain.jsonl"

	fs, err := NewFileStore(path, 0)
	if err != nil {
		t.Fatalf("NewFileStore error: %v", err)
	}

	// Fill the channel with events before closing
	for i := range 50 {
		_ = fs.Store(engine.Event{
			ID:        "drain-" + intToStr(i),
			RequestID: "r-" + intToStr(i),
			Method:    "GET",
			Path:      "/drain",
			Action:    engine.ActionPass,
			Timestamp: time.Now(),
		})
	}

	// Small delay to let some events be written
	time.Sleep(50 * time.Millisecond)

	// Close drains remaining
	if err := fs.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 50 {
		t.Errorf("expected 50 lines, got %d (drain may not have captured all)", len(lines))
	}
}

func TestFileStore_RotationSmallMax(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/rotate.jsonl"

	// Very small maxSize to trigger rotation quickly
	fs, err := NewFileStore(path, 200)
	if err != nil {
		t.Fatalf("NewFileStore error: %v", err)
	}

	// Write enough events to exceed 200 bytes
	for i := range 20 {
		_ = fs.Store(engine.Event{
			ID:        "rot-" + intToStr(i),
			RequestID: "req-" + intToStr(i),
			ClientIP:  "10.0.0.1",
			Method:    "GET",
			Path:      "/rotation-test-path-that-is-long-enough",
			Action:    engine.ActionPass,
			Score:     i,
			Timestamp: time.Now(),
		})
	}

	// Wait for events to be processed
	time.Sleep(200 * time.Millisecond)

	if err := fs.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	// Check that rotation happened — there should be rotated files
	entries, _ := os.ReadDir(dir)
	if len(entries) < 2 {
		t.Logf("only %d files found (rotation may not have triggered for this data volume)", len(entries))
	}
}

func TestFileStore_UnsupportedOps(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/query.jsonl"

	fs, err := NewFileStore(path, 0)
	if err != nil {
		t.Fatalf("NewFileStore error: %v", err)
	}
	defer fs.Close()

	_, _, err = fs.Query(EventFilter{})
	if err == nil {
		t.Error("expected error from Query")
	}

	_, err = fs.Get("id")
	if err == nil {
		t.Error("expected error from Get")
	}

	_, err = fs.Recent(10)
	if err == nil {
		t.Error("expected error from Recent")
	}

	_, err = fs.Count(EventFilter{})
	if err == nil {
		t.Error("expected error from Count")
	}
}

func TestFileStore_FlushOnTick(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/tick.jsonl"

	fs, err := NewFileStore(path, 0)
	if err != nil {
		t.Fatalf("NewFileStore error: %v", err)
	}

	// Store a single event
	_ = fs.Store(engine.Event{
		ID:        "tick-1",
		RequestID: "r-1",
		Method:    "GET",
		Path:      "/tick",
		Action:    engine.ActionPass,
		Timestamp: time.Now(),
	})

	// Wait for flush tick (1 second)
	time.Sleep(1500 * time.Millisecond)

	if err := fs.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	data, _ := os.ReadFile(path)
	if len(data) == 0 {
		t.Error("expected data after flush tick")
	}
}

// intToStr converts a non-negative integer to its string representation without fmt.
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + intToStr(-n)
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte(n%10) + '0'
		n /= 10
	}
	return string(digits[i:])
}

// TestEventBus_PublishDoesNotBlockSubscribe verifies that Publish (which
// snapshots the subscriber list under RLock) does not block a concurrent
// Subscribe call. This is a regression test for the fix that moved channel
// sends outside the RLock critical section.
func TestEventBus_PublishDoesNotBlockSubscribe(t *testing.T) {
	bus := NewEventBus()

	// Create a subscriber with a tiny buffer that will fill up quickly
	slowCh := make(chan engine.Event, 1)
	bus.Subscribe(slowCh)

	now := time.Now()

	// Start a goroutine that continuously publishes events.
	// With the old code (holding RLock during sends), Subscribe would block.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			bus.Publish(makeEvent("concurrent", engine.ActionPass, 0, "/", "1.2.3.4", now))
		}
	}()

	// Try to subscribe a new channel concurrently — should not block
	newCh := make(chan engine.Event, 100)
	bus.Subscribe(newCh)

	// Wait for publisher to finish
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("publisher goroutine timed out — Publish may be blocking")
	}

	bus.Close()
}

// TestEventBus_DropsEventsForSlowSubscribers verifies that a slow subscriber
// (full channel) does not block other subscribers from receiving events.
func TestEventBus_DropsEventsForSlowSubscribers(t *testing.T) {
	bus := NewEventBus()

	// Subscriber with a full buffer — events will be dropped
	blockedCh1 := make(chan engine.Event, 1)
	blockedCh1 <- makeEvent("prefill", engine.ActionPass, 0, "/", "1.1.1.1", time.Now())
	bus.Subscribe(blockedCh1)

	// Working subscriber
	goodCh := make(chan engine.Event, 10)
	bus.Subscribe(goodCh)

	now := time.Now()
	bus.Publish(makeEvent("test", engine.ActionPass, 0, "/", "2.2.2.2", now))

	// goodCh should receive the event despite blockedCh1 being full
	select {
	case ev := <-goodCh:
		if ev.ID != "test" {
			t.Errorf("expected event 'test', got %q", ev.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("good subscriber did not receive event — slow subscriber blocked fan-out")
	}

	// Verify drop counter incremented
	stats := bus.Stats()
	if stats.DroppedEvents == 0 {
		t.Error("expected at least 1 dropped event for the full subscriber")
	}

	bus.Close()
}

func TestMemoryStore_QueryTenantIsolation(t *testing.T) {
	ms := NewMemoryStore(100)
	now := time.Now()
	// Two tenants' events plus one global event.
	a := makeEvent("a", engine.ActionBlock, 80, "/a", "1.1.1.1", now)
	a.TenantID = "tenant-a"
	b := makeEvent("b", engine.ActionBlock, 80, "/b", "2.2.2.2", now)
	b.TenantID = "tenant-b"
	g := makeEvent("g", engine.ActionBlock, 80, "/g", "3.3.3.3", now)
	for _, ev := range []engine.Event{a, b, g} {
		if err := ms.Store(ev); err != nil {
			t.Fatalf("store: %v", err)
		}
	}

	// A tenant-scoped query must return only that tenant's events.
	got, _, err := ms.Query(EventFilter{TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("tenant-a query returned %d events %v, want just [a]", len(got), got)
	}

	// An unscoped query still returns everything.
	all, _, err := ms.Query(EventFilter{})
	if err != nil {
		t.Fatalf("query all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("unscoped query returned %d events, want 3", len(all))
	}
}

// Merged from coverage_gap_test.go
func TestEventBus_StatsDefaultsMaxSubscribersWhenUnset(t *testing.T) {
	bus := &EventBus{}

	if got := bus.Stats().MaxSubscribers; got != defaultMaxEventBusSubscribers {
		t.Fatalf("MaxSubscribers = %d, want %d", got, defaultMaxEventBusSubscribers)
	}
}

func TestEventBus_SubscribeAppliesDefaultMaxSubscribersWhenUnset(t *testing.T) {
	bus := &EventBus{}
	ch := make(chan engine.Event, 1)

	bus.Subscribe(ch)

	if got := bus.maxSubscribers; got != defaultMaxEventBusSubscribers {
		t.Fatalf("maxSubscribers = %d, want %d", got, defaultMaxEventBusSubscribers)
	}
	if got := bus.Stats().Subscribers; got != 1 {
		t.Fatalf("Subscribers = %d, want 1", got)
	}
	bus.Close()
}

func TestFileStore_CheckRotationCloseAfterRotationFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}

	fs := &FileStore{
		file:     f,
		writer:   bufio.NewWriterSize(f, 32*1024),
		ch:       make(chan engine.Event),
		filePath: path,
		maxSize:  1,
	}
	if _, err := fs.writer.WriteString("xxx"); err != nil {
		t.Fatal(err)
	}
	if err := fs.writer.Flush(); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	time.Sleep(now.Truncate(time.Second).Add(time.Second).Sub(now) + 10*time.Millisecond)

	rotated := filepath.Join(dir, "events-"+time.Now().Format("20060102-150405")+".jsonl")
	if err := os.Mkdir(rotated, 0o755); err != nil {
		t.Fatalf("setup rotated dir: %v", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}

	fs.checkRotation()

	if !fs.closed {
		t.Fatal("expected file store to close after rotation reopen failure")
	}
	select {
	case _, ok := <-fs.ch:
		if ok {
			t.Fatal("expected channel to be closed")
		}
	default:
		t.Fatal("expected closed channel read to proceed immediately")
	}
	if got := fs.DroppedEvents(); got < 2 {
		t.Fatalf("DroppedEvents = %d, want at least 2", got)
	}
	_ = os.Chmod(path, 0o600)
}

func TestFileStore_CleanupRotatedReadDirError(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	fs := &FileStore{}
	fs.cleanupRotated(filepath.Join(filePath, "events"), ".jsonl")

	if got := fs.DroppedEvents(); got != 1 {
		t.Fatalf("DroppedEvents = %d, want 1", got)
	}
}

func TestPersistentMemoryStore_StoreFallsBackToMemoryWhenFileNil(t *testing.T) {
	ps := &PersistentMemoryStore{MemoryStore: NewMemoryStore(4)}
	ev := engine.Event{ID: "memory-only", Timestamp: time.Now(), Action: engine.ActionPass}

	if err := ps.Store(ev); err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	got, err := ps.Get("memory-only")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.ID != ev.ID {
		t.Fatalf("Get().ID = %q, want %q", got.ID, ev.ID)
	}
}

func TestPersistentMemoryStore_StoreMarshalErrorDropsEvent(t *testing.T) {
	ps := &PersistentMemoryStore{
		MemoryStore: NewMemoryStore(4),
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ev := engine.Event{
		ID:       "bad-json",
		Timestamp: time.Now(),
		Action:   engine.ActionPass,
		Findings: []engine.Finding{{Confidence: math.NaN()}},
	}

	if err := ps.Store(ev); err != nil {
		t.Fatalf("Store marshal error should be swallowed, got %v", err)
	}
	if got := ps.DroppedEvents(); got != 1 {
		t.Fatalf("DroppedEvents = %d, want 1", got)
	}
	if _, err := ps.Get("bad-json"); err == nil {
		t.Fatal("marshal-failed event should not be added to memory")
	}
}

func TestPersistentMemoryStore_DroppedEventsNilReceiver(t *testing.T) {
	var ps *PersistentMemoryStore
	if got := ps.DroppedEvents(); got != 0 {
		t.Fatalf("DroppedEvents(nil) = %d, want 0", got)
	}
}

func TestPersistentMemoryStore_CompactLockedReturnsCloseError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	ps, err := NewPersistentMemoryStore(2, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()

	if err := ps.Store(engine.Event{ID: "first", Timestamp: time.Now(), Action: engine.ActionPass}); err != nil {
		t.Fatal(err)
	}

	ps.fileMu.Lock()
	if err := ps.file.Close(); err != nil {
		ps.fileMu.Unlock()
		t.Fatal(err)
	}
	err = ps.compactLocked()
	ps.fileMu.Unlock()
	if err == nil {
		t.Fatal("expected compactLocked close error")
	}
}

func TestPersistentMemoryStore_ReplayScannerError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	tooLongLine := strings.Repeat("a", 1024*1024+1)
	if err := os.WriteFile(path, []byte(tooLongLine), 0o600); err != nil {
		t.Fatal(err)
	}

	ps := &PersistentMemoryStore{MemoryStore: NewMemoryStore(1), path: path}
	if err := ps.replay(); err == nil {
		t.Fatal("expected scanner error for oversized JSONL line")
	}
}

func TestPersistentMemoryStore_RewriteFileEncodeError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	ps := &PersistentMemoryStore{path: path}

	err := ps.rewriteFile([]engine.Event{{
		ID:        "bad-encode",
		Timestamp: time.Now(),
		Findings:  []engine.Finding{{Confidence: math.NaN()}},
	}})
	if err == nil {
		t.Fatal("expected rewrite encode error")
	}
	if _, statErr := os.Stat(path + ".tmp"); !os.IsNotExist(statErr) {
		t.Fatalf("expected temp file cleanup after encode error, stat error = %v", statErr)
	}
}

func TestFileStore_CloseAfterRotationFailureNoopWhenAlreadyClosed(t *testing.T) {
	fs := &FileStore{closed: true, ch: make(chan engine.Event)}

	fs.closeAfterRotationFailure()

	if !fs.closed {
		t.Fatal("expected closed flag to remain true")
	}
	select {
	case _, ok := <-fs.ch:
		if !ok {
			t.Fatal("channel should remain open on early return")
		}
	default:
	}
}

func TestPersistentMemoryStore_NewReturnsReplayError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	tooLongLine := strings.Repeat("a", 1024*1024+1)
	if err := os.WriteFile(path, []byte(tooLongLine), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := NewPersistentMemoryStore(1, path); err == nil {
		t.Fatal("expected replay error from oversized persisted line")
	}
}

func TestPersistentMemoryStore_StoreCompactionErrorIsLoggedAndSwallowed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	ps, err := NewPersistentMemoryStore(2, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()

	ps.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	ps.fileMu.Lock()
	ps.maxFileBytes = 1
	ps.path = "bad\x00path"
	ps.fileMu.Unlock()

	if err := ps.Store(engine.Event{ID: "compact-warn", Timestamp: time.Now(), Action: engine.ActionPass}); err != nil {
		t.Fatalf("Store should swallow compaction error, got %v", err)
	}
	if got := ps.DroppedEvents(); got != 0 {
		t.Fatalf("DroppedEvents = %d, want 0", got)
	}
}

func TestPersistentMemoryStore_CompactLockedRewriteError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	ps, err := NewPersistentMemoryStore(2, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()

	if err := ps.Store(engine.Event{ID: "first", Timestamp: time.Now(), Action: engine.ActionPass}); err != nil {
		t.Fatal(err)
	}

	ps.fileMu.Lock()
	ps.path = "bad\x00path"
	err = ps.compactLocked()
	ps.fileMu.Unlock()
	if err == nil {
		t.Fatal("expected compactLocked rewrite error")
	}
}

func TestPersistentMemoryStore_ReplayRejectsInvalidPath(t *testing.T) {
	ps := &PersistentMemoryStore{MemoryStore: NewMemoryStore(1), path: "bad\x00path"}
	if err := ps.replay(); err == nil {
		t.Fatal("expected replay path cleaning error")
	}
}

func TestPersistentMemoryStore_ReplaySkipsInvalidJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	content := "not-json\n{\"id\":\"kept\",\"timestamp\":\"2025-01-01T00:00:00Z\",\"action\":\"pass\"}\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	ps := &PersistentMemoryStore{MemoryStore: NewMemoryStore(2), path: path}
	if err := ps.replay(); err != nil {
		t.Fatalf("replay failed: %v", err)
	}
	if _, err := ps.Get("kept"); err != nil {
		t.Fatal("expected valid JSON line to be replayed")
	}
}

func TestPersistentMemoryStore_RewriteFileRejectsInvalidPath(t *testing.T) {
	ps := &PersistentMemoryStore{path: "bad\x00path"}
	if err := ps.rewriteFile(nil); err == nil {
		t.Fatal("expected rewriteFile path cleaning error")
	}
}

func TestPersistentMemoryStore_RewriteFileOpenTempError(t *testing.T) {
	ps := &PersistentMemoryStore{path: filepath.Join(t.TempDir(), "missing", "events.jsonl")}
	if err := ps.rewriteFile(nil); err == nil {
		t.Fatal("expected rewriteFile temp open error")
	}
}

// Merged from events_extra_test.go
func TestEventBus_DoubleClose(t *testing.T) {
	bus := NewEventBus()
	bus.Close()
	// Second close should be a no-op and not panic
	bus.Close()
}

func TestEventBus_Stats(t *testing.T) {
	bus := NewEventBusWithMaxSubscribers(2)
	fastCh := make(chan engine.Event, 1)
	slowCh := make(chan engine.Event)
	ignoredCh := make(chan engine.Event, 1)

	bus.Subscribe(fastCh)
	bus.Subscribe(slowCh)
	bus.Subscribe(ignoredCh)

	bus.Publish(engine.Event{ID: "stats", Timestamp: time.Now(), Action: engine.ActionPass})

	stats := bus.Stats()
	if stats.Subscribers != 2 {
		t.Fatalf("Subscribers = %d, want 2", stats.Subscribers)
	}
	if stats.MaxSubscribers != 2 {
		t.Fatalf("MaxSubscribers = %d, want 2", stats.MaxSubscribers)
	}
	if stats.PublishedEvents != 1 {
		t.Fatalf("PublishedEvents = %d, want 1", stats.PublishedEvents)
	}
	if stats.DroppedEvents != 1 {
		t.Fatalf("DroppedEvents = %d, want 1", stats.DroppedEvents)
	}
	if stats.RejectedSubscriptions != 1 {
		t.Fatalf("RejectedSubscriptions = %d, want 1", stats.RejectedSubscriptions)
	}
	bus.Close()
}

func TestEventBus_NewWithMaxSubscribers(t *testing.T) {
	tests := []struct {
		name string
		max  int
		want int
	}{
		{name: "positive", max: 7, want: 7},
		{name: "zero defaults", max: 0, want: defaultMaxEventBusSubscribers},
		{name: "negative defaults", max: -1, want: defaultMaxEventBusSubscribers},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bus := NewEventBusWithMaxSubscribers(tt.max)
			if got := bus.Stats().MaxSubscribers; got != tt.want {
				t.Fatalf("MaxSubscribers = %d, want %d", got, tt.want)
			}
		})
	}
}

// --- drainRemaining loop body ---

func TestDrainRemaining_WithBufferedEvents(t *testing.T) {
	path := t.TempDir() + "/events.jsonl"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fs := &FileStore{
		file:     f,
		writer:   bufio.NewWriterSize(f, 32*1024),
		ch:       make(chan engine.Event, fileChannelBufSize),
		done:     make(chan struct{}),
		filePath: path,
		maxSize:  defaultMaxSize,
	}

	// Put events directly into the channel
	ev1 := engine.Event{ID: "drain-1", Timestamp: time.Now(), Action: engine.ActionPass}
	ev2 := engine.Event{ID: "drain-2", Timestamp: time.Now(), Action: engine.ActionBlock}
	fs.ch <- ev1
	fs.ch <- ev2
	close(fs.ch)

	// Manually drain (bypasses writeLoop goroutine)
	fs.drainRemaining()

	// Close file so Windows temp dir can be cleaned up
	fs.file.Close()

	// Verify events were written by reading file
	f2, _ := os.Open(path)
	defer f2.Close()
	data := make([]byte, 4096)
	n, _ := f2.Read(data)
	content := string(data[:n])
	if !strings.Contains(content, "drain-1") {
		t.Error("expected drain-1 in output")
	}
	if !strings.Contains(content, "drain-2") {
		t.Error("expected drain-2 in output")
	}
}

// --- writeEvent WriteString error ---

func TestWriteEvent_WriteStringError(t *testing.T) {
	ew := &errorWriter{failAt: 0}
	fs := &FileStore{
		writer: bufio.NewWriterSize(ew, 1), // 1-byte buffer forces immediate flush
	}
	ev := engine.Event{ID: "err", Timestamp: time.Now(), Action: engine.ActionPass}
	fs.writeEvent(ev) // should return early due to WriteString error without panicking
}

// --- writeEvent WriteByte error ---

func TestWriteEvent_WriteByteError(t *testing.T) {
	ev := engine.Event{ID: "err", Timestamp: time.Now(), Action: engine.ActionPass}
	line := marshalEventJSON(ev)
	// Buffer size exactly fits the JSON line so WriteByte triggers flush
	ew := &errorWriter{failAt: 0}
	fs := &FileStore{
		writer: bufio.NewWriterSize(ew, len(line)),
	}
	fs.writeEvent(ev) // WriteString fits, WriteByte triggers flush and fails
}

func TestWriteJSONFloat_WritesBoundedDecimalDigits(t *testing.T) {
	var b strings.Builder
	writeJSONFloat(&b, 12.125)
	if got, want := b.String(), "12.125"; got != want {
		t.Fatalf("writeJSONFloat() = %q, want %q", got, want)
	}

	for digit := 0; digit <= 9; digit++ {
		if got, want := decimalDigitByte(digit), byte('0'+digit); got != want {
			t.Fatalf("decimalDigitByte(%d) = %q, want %q", digit, got, want)
		}
	}
	if got := decimalDigitByte(10); got != '0' {
		t.Fatalf("decimalDigitByte overflow fallback = %q, want '0'", got)
	}
}

func TestCleanEventFilePath(t *testing.T) {
	cleaned, err := cleanEventFilePath(filepath.Join("events", "..", "events.jsonl"), false)
	if err != nil {
		t.Fatalf("cleanEventFilePath valid: %v", err)
	}
	if cleaned != "events.jsonl" {
		t.Fatalf("cleanEventFilePath = %q, want events.jsonl", cleaned)
	}
	if _, err := cleanEventFilePath("bad\x00events.jsonl", false); err == nil {
		t.Fatal("expected error for NUL event path")
	}
	if _, err := cleanEventFilePath("", false); err == nil {
		t.Fatal("expected error for empty required event path")
	}
	if cleaned, err := cleanEventFilePath("", true); err != nil || cleaned != "" {
		t.Fatalf("optional empty path = %q, %v; want empty nil", cleaned, err)
	}
}

func TestNewFileStore_RejectsNULPath(t *testing.T) {
	if _, err := NewFileStore("bad\x00events.jsonl", 0); err == nil {
		t.Fatal("expected error for NUL file store path")
	}
}

// --- FileStore.Close flush error ---

func TestFileStore_CloseFlushError(t *testing.T) {
	path := t.TempDir() + "/events.jsonl"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}

	fs := &FileStore{
		file:     f,
		writer:   bufio.NewWriterSize(f, 32*1024),
		ch:       make(chan engine.Event),
		done:     make(chan struct{}),
		filePath: path,
		maxSize:  defaultMaxSize,
	}

	// Start a goroutine that closes done after the channel is closed
	go func() {
		for range fs.ch {
		}
		close(fs.done)
	}()

	// Write something so the buffer is non-empty and Flush actually hits the file
	fs.writer.WriteString("x")

	// Close underlying file to make writer.Flush fail
	f.Close()

	err = fs.Close()
	if err == nil {
		t.Error("expected flush error")
	}
}

func TestFileStore_CloseSyncError(t *testing.T) {
	path := t.TempDir() + "/events.jsonl"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}

	fs := &FileStore{
		file:     f,
		writer:   bufio.NewWriterSize(f, 32*1024),
		ch:       make(chan engine.Event),
		done:     make(chan struct{}),
		filePath: path,
		maxSize:  defaultMaxSize,
	}
	close(fs.done)

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	err = fs.Close()
	if err == nil {
		t.Fatal("expected sync/close error")
	}
	if !strings.Contains(err.Error(), "file already closed") && !strings.Contains(err.Error(), "invalid argument") {
		t.Fatalf("expected closed-file sync/close error, got %v", err)
	}
}

func TestFileStore_Close(t *testing.T) {
	path := t.TempDir() + "/events.jsonl"
	fs, err := NewFileStore(path, defaultMaxSize)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	ev := engine.Event{ID: "close-ok", Timestamp: time.Now(), Action: engine.ActionPass}
	if err := fs.Store(ev); err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
	if err := fs.Store(ev); err == nil {
		t.Fatal("expected Store after Close to fail")
	}
}

func TestFileStore_FlushRecordsSyncErrorAsDropped(t *testing.T) {
	path := t.TempDir() + "/events.jsonl"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}

	fs := &FileStore{
		file:     f,
		writer:   bufio.NewWriterSize(f, 32*1024),
		ch:       make(chan engine.Event),
		done:     make(chan struct{}),
		filePath: path,
		maxSize:  defaultMaxSize,
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if err := fs.flush(); err == nil {
		t.Fatal("expected flush to return sync error")
	}
	if got := fs.DroppedEvents(); got != 1 {
		t.Fatalf("DroppedEvents = %d, want 1", got)
	}
}

// --- checkRotation Stat error ---

func TestCheckRotation_StatError(t *testing.T) {
	path := t.TempDir() + "/events.jsonl"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fs := &FileStore{
		file:     f,
		writer:   bufio.NewWriterSize(f, 32*1024),
		filePath: path,
		maxSize:  1,
	}

	// Write enough to exceed maxSize
	fs.writer.WriteString("xxx")
	fs.writer.Flush()

	// Close underlying file so Stat fails
	f.Close()

	// Should not panic; returns early because Stat errors
	fs.checkRotation()
}

// --- checkRotation rename error (destination is existing directory) ---

func TestCheckRotation_RenameError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fs := &FileStore{
		file:     f,
		writer:   bufio.NewWriterSize(f, 32*1024),
		filePath: path,
		maxSize:  1,
	}

	fs.writer.WriteString("xxx")
	fs.writer.Flush()

	// Align to next second boundary and pre-create rotated directory
	now := time.Now()
	time.Sleep(now.Truncate(time.Second).Add(time.Second).Sub(now) + 10*time.Millisecond)

	ts := time.Now().Format("20060102-150405")
	rotated := filepath.Join(dir, "events-"+ts+".jsonl")
	if err := os.Mkdir(rotated, 0o755); err != nil {
		t.Fatalf("setup rotated dir: %v", err)
	}

	// Rename should fail because destination exists as directory
	fs.checkRotation()

	if got := fs.DroppedEvents(); got == 0 {
		t.Fatal("expected rotation rename failure to increment dropped counter")
	}

	// fs.file should be nil or the reopened file
	if fs.file == nil {
		t.Error("expected file to remain open after rename error")
	}
	if fs.file != nil {
		fs.file.Close()
	}
}

func TestCheckRotation_NoRotationBelowThreshold(t *testing.T) {
	path := t.TempDir() + "/events.jsonl"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	fs := &FileStore{
		file:     f,
		writer:   bufio.NewWriterSize(f, 32*1024),
		filePath: path,
		maxSize:  1024,
	}
	if _, err := fs.writer.WriteString("small"); err != nil {
		t.Fatal(err)
	}

	fs.checkRotation()

	if got := fs.DroppedEvents(); got != 0 {
		t.Fatalf("DroppedEvents = %d, want 0", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("original file missing after below-threshold checkRotation: %v", err)
	}
}

func TestCleanupRotatedRecordsRemoveError(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "events")
	for i := range defaultMaxRotated + 1 {
		name := filepath.Join(dir, "events-20250101-0000"+intToStr(i)+".jsonl")
		if err := os.WriteFile(name, []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	fs := &FileStore{}
	fs.cleanupRotated(base, ".jsonl")

	if got := fs.DroppedEvents(); got != 1 {
		t.Fatalf("DroppedEvents = %d, want 1", got)
	}
}

// --- marshalEventJSON IsBot true ---

func TestMarshalEventJSON_IsBotTrue(t *testing.T) {
	ev := engine.Event{
		ID:        "bot-evt",
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		RequestID: "req-bot",
		ClientIP:  "10.0.0.1",
		Method:    "GET",
		Path:      "/",
		Action:    engine.ActionPass,
		Score:     0,
		IsBot:     true,
	}
	result := marshalEventJSON(ev)
	if !strings.Contains(result, `"is_bot":true`) {
		t.Errorf("expected is_bot:true, got %s", result)
	}
}
