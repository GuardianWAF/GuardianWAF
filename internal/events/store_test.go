package events

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ersinkoc/guardianwaf/internal/engine"
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
		ms.Store(ev)
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

	ms.Store(makeEvent("evt-0", engine.ActionPass, 0, "/", "10.0.0.1", now))
	ms.Store(makeEvent("evt-1", engine.ActionPass, 0, "/", "10.0.0.1", now.Add(time.Second)))

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

	ms.Store(makeEvent("evt-pass", engine.ActionPass, 0, "/", "10.0.0.1", now))
	ms.Store(makeEvent("evt-block", engine.ActionBlock, 50, "/", "10.0.0.1", now.Add(time.Second)))
	ms.Store(makeEvent("evt-log", engine.ActionLog, 30, "/", "10.0.0.1", now.Add(2*time.Second)))
	ms.Store(makeEvent("evt-block2", engine.ActionBlock, 60, "/", "10.0.0.1", now.Add(3*time.Second)))

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

func TestMemoryStore_QueryByTimeRange(t *testing.T) {
	ms := NewMemoryStore(100)
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	for i := range 10 {
		ev := makeEvent("evt-"+intToStr(i), engine.ActionPass, 0, "/", "10.0.0.1", base.Add(time.Duration(i)*time.Hour))
		ms.Store(ev)
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

	ms.Store(makeEvent("evt-low", engine.ActionPass, 10, "/", "10.0.0.1", now))
	ms.Store(makeEvent("evt-med", engine.ActionLog, 50, "/", "10.0.0.1", now.Add(time.Second)))
	ms.Store(makeEvent("evt-high", engine.ActionBlock, 90, "/", "10.0.0.1", now.Add(2*time.Second)))

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

	ms.Store(makeEvent("evt-api1", engine.ActionPass, 0, "/api/users", "10.0.0.1", now))
	ms.Store(makeEvent("evt-api2", engine.ActionPass, 0, "/api/orders", "10.0.0.1", now.Add(time.Second)))
	ms.Store(makeEvent("evt-web", engine.ActionPass, 0, "/web/page", "10.0.0.1", now.Add(2*time.Second)))

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
		ms.Store(ev)
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

	ms.Store(makeEvent("evt-low", engine.ActionPass, 10, "/", "10.0.0.1", now))
	ms.Store(makeEvent("evt-high", engine.ActionBlock, 90, "/", "10.0.0.1", now.Add(time.Second)))
	ms.Store(makeEvent("evt-med", engine.ActionLog, 50, "/", "10.0.0.1", now.Add(2*time.Second)))

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

	ms.Store(makeEvent("evt-1", engine.ActionPass, 0, "/", "10.0.0.1", now))
	ms.Store(makeEvent("evt-2", engine.ActionPass, 0, "/", "10.0.0.2", now.Add(time.Second)))
	ms.Store(makeEvent("evt-3", engine.ActionPass, 0, "/", "10.0.0.1", now.Add(2*time.Second)))

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

	ms.Store(makeEvent("evt-1", engine.ActionBlock, 60, "/", "10.0.0.1", now))
	ms.Store(makeEvent("evt-2", engine.ActionPass, 0, "/", "10.0.0.1", now.Add(time.Second)))
	ms.Store(makeEvent("evt-3", engine.ActionBlock, 80, "/", "10.0.0.1", now.Add(2*time.Second)))
	ms.Store(makeEvent("evt-4", engine.ActionLog, 40, "/", "10.0.0.1", now.Add(3*time.Second)))

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
		fs.Store(ev)
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
		fs.Store(ev)
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
		fs.Store(ev)
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

	fs.Store(ev)
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

	// Channel should not be closed since it was added after Close
	select {
	case ch <- engine.Event{}:
		<-ch // drain
	default:
		t.Error("channel should still be open after Subscribe on closed bus")
	}
}

// --- Helper ---

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
