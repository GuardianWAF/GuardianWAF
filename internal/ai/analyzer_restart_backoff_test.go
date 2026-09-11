package ai

// Regression tests for round 12/25: Analyzer.loop's panic recovery must
// restart with a backoff (and honor shutdown), so a persistently panicking
// state cannot hot-spin the loop. This mirrors the docker/watcher.go pattern
// and the ACME renewal-loop fix. The pre-fix implementation restarted
// immediately: 5 panics landed within ~300ms for 5 events.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

type panicBlocker struct{ calls atomic.Int64 }

func (p *panicBlocker) AddAutoBan(ip string, reason string, ttl time.Duration) {
	p.calls.Add(1)
	panic("blocker boom")
}

type goodBlocker struct{ calls atomic.Int64 }

func (g *goodBlocker) AddAutoBan(ip string, reason string, ttl time.Duration) {
	g.calls.Add(1)
}

func newAnalyzerBackoffTest(t *testing.T, blocker IPBlocker) (*Analyzer, *atomic.Int64) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"verdicts\":[{\"ip\":\"10.0.0.9\",\"action\":\"block\",\"reason\":\"proof\",\"confidence\":0.9}],\"summary\":\"proof\",\"threats_detected\":[]}","finish_reason":"stop"}}],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}`))
	}))
	t.Cleanup(srv.Close)

	store := NewStore(t.TempDir())
	a := NewAnalyzer(AnalyzerConfig{
		Enabled:          true,
		BatchSize:        1,
		BatchInterval:    10 * time.Millisecond,
		AutoBlockEnabled: true,
		AutoBlockTTL:     time.Hour,
		MinScoreForAI:    1,
	}, store, "")

	client, err := NewClientValidated(ClientConfig{
		BaseURL: srv.URL, APIKey: "test-key", Model: "test-model",
		AllowPrivateEndpoint: true,
	})
	if err != nil {
		t.Fatalf("client setup: %v", err)
	}
	a.mu.Lock()
	a.client = client
	a.mu.Unlock()

	var panics atomic.Int64
	a.SetLogger(func(level, msg string) {
		if strings.Contains(msg, "loop panic") {
			panics.Add(1)
		}
	})
	a.SetBlocker(blocker)
	return a, &panics
}

func TestAnalyzerPanicRestartBacksOff(t *testing.T) {
	blocker := &panicBlocker{}
	a, panics := newAnalyzerBackoffTest(t, blocker)

	eventCh := make(chan engine.Event, 16)
	a.Start(eventCh)
	t.Cleanup(a.Stop)

	for i := 0; i < 5; i++ {
		eventCh <- engine.Event{
			Timestamp: time.Now(),
			ClientIP:  "10.0.0.9",
			Method:    "GET",
			Path:      "/proof",
			Score:     50,
			Findings:  []engine.Finding{{DetectorName: "proof", Description: "d", Score: 50}},
		}
	}

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) && panics.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	got := panics.Load()

	if got == 0 {
		t.Fatalf("restart after panic is broken entirely — the loop never recovered")
	}
	if got > 2 {
		t.Fatalf("panic restart has no backoff: %d restarts within ~300ms — a persistently panicking state hot-spins the loop", got)
	}
	if blocker.calls.Load() == 0 {
		t.Fatalf("harness broken: applyVerdicts never ran")
	}
}

func TestAnalyzerVerdictsAppliedWithoutPanic(t *testing.T) {
	blocker := &goodBlocker{}
	a, panics := newAnalyzerBackoffTest(t, blocker)

	eventCh := make(chan engine.Event, 16)
	a.Start(eventCh)
	t.Cleanup(a.Stop)

	eventCh <- engine.Event{
		Timestamp: time.Now(),
		ClientIP:  "10.0.0.9",
		Method:    "GET",
		Path:      "/proof",
		Score:     50,
		Findings:  []engine.Finding{{DetectorName: "proof", Description: "d", Score: 50}},
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && blocker.calls.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if blocker.calls.Load() == 0 {
		t.Fatalf("verdict was never applied — the happy path broke")
	}
	if panics.Load() != 0 {
		t.Fatalf("happy path must not panic (got %d loop panics)", panics.Load())
	}
}
