package docker

// Regression test: StreamEvents must RETURN when the `docker events` stream
// dies (daemon restart, CLI exit, decode error) — not only when ctx is
// canceled. The previous implementation's decoder goroutine discarded the
// stream EOF while the parent blocked on <-ctx.Done() forever, so
// watcher.loop's polling fallback (err := streamEvents() -> pollLoop) was
// unreachable: after a daemon restart, event-driven discovery froze
// permanently with eventStreamConnected still reporting true.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestStreamEventsReturnsWhenStreamDies(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker executable requires a POSIX shell")
	}

	// Fake `docker` binary: emits one JSON event, then exits — the stream
	// dies immediately after a successful start.
	binDir := t.TempDir()
	script := "#!/bin/sh\n" +
		"echo '{\"Type\":\"container\",\"Action\":\"start\",\"Actor\":{\"ID\":\"abc123\",\"Attributes\":{\"name\":\"web\"}}}'\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(binDir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake docker: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	c := NewClient("/var/run/docker.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan Event, 8)
	done := make(chan error, 1)
	go func() { done <- c.StreamEvents(ctx, "gwaf", ch) }()

	// Control: the streamed event must arrive (proves the stream started and
	// worked before it died).
	select {
	case ev := <-ch:
		if ev.Action != "start" {
			t.Fatalf("unexpected first event action %q", ev.Action)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("control failed: no event delivered from the fake stream")
	}

	// Stream death must surface as a returned error (non-nil), letting the
	// watcher's loop fall back to polling.
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("StreamEvents returned nil after the docker events process exited; want a non-nil error so the watcher logs the disconnect and falls back to polling")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the docker events process exited but StreamEvents never returned — discovery would stay frozen with eventStreamConnected still true")
	}
}
