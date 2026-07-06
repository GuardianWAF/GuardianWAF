package docker

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientInspectContainerRejectsUnsafeRef(t *testing.T) {
	c := NewClient("")

	_, err := c.InspectContainer("bad;name")
	if err == nil {
		t.Fatal("expected unsafe container reference to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid container reference") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientDockerCLIBaseArgsRejectsInvalidTLSArg(t *testing.T) {
	c := NewClient("")
	c.tlsArgs = []string{"--tlsverify", "/bad\npath.pem"}

	_, err := c.dockerCLIBaseArgs()
	if err == nil {
		t.Fatal("expected invalid TLS arg error")
	}
	if !strings.Contains(err.Error(), "docker TLS argument") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientStreamEventsRejectsInvalidHostFlag(t *testing.T) {
	c := NewClient("")
	c.hostFlag = "unix:///var/run/docker.sock\n--host=tcp://evil"

	err := c.StreamEvents(context.Background(), "gwaf", make(chan Event, 1))
	if err == nil {
		t.Fatal("expected invalid docker host error")
	}
	if !strings.Contains(err.Error(), "docker host") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientStreamEventsStartError(t *testing.T) {
	c := NewClient("")
	t.Setenv("PATH", "")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := c.StreamEvents(ctx, "gwaf", make(chan Event, 1))
	if err == nil {
		t.Fatal("expected start error when docker is unavailable in PATH")
	}
	if !strings.Contains(err.Error(), "starting docker events") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewHTTPClientCheckRedirect(t *testing.T) {
	client := NewHTTPClient("/var/run/docker.sock")
	err := client.CheckRedirect(&http.Request{}, []*http.Request{{}})
	if !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect error = %v, want %v", err, http.ErrUseLastResponse)
	}
}

func TestIsSafeContainerRef(t *testing.T) {
	valid := []string{"abc123def456", "my-container_1.2"}
	for _, ref := range valid {
		if !isSafeContainerRef(ref) {
			t.Fatalf("expected %q to be safe", ref)
		}
	}

	invalid := []string{"", strings.Repeat("a", 129), "bad/name", "bad;name"}
	for _, ref := range invalid {
		if isSafeContainerRef(ref) {
			t.Fatalf("expected %q to be rejected", ref)
		}
	}
}

func TestSanitizeLogValueStripsControlCharacters(t *testing.T) {
	got := sanitizeLogValue("svc\nname\r\x1b[31m\t!")
	if got != "svcname[31m!" {
		t.Fatalf("sanitizeLogValue() = %q", got)
	}
}

func TestWatcherPollLoopUsesDefaultIntervalWhenNonPositive(t *testing.T) {
	w := NewWatcher(NewClient(""), "gwaf", "bridge", time.Second)
	w.pollInterval = 0
	w.SetLogger(func(_, _ string) {})

	done := make(chan struct{})
	go func() {
		w.pollLoop()
		close(done)
	}()

	time.Sleep(20 * time.Millisecond)
	close(w.stopCh)

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("pollLoop did not stop")
	}
}

func writeFakeDocker(t *testing.T, script string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	return dir
}

func TestDockerCmdWrapsExitErrorStderr(t *testing.T) {
	dir := writeFakeDocker(t, "#!/bin/sh\necho docker failed >&2\nexit 12\n")
	t.Setenv("PATH", dir)

	c := &Client{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := c.dockerCmd(ctx, "ps")
	if err == nil {
		t.Fatal("expected dockerCmd to fail")
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected wrapped exit error, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "docker failed") {
		t.Fatalf("expected stderr in error, got %v", err)
	}
}

func TestClientListContainersSkipsUnsafeIDs(t *testing.T) {
	c := NewClient("")
	calledInspect := false
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return "{\"ID\":\"bad;name\"}\n", nil
		}
		calledInspect = true
		return "[]", nil
	}

	containers, err := c.ListContainers("gwaf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if containers != nil {
		t.Fatalf("expected nil containers, got %v", containers)
	}
	if calledInspect {
		t.Fatal("inspect should not be called for unsafe IDs")
	}
}

func TestClientStreamEventsReceivesEvent(t *testing.T) {
	dir := writeFakeDocker(t, "#!/bin/sh\necho '{\"Type\":\"container\",\"Action\":\"start\",\"Actor\":{\"ID\":\"abc123\",\"Attributes\":{\"name\":\"svc\"}},\"time\":1}'\nsleep 5\n")
	t.Setenv("PATH", dir)

	c := NewClient("")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan Event, 1)
	errCh := make(chan error, 1)

	go func() {
		errCh <- c.StreamEvents(ctx, "gwaf", ch)
	}()

	select {
	case evt := <-ch:
		if evt.Action != "start" || evt.Actor.ID != "abc123" {
			t.Fatalf("unexpected event: %+v", evt)
		}
		cancel()
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("StreamEvents returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for StreamEvents to return")
	}
}
