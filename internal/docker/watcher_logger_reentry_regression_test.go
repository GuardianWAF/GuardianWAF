package docker

import (
	"context"
	"testing"
)

func batchF22Watcher() *Watcher {
	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		if args[0] == "ps" {
			return `{"ID":"abc123"}`, nil
		}
		return `[{"Id":"abc123","Name":"/api","Config":{"Labels":{"gwaf.enable":"true","gwaf.port":"8080"}},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.2"}}}}]`, nil
	}
	return NewWatcher(c, "gwaf", "bridge", 0)
}
func TestWatcherDiscoveryLoggerCanReadServices(t *testing.T) {
	w := batchF22Watcher()
	counts := make(chan int, 3)
	w.SetLogger(func(_, _ string) { counts <- w.ServiceCount(); _ = w.Stats(); _ = w.Services() })
	done := make(chan bool, 1)
	go func() { done <- w.sync() }()
	if got := <-counts; got != 1 {
		t.Fatalf("got %d", got)
	}
	if !<-done {
		t.Fatal("first refresh not changed")
	}
	if w.sync() {
		t.Fatal("unchanged refresh")
	}
	select {
	case <-counts:
		t.Fatal("unchanged logged")
	default:
	}
	w.client.cmdFunc = func(_ context.Context, _ ...string) (string, error) { return "", nil }
	go func() { done <- w.sync() }()
	if got := <-counts; got != 0 {
		t.Fatalf("empty got %d", got)
	}
	if !<-done {
		t.Fatal("removal not changed")
	}
	if w.sync() {
		t.Fatal("empty repeated refresh")
	}
	t.Log("FIX VERIFIED")
}
