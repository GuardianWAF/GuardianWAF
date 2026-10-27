package docker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestWatcherDiscardsSyncAfterStop(t *testing.T) {
	for _, mode := range []string{"new-service", "empty", "error"} {
		t.Run(mode, func(t *testing.T) {
			client := NewClient("")
			client.cmdFunc = func(_ context.Context, args ...string) (string, error) {
				if args[0] == "ps" {
					return `{"ID":"abc123"}`, nil
				}
				return `[{"Id":"abc123","Name":"/api","Config":{"Labels":{"gwaf.enable":"true","gwaf.port":"8080"}},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.2"}}}}]`, nil
			}
			w := NewWatcher(client, "gwaf", "bridge", 0)
			if !w.sync() || w.sync() {
				t.Fatal("normal changed/unchanged sync failed")
			}
			entered, release, startDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			client.cmdFunc = func(_ context.Context, args ...string) (string, error) {
				calls.Add(1)
				if args[0] == "ps" {
					close(entered)
					<-release
					if mode == "empty" {
						return "", nil
					}
					if mode == "error" {
						return "", errors.New("injected failure")
					}
					return `{"ID":"def456"}`, nil
				}
				return `[{"Id":"def456","Name":"/late","Config":{"Labels":{"gwaf.enable":"true","gwaf.port":"8080"}},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.3"}}}}]`, nil
			}
			go func() { w.Start(); close(startDone) }()
			<-entered
			stopOne, stopTwo := make(chan struct{}), make(chan struct{})
			go func() { w.Stop(); close(stopOne) }()
			go func() { w.Stop(); close(stopTwo) }()
			<-stopOne
			<-stopTwo
			close(release)
			<-startDone
			w.wg.Wait()
			got := w.Services()
			if len(got) != 1 || got[0].ContainerID != "abc123" {
				t.Fatalf("late %s published: %v", mode, got)
			}
			stats := w.Stats()
			if stats.Running || !stats.LastSyncOK || stats.SyncFailures != 0 {
				t.Fatalf("stopped state changed: %+v", stats)
			}
			before := calls.Load()
			if w.sync() || calls.Load() != before {
				t.Fatal("stopped sync invoked Docker")
			}
			w.Stop()
		})
	}
}
