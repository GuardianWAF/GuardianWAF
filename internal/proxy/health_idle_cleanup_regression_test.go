package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type healthIdleCleanupTransport struct {
	idle, closes               atomic.Int32
	entered, canceled, release chan struct{}
}

type healthIdleCleanupBody struct {
	io.Reader
	tr   *healthIdleCleanupTransport
	once sync.Once
}

func (b *healthIdleCleanupBody) Close() error { b.once.Do(func() { b.tr.idle.Store(1) }); return nil }

func (tr *healthIdleCleanupTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if tr.entered != nil {
		close(tr.entered)
		<-r.Context().Done()
		close(tr.canceled)
		<-tr.release // a late completion can return a connection to the idle pool
	}
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &healthIdleCleanupBody{Reader: strings.NewReader(""), tr: tr}, Request: r}, nil
}
func (tr *healthIdleCleanupTransport) CloseIdleConnections() { tr.closes.Add(1); tr.idle.Store(0) }

func TestHealthCheckerReleasesIdleConnections(t *testing.T) {
	newChecker := func(tr *healthIdleCleanupTransport) *HealthChecker {
		target, err := NewTargetWithPolicy("http://192.0.2.1", 1, TargetPolicy{AllowPrivateTargets: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(target.Close)
		hc := NewHealthChecker(NewBalancer([]*Target{target}, ""), HealthConfig{Interval: time.Hour})
		hc.client.Timeout = 0
		hc.client.Transport = tr
		return hc
	}
	t.Run("eight-repeated-lifecycles", func(t *testing.T) {
		var idle int32
		for range 8 {
			tr := &healthIdleCleanupTransport{}
			hc := newChecker(tr)
			hc.checkAll(context.Background())
			if tr.idle.Load() != 1 {
				t.Fatal("control: probe did not create an idle resource")
			}
			hc.Stop()
			hc.Stop()
			idle += tr.idle.Load()
			if tr.closes.Load() == 0 {
				t.Fatal("stop did not release the checker's transport")
			}
		}
		if idle != 0 {
			t.Fatalf("EXPECTED: idle=0 | ACTUAL: idle=%d", idle)
		}
	})
	t.Run("stop-before-start", func(t *testing.T) {
		tr := &healthIdleCleanupTransport{}
		hc := newChecker(tr)
		hc.Stop()
		hc.Start()
		hc.Stop()
		if tr.idle.Load() != 0 {
			t.Fatal("stop-before-start retained a resource")
		}
	})
	for _, bounded := range []bool{false, true} {
		t.Run(fmt.Sprintf("late-completion-bounded-%v", bounded), func(t *testing.T) {
			tr := &healthIdleCleanupTransport{entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
			hc := newChecker(tr)
			hc.Start()
			<-tr.entered
			stopped := make(chan error, 1)
			if bounded {
				ctx, cancel := context.WithCancel(context.Background())
				cancel() // deterministic canceled wait; no wall-clock deadline
				stopped <- hc.StopWithContext(ctx)
			} else {
				go func() { stopped <- hc.StopWithContext(context.Background()) }()
			}
			<-tr.canceled
			if bounded {
				if err := <-stopped; !errors.Is(err, context.Canceled) {
					t.Fatalf("bounded stop error = %v", err)
				}
			}
			close(tr.release)
			hc.wg.Wait() // worker completion barrier includes deferred transport cleanup
			if !bounded {
				if err := <-stopped; err != nil {
					t.Fatal(err)
				}
			}
			if tr.idle.Load() != 0 || tr.closes.Load() == 0 {
				t.Fatalf("EXPECTED: idle=0 cleanup=true | ACTUAL: idle=%d closes=%d", tr.idle.Load(), tr.closes.Load())
			}
		})
	}
}
