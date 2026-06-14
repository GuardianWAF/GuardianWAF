package ai

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAnalyzerStopWithContextReturnsWhenLoopStops(t *testing.T) {
	a := &Analyzer{stopCh: make(chan struct{})}
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		<-a.stopCh
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.StopWithContext(ctx); err != nil {
		t.Fatalf("StopWithContext returned error: %v", err)
	}

	select {
	case <-a.stopCh:
	default:
		t.Fatal("expected StopWithContext to close stopCh")
	}
}

func TestAnalyzerStopWithContextHonorsDeadline(t *testing.T) {
	a := &Analyzer{stopCh: make(chan struct{})}
	a.wg.Add(1)
	done := make(chan struct{})
	go func() {
		<-done
		a.wg.Done()
	}()
	defer close(done)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := a.StopWithContext(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("StopWithContext error = %v, want deadline exceeded", err)
	}

	select {
	case <-a.stopCh:
	default:
		t.Fatal("expected StopWithContext to close stopCh even on timeout")
	}
}
