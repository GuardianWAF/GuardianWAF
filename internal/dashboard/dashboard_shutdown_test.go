package dashboard

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDashboardCloseWithContextWaitsForCleanupLoops(t *testing.T) {
	d := New(nil, nil, "test-key")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := d.CloseWithContext(ctx); err != nil {
		t.Fatalf("CloseWithContext: %v", err)
	}
}

func TestDashboardCloseWithContextHonorsDeadline(t *testing.T) {
	d := New(nil, nil, "test-key")
	d.cleanupWG.Add(1)

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	err := d.CloseWithContext(ctx)
	d.cleanupWG.Done()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseWithContext error = %v, want deadline exceeded", err)
	}

	if err := d.CloseWithContext(context.Background()); err != nil {
		t.Fatalf("final CloseWithContext: %v", err)
	}
}
