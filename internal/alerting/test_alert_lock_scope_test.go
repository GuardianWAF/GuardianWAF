package alerting

// Regression: TestAlert held m.mu.RLock across the blocking delivery —
//
// Defect: Manager.TestAlert holds m.mu.RLock across the blocking send — a
// slow or dead webhook target holds the read lock for up to the HTTP
// timeout, and every concurrent config writer (AddWebhook, AddEmailTarget)
// waits behind it for that whole duration. The target config is already
// copied under the lock, so the send has no reason to run under it.

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestAlertReleasesLockBeforeDelivery(t *testing.T) {
	prev := allowWebhookPrivate.Load()
	allowWebhookPrivate.Store(true)
	// Restore the PRIOR value, not a hardcoded false: TestMain arms the flag
	// package-wide, and a false restore poisons every test compiled after
	// this file (webhook_extra_test.go runs later in file order and needs it
	// armed).
	defer allowWebhookPrivate.Store(prev)

	deliveryStarted := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	releaseOnce := func() { once.Do(func() { close(release) }) } // idempotent; also unblocks the handler on the death path
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(deliveryStarted) // signal: TestAlert is now blocked inside send()
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer releaseOnce() // unblocks the abandoned handler before srv.Close on every path

	m := NewManager([]WebhookTarget{{Name: "slow", URL: srv.URL}})

	done := make(chan error, 1)
	go func() { done <- m.TestAlert("slow") }()

	select {
	case <-deliveryStarted: // TestAlert is provably inside m.send() right now
	case <-time.After(5 * time.Second):
		t.Fatal("setup: TestAlert never reached the delivery stage")
	}

	// The probe: a config writer must be able to take the write lock while
	// delivery is still blocked. Pre-fix, the read lock is held across the
	// entire HTTP round-trip, so TryLock fails.
	if !m.mu.TryLock() {
		t.Fatal("FAIL: TestAlert holds m.mu.RLock across the blocking delivery — a concurrent config writer (AddWebhook/AddEmailTarget) cannot proceed for the entire HTTP timeout")
	}
	m.mu.Unlock()

	releaseOnce()
	if err := <-done; err != nil {
		t.Fatalf("TestAlert failed after delivery: %v", err)
	}
}
