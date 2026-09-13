package alerting

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (round 79): HandleEvent's cooldown eviction was broken in two
// ways. The prune loop covered only webhook targets — email targets' lastFire
// maps grew one entry per distinct client IP and were never evicted
// (attacker-amplified unbounded growth in a long-lived process; NewEmailTarget
// defaults cooldown to 5 minutes, so the Store always runs). And the webhook
// prune kept an ARBITRARY 1000 entries (Go map iteration order), not the most
// recent ones, so it could evict fresh, still-active suppression entries while
// retaining expired ones that can never suppress again — defeating cooldown
// exactly under the IP-diversity load where alerting matters. HandleEvent now
// prunes both target kinds after all Stores: expired entries are always
// deleted and the count cap evicts oldest first.

func newPruneTestManager(t *testing.T) *Manager {
	t.Helper()
	// bb1232c rule: restore the captured PRIOR value — TestMain arms this
	// flag package-wide and sibling test files depend on it.
	prev := allowWebhookPrivate.Load()
	allowWebhookPrivate.Store(true)
	t.Cleanup(func() { allowWebhookPrivate.Store(prev) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	m := NewManagerWithEmail([]WebhookTarget{{
		Name:     "t",
		URL:      srv.URL,
		Type:     "generic",
		Events:   []string{"block"},
		MinScore: 0,
		Cooldown: 50 * time.Millisecond,
	}}, []config.EmailConfig{{SMTPHost: "127.0.0.1:1", To: []string{"ops@example.test"}}})
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func fireBlockEvent(m *Manager, ip string) {
	m.HandleEvent(&engine.Event{
		ID:        "e-" + ip,
		Timestamp: time.Now(),
		ClientIP:  ip,
		Method:    "GET",
		Path:      "/a",
		Action:    engine.ActionBlock,
		Score:     50,
	})
}

func countEntries(mp *sync.Map) int {
	n := 0
	mp.Range(func(_, _ any) bool { n++; return true })
	return n
}

func TestHandleEventPrunesEmailCooldownMap(t *testing.T) {
	m := newPruneTestManager(t)

	for i := 1; i <= 1001; i++ {
		fireBlockEvent(m, fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255))
	}

	// Email targets had no eviction at all: every distinct client IP added a
	// permanent entry (cooldown defaults to 5 minutes in NewEmailTarget).
	if got := countEntries(m.emailTargets[0].lastFire); got > maxCooldownEntries {
		t.Fatalf("email cooldown map holds %d entries after the prune pass — email targets must be pruned like webhooks", got)
	}
}

func TestHandleEventPrunesExpiredWebhookCooldownEntries(t *testing.T) {
	m := newPruneTestManager(t)

	for i := 1; i <= 1000; i++ {
		fireBlockEvent(m, fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255))
	}
	// Age every entry past the 50ms cooldown, then fire one fresh IP: the
	// expired entries are garbage (the suppression check treats them as
	// absent) and must be swept, while the fresh entry must survive.
	time.Sleep(120 * time.Millisecond)
	fireBlockEvent(m, "10.99.99.99")

	fresh := "10.99.99.99"
	stale := 0
	freshPresent := false
	m.webhooks[0].lastFire.Range(func(k, v any) bool {
		ts, _ := v.(time.Time)
		if time.Since(ts) >= 50*time.Millisecond {
			stale++
		}
		if k == fresh {
			freshPresent = true
		}
		return true
	})
	if stale != 0 {
		t.Fatalf("webhook cooldown map retains %d expired entries — eviction must be by staleness, not arbitrary map order", stale)
	}
	if !freshPresent {
		t.Fatal("the fresh suppression entry was evicted by arbitrary-order pruning")
	}
}
