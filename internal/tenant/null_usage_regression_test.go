package tenant

import (
	"os"
	"path/filepath"
	"testing"
)

func batchF29Store(t *testing.T, content string) *BillingManager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "billing.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return NewBillingManager(path)
}
func TestBillingNullUsageEntriesBehaveAsAbsent(t *testing.T) {
	for _, content := range []string{`{}`, `{"current_usage":null}`, `{"current_usage":{"one":null}}`, `{"current_usage":{"one":{"requests":5,"bytes_transferred":7,"blocked_attacks":2}}}`} {
		bm := batchF29Store(t, content)
		before := bm.GetCurrentUsage("one")
		baseR, baseB, baseA := int64(0), int64(0), int64(0)
		if before != nil {
			baseR = before.Requests
			baseB = before.BytesTransferred
			baseA = before.BlockedAttacks
		}
		bm.RecordUsage("one", 3, 10, 1)
		got := bm.GetCurrentUsage("one")
		if got == nil || got.Requests != baseR+3 || got.BytesTransferred != baseB+10 || got.BlockedAttacks != baseA+1 {
			t.Fatalf("usage %+v", got)
		}
		if err := bm.save(); err != nil {
			t.Fatal(err)
		}
		reloaded := NewBillingManager(bm.storePath)
		again := reloaded.GetCurrentUsage("one")
		if again.Requests != got.Requests || again.BytesTransferred != got.BytesTransferred || again.BlockedAttacks != got.BlockedAttacks || !again.PeriodStart.Equal(got.PeriodStart) || !again.PeriodEnd.Equal(got.PeriodEnd) {
			t.Fatal("save/reload mismatch")
		}
		if reloaded.GetCurrentUsage("missing") != nil {
			t.Fatal("missing entry")
		}
	}
	t.Log("FIX VERIFIED")
}
