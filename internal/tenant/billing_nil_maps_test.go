package tenant

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Regression: BillingManager.load() assigned the decoded maps verbatim, so a
// store file that omitted the "invoices"/"current_usage" keys — or carried
// JSON null after truncation or manual edits — decoded to nil maps, silently
// discarding the constructor's make() initialization. The next RecordUsage
// (called per request from Manager.RecordUsage on the tenant middleware hot
// path) then executed an assignment into a nil map and panicked, crashing the
// process. load() now normalizes nil maps at the deserialization boundary.
func TestBillingStoreWithMissingKeysDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "billing.json")
	if err := os.WriteFile(storePath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("writing store fixture: %v", err)
	}

	bm := NewBillingManager(storePath)
	bm.RecordUsage("tenant-1", 5, 100, 1)

	inv, err := bm.GenerateInvoice("tenant-1", "Tenant One", PlanBasic,
		time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("GenerateInvoice: %v", err)
	}
	if inv == nil || inv.Usage.Requests != 5 {
		t.Fatalf("invoice did not reflect recorded usage (invoice=%+v)", inv)
	}
	if inv.TotalCost <= 0 {
		t.Fatalf("invoice total cost is not positive: %v", inv.TotalCost)
	}
}

func TestBillingStoreWithNullKeysDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "billing.json")
	if err := os.WriteFile(storePath, []byte(`{"invoices":null,"current_usage":null}`), 0o600); err != nil {
		t.Fatalf("writing store fixture: %v", err)
	}

	bm := NewBillingManager(storePath)
	bm.RecordUsage("tenant-2", 1, 10, 0)

	usage := bm.GetCurrentUsage("tenant-2")
	if usage == nil || usage.Requests != 1 {
		t.Fatalf("recorded usage lost (usage=%+v)", usage)
	}
}
