package tenant

// Regression: invoice IDs must be unique.
//
// generateInvoiceID encoded seconds + a MILLISECOND field, so any two
// GenerateInvoice calls inside the same millisecond produced byte-identical
// IDs. GenerateInvoice holds bm.mu across bm.save(), but that write is tens of
// microseconds on tmpfs/overlayfs — far under 1ms — so collisions were routine,
// not theoretical (measured: 300 invoices produced only 222 distinct IDs,
// with individual IDs reused up to three times).
//
// The damage is data corruption, not a cosmetic duplicate. UpdateInvoiceStatus
// searches bm.invoices by ID alone and mutates the FIRST match:
//
//	for tenantID, invoices := range bm.invoices {
//	    for i := range invoices {
//	        if invoices[i].ID == invoiceID { ... }
//
// So with two invoices sharing an ID, an operator marking one "paid" mutated an
// arbitrary record and the other became permanently unreachable by ID — a
// settled invoice could keep showing draft, or an unpaid one could be marked
// paid. The ID is now suffixed with crypto/rand, the same scheme
// generateAlertID uses in this package, keeping the human-readable
// INV-<tenant>-<timestamp> prefix.
//
// Note: the store path must be a FILE. NewBillingManager(storePath) treats its
// argument as a file path, so passing a directory makes save() fail fast —
// which also collapses the inter-call gap and would make this test pass for the
// wrong reason.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newBillingForTest builds a BillingManager with a real on-disk store.
func newBillingForTest(t *testing.T) *BillingManager {
	t.Helper()
	return NewBillingManager(filepath.Join(t.TempDir(), "billing.json"))
}

func TestInvoiceIDsAreUniqueUnderRapidGeneration(t *testing.T) {
	bm := newBillingForTest(t)
	bm.RecordUsage("acme-corp-001", 5000, 1<<30, 20)

	ids := make(map[string]int, 300)
	for i := 0; i < 300; i++ {
		inv, err := bm.GenerateInvoice("acme-corp-001", "Acme", PlanPro,
			time.Now().Add(-time.Hour), time.Now())
		if err != nil {
			t.Fatalf("GenerateInvoice: %v", err)
		}
		ids[inv.ID]++
	}

	if len(ids) != 300 {
		t.Fatalf("%d of 300 generated invoice IDs collided (%d distinct). generateInvoiceID "+
			"must not encode only a millisecond-resolution timestamp — UpdateInvoiceStatus "+
			"matches by ID alone and would mutate an arbitrary invoice", 300-len(ids), len(ids))
	}
}

// A status update must land on exactly the intended invoice even when many
// exist for one tenant — the property duplicates used to break.
func TestUpdateInvoiceStatusTargetsExactlyOneInvoice(t *testing.T) {
	bm := newBillingForTest(t)
	bm.RecordUsage("acme-corp-001", 1000, 1<<20, 1)

	const n = 25
	var made []string
	for i := 0; i < n; i++ {
		inv, err := bm.GenerateInvoice("acme-corp-001", "Acme", PlanPro,
			time.Now().Add(-time.Hour), time.Now())
		if err != nil {
			t.Fatalf("GenerateInvoice: %v", err)
		}
		made = append(made, inv.ID)
	}

	// Mark each invoice paid in turn; every one must end up paid.
	for _, id := range made {
		if !bm.UpdateInvoiceStatus(id, "paid") {
			t.Fatalf("UpdateInvoiceStatus(%q) found no invoice", id)
		}
	}
	for _, inv := range bm.GetInvoices("acme-corp-001") {
		if inv.Status != "paid" {
			t.Fatalf("invoice %q is %q after every ID was marked paid — a status update "+
				"landed on the wrong record (duplicate IDs)", inv.ID, inv.Status)
		}
	}
}

// CONTROL: the ID keeps its documented human-readable shape so dashboard and
// operator-facing consumers are unaffected.
func TestInvoiceIDShapePreserved(t *testing.T) {
	id := generateInvoiceID("tenant-12345")
	if !strings.HasPrefix(id, "INV-") {
		t.Errorf("ID %q lost its INV- prefix", id)
	}
	if !strings.HasPrefix(id, "INV-tenant-") {
		t.Errorf("ID %q lost its tenant prefix", id)
	}
	if len(id) < 10 {
		t.Errorf("ID %q is too short to stay human-readable", id)
	}
	if strings.ContainsAny(id, "/\\ \t\n") {
		t.Errorf("ID %q contains whitespace or path separators", id)
	}
}

// CONTROL: distinct tenants keep distinct ID prefixes.
func TestInvoiceIDKeepsTenantPrefix(t *testing.T) {
	a := generateInvoiceID("tenant-alpha")
	b := generateInvoiceID("tenant-beta")
	if !strings.HasPrefix(a, "INV-tenant-") || !strings.HasPrefix(b, "INV-tenant-") {
		t.Fatalf("tenant prefix missing: %q / %q", a, b)
	}
	if a == b {
		t.Fatalf("IDs for different tenants collided: %q", a)
	}
}
