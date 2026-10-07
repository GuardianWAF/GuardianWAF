package tenant

// Regression: an unrecognized billing plan must be priced as the Basic plan,
// never at $0.
//
// internal/tenant/billing.go seeds bm.pricing with exactly four keys
// (PlanFree, PlanBasic, PlanPro, PlanEnterprise). Both GenerateInvoice and
// EstimateCost resolved the plan with a bare map index — `bm.pricing[plan]` —
// and a Go map miss returns the ZERO PlanPricing, not the documented
// DefaultPlanPricing fallback: BaseMonthlyCost, every per-unit rate and
// OverageRate are all 0, so an invoice for any unrecognized plan string
// totalled $0 regardless of usage.
//
// Reachability: the plan is an operator-supplied, unvalidated string.
// PUT /api/admin/tenants/{id} maps the "plan" form field onto "billing_plan"
// (internal/dashboard/tenant_admin_handler.go normalizeTenantAdminUpdate) with
// no enum check anywhere in the repo, handleBillingDetail forwards that stored
// value verbatim, and cmd/guardianwaf/dashboard_adapters.go converts the raw
// string with tenant.BillingPlan(plan). A typo or an unsupported tier silently
// under-billed the tenant.

import (
	"testing"
	"time"
)

// TestBillingManager_UnknownPlanIsPricedAsBasic is the exact trigger from the
// proof: a non-compiled-in plan over heavy usage.
func TestBillingManager_UnknownPlanIsPricedAsBasic(t *testing.T) {
	bm := NewBillingManager("")
	bm.RecordUsage("acme-corp", 5_000_000, 900*(1024*1024*1024), 12_345)

	start := time.Now().AddDate(0, -1, 0)
	end := time.Now()

	invoice, err := bm.GenerateInvoice("acme-corp", "Acme Corp", BillingPlan("pro-plus"), start, end)
	if err != nil {
		t.Fatalf("GenerateInvoice with an unrecognized plan returned an error instead of pricing: %v", err)
	}

	// The zero-PlanPricing regression: every component collapsed to zero.
	if invoice.BaseCost == 0 {
		t.Errorf("BaseCost = 0 for plan %q — the plan did not resolve to the "+
			"DefaultPlanPricing Basic fallback (want %v)", invoice.Plan, DefaultPlanPricing(PlanBasic).BaseMonthlyCost)
	}
	if invoice.TotalCost == 0 {
		t.Fatalf("TotalCost = 0 for plan %q over %d requests and %d bytes — an "+
			"unrecognized plan must be priced, not billed as free",
			invoice.Plan, invoice.Usage.Requests, invoice.Usage.BytesTransferred)
	}

	// Exact equality with the Basic fallback: this is the documented contract,
	// not merely "some non-zero number".
	want := DefaultPlanPricing(PlanBasic)
	if invoice.BaseCost != want.BaseMonthlyCost {
		t.Errorf("BaseCost = %v, want the Basic fallback %v", invoice.BaseCost, want.BaseMonthlyCost)
	}

	// The invoice must not exceed what the same usage would cost on the
	// cheapest real plan boundary either — it must at least carry the base.
	if invoice.TotalCost < want.BaseMonthlyCost {
		t.Errorf("TotalCost = %v, want >= the Basic base cost %v", invoice.TotalCost, want.BaseMonthlyCost)
	}
}

// TestBillingManager_KnownPlansUnaffected is the control: the four compiled-in
// plans must keep resolving from the table, unchanged by the fallback. It pins
// the branch the fix must not disturb.
func TestBillingManager_KnownPlansUnaffected(t *testing.T) {
	plans := []BillingPlan{PlanFree, PlanBasic, PlanPro, PlanEnterprise}

	for _, plan := range plans {
		t.Run(string(plan), func(t *testing.T) {
			bm := NewBillingManager("")
			bm.RecordUsage("t-1", 1_000, 1024, 1)

			invoice, err := bm.GenerateInvoice("t-1", "T", plan, time.Now().AddDate(0, -1, 0), time.Now())
			if err != nil {
				t.Fatalf("GenerateInvoice: %v", err)
			}

			want := DefaultPlanPricing(plan)
			if invoice.BaseCost != want.BaseMonthlyCost {
				t.Errorf("BaseCost = %v, want %v (pricing table must still win for a known plan)",
					invoice.BaseCost, want.BaseMonthlyCost)
			}
			if invoice.TotalCost != bm.EstimateCost(plan, 1_000, 0, 1) {
				t.Errorf("TotalCost = %v disagrees with EstimateCost = %v for plan %q",
					invoice.TotalCost, bm.EstimateCost(plan, 1_000, 0, 1), plan)
			}
		})
	}
}

// TestBillingManager_EstimateCostUnknownPlan covers the secondary branch the fix
// touched: EstimateCost is the read-only sibling and had the same bare map
// index, so a previews/quotation for an unrecognized plan also returned 0.
func TestBillingManager_EstimateCostUnknownPlan(t *testing.T) {
	bm := NewBillingManager("")

	const (
		requests = int64(5_000_000)
		gb       = int64(900)
		attacks  = int64(12_345)
	)

	got := bm.EstimateCost(BillingPlan("pro-plus"), requests, gb, attacks)
	if got == 0 {
		t.Fatalf("EstimateCost for an unrecognized plan = 0, want the Basic fallback price")
	}
	if got != bm.EstimateCost(PlanBasic, requests, gb, attacks) {
		t.Errorf("EstimateCost(unknown) = %v, want it to equal the Basic fallback %v",
			got, bm.EstimateCost(PlanBasic, requests, gb, attacks))
	}
}

// TestBillingManager_EmptyPlanString covers the boundary case: an empty plan is
// the most likely way an unrecognized value reaches production (a cleared form
// field), and must fall back rather than bill free.
func TestBillingManager_EmptyPlanString(t *testing.T) {
	bm := NewBillingManager("")
	bm.RecordUsage("t-empty", 2_000_000, 100*(1024*1024*1024), 5)

	invoice, err := bm.GenerateInvoice("t-empty", "T", BillingPlan(""), time.Now().AddDate(0, -1, 0), time.Now())
	if err != nil {
		t.Fatalf("GenerateInvoice: %v", err)
	}
	if invoice.TotalCost == 0 {
		t.Fatalf("TotalCost = 0 for an empty plan string — an unset plan must be " +
			"priced as the Basic fallback, not billed as free")
	}
	if invoice.BaseCost != DefaultPlanPricing(PlanBasic).BaseMonthlyCost {
		t.Errorf("BaseCost = %v, want the Basic fallback %v", invoice.BaseCost, DefaultPlanPricing(PlanBasic).BaseMonthlyCost)
	}
}
