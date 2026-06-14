package tenant

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultPlanPricing(t *testing.T) {
	tests := []struct {
		plan         BillingPlan
		wantBaseCost float64
	}{
		{PlanFree, 0},
		{PlanBasic, 29},
		{PlanPro, 99},
		{PlanEnterprise, 499},
	}

	for _, tt := range tests {
		t.Run(string(tt.plan), func(t *testing.T) {
			pricing := DefaultPlanPricing(tt.plan)
			if pricing.BaseMonthlyCost != tt.wantBaseCost {
				t.Errorf("BaseMonthlyCost = %f, want %f", pricing.BaseMonthlyCost, tt.wantBaseCost)
			}
		})
	}
}

func TestDefaultPlanPricing_Unknown(t *testing.T) {
	// Unknown plan should return Basic pricing
	pricing := DefaultPlanPricing("unknown")
	if pricing.BaseMonthlyCost != 29 {
		t.Errorf("expected basic pricing, got %f", pricing.BaseMonthlyCost)
	}
}

func TestBillingManager_NewBillingManager(t *testing.T) {
	bm := NewBillingManager("")
	if bm == nil {
		t.Fatal("expected billing manager, got nil")
	}

	if bm.pricing == nil {
		t.Error("expected pricing map to be initialized")
	}

	if bm.invoices == nil {
		t.Error("expected invoices map to be initialized")
	}

	if bm.currentUsage == nil {
		t.Error("expected currentUsage map to be initialized")
	}
}

func TestBillingManager_NewBillingManager_WithStorePath(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "billing.json")

	bm := NewBillingManager(storePath)
	if bm.storePath != storePath {
		t.Errorf("storePath = %s, want %s", bm.storePath, storePath)
	}
}

func TestBillingManager_RejectsNULStorePath(t *testing.T) {
	bm := NewBillingManager("")
	bm.storePath = "bad\x00billing.json"
	if err := bm.save(); err == nil {
		t.Fatal("expected save error for NUL store path")
	}
	if err := bm.load(); err == nil {
		t.Fatal("expected load error for NUL store path")
	}
}

func TestBillingManager_RecordUsage(t *testing.T) {
	bm := NewBillingManager("")

	bm.RecordUsage("tenant-1", 100, 1024*1024, 5)

	usage := bm.GetCurrentUsage("tenant-1")
	if usage == nil {
		t.Fatal("expected usage, got nil")
	}

	if usage.Requests != 100 {
		t.Errorf("Requests = %d, want 100", usage.Requests)
	}

	if usage.BytesTransferred != 1024*1024 {
		t.Errorf("BytesTransferred = %d, want %d", usage.BytesTransferred, 1024*1024)
	}

	if usage.BlockedAttacks != 5 {
		t.Errorf("BlockedAttacks = %d, want 5", usage.BlockedAttacks)
	}
}

func TestBillingManager_RecordUsage_Multiple(t *testing.T) {
	bm := NewBillingManager("")

	bm.RecordUsage("tenant-1", 100, 1024, 1)
	bm.RecordUsage("tenant-1", 50, 512, 2)

	usage := bm.GetCurrentUsage("tenant-1")
	if usage.Requests != 150 {
		t.Errorf("Requests = %d, want 150", usage.Requests)
	}

	if usage.BytesTransferred != 1536 {
		t.Errorf("BytesTransferred = %d, want 1536", usage.BytesTransferred)
	}

	if usage.BlockedAttacks != 3 {
		t.Errorf("BlockedAttacks = %d, want 3", usage.BlockedAttacks)
	}
}

func TestBillingManager_GetCurrentUsage_NoUsage(t *testing.T) {
	bm := NewBillingManager("")

	usage := bm.GetCurrentUsage("non-existent")
	if usage != nil {
		t.Error("expected nil for non-existent tenant")
	}
}

func TestBillingManager_GenerateInvoice(t *testing.T) {
	tmpDir := t.TempDir()
	bm := NewBillingManager(filepath.Join(tmpDir, "billing.json"))

	// Record some usage
	bm.RecordUsage("tenant-1", 100000, 10*1024*1024*1024, 10)

	now := time.Now()
	invoice, err := bm.GenerateInvoice("tenant-1", "Test Tenant", PlanBasic, now.AddDate(0, -1, 0), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if invoice.TenantID != "tenant-1" {
		t.Errorf("TenantID = %s, want tenant-1", invoice.TenantID)
	}

	if invoice.TenantName != "Test Tenant" {
		t.Errorf("TenantName = %s, want Test Tenant", invoice.TenantName)
	}

	if invoice.Plan != PlanBasic {
		t.Errorf("Plan = %s, want %s", invoice.Plan, PlanBasic)
	}

	if invoice.TotalCost <= 0 {
		t.Error("expected positive total cost")
	}
}

func TestBillingManager_GenerateInvoice_NoUsage(t *testing.T) {
	tmpDir := t.TempDir()
	bm := NewBillingManager(filepath.Join(tmpDir, "billing.json"))

	now := time.Now()
	invoice, err := bm.GenerateInvoice("tenant-1", "Test Tenant", PlanFree, now.AddDate(0, -1, 0), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if invoice.TotalCost != 0 {
		t.Errorf("TotalCost = %f, want 0 for free plan", invoice.TotalCost)
	}
}

func TestBillingManager_GenerateInvoice_ResetsUsage(t *testing.T) {
	tmpDir := t.TempDir()
	bm := NewBillingManager(filepath.Join(tmpDir, "billing.json"))

	bm.RecordUsage("tenant-1", 100000, 1024*1024*1024, 10)

	now := time.Now()
	bm.GenerateInvoice("tenant-1", "Test Tenant", PlanBasic, now.AddDate(0, -1, 0), now)

	// Usage should be reset
	usage := bm.GetCurrentUsage("tenant-1")
	if usage.Requests != 0 {
		t.Errorf("expected 0 requests after invoice, got %d", usage.Requests)
	}
}

func TestBillingManager_GetInvoices(t *testing.T) {
	tmpDir := t.TempDir()
	bm := NewBillingManager(filepath.Join(tmpDir, "billing.json"))

	// No invoices yet
	invoices := bm.GetInvoices("tenant-1")
	if invoices != nil {
		t.Error("expected nil for non-existent tenant")
	}

	// Generate invoice
	now := time.Now()
	bm.GenerateInvoice("tenant-1", "Test Tenant", PlanBasic, now.AddDate(0, -1, 0), now)

	invoices = bm.GetInvoices("tenant-1")
	if len(invoices) != 1 {
		t.Errorf("expected 1 invoice, got %d", len(invoices))
	}
}

func TestBillingManager_GetAllInvoices(t *testing.T) {
	tmpDir := t.TempDir()
	bm := NewBillingManager(filepath.Join(tmpDir, "billing.json"))

	now := time.Now()
	bm.GenerateInvoice("tenant-1", "Tenant 1", PlanBasic, now.AddDate(0, -1, 0), now)
	bm.GenerateInvoice("tenant-2", "Tenant 2", PlanPro, now.AddDate(0, -1, 0), now)

	all := bm.GetAllInvoices()
	if len(all) != 2 {
		t.Errorf("expected 2 invoices, got %d", len(all))
	}
}

func TestBillingManager_UpdateInvoiceStatus(t *testing.T) {
	tmpDir := t.TempDir()
	bm := NewBillingManager(filepath.Join(tmpDir, "billing.json"))

	now := time.Now()
	invoice, _ := bm.GenerateInvoice("tenant-1", "Test Tenant", PlanBasic, now.AddDate(0, -1, 0), now)

	// Update status
	ok := bm.UpdateInvoiceStatus(invoice.ID, "paid")
	if !ok {
		t.Error("expected successful update")
	}

	invoices := bm.GetInvoices("tenant-1")
	if invoices[0].Status != "paid" {
		t.Errorf("Status = %s, want paid", invoices[0].Status)
	}
}

func TestBillingManager_UpdateInvoiceStatus_NotFound(t *testing.T) {
	bm := NewBillingManager("")

	ok := bm.UpdateInvoiceStatus("non-existent", "paid")
	if ok {
		t.Error("expected false for non-existent invoice")
	}
}

func TestBillingManager_EstimateCost(t *testing.T) {
	bm := NewBillingManager("")

	tests := []struct {
		plan           BillingPlan
		requests       int64
		bandwidthGB    int64
		blockedAttacks int64
	}{
		{PlanFree, 10000, 1, 0},
		{PlanBasic, 100000, 10, 0},
		{PlanPro, 1000000, 100, 100},
		{PlanEnterprise, 10000000, 1000, 1000},
	}

	for _, tt := range tests {
		t.Run(string(tt.plan), func(t *testing.T) {
			cost := bm.EstimateCost(tt.plan, tt.requests, tt.bandwidthGB, tt.blockedAttacks)
			if cost < 0 {
				t.Errorf("expected non-negative cost, got %f", cost)
			}
		})
	}
}

func TestBillingManager_EstimateCost_WithOverage(t *testing.T) {
	bm := NewBillingManager("")

	// Basic plan with included 100000 requests, 10GB bandwidth
	// 200000 requests = 100000 overage
	cost := bm.EstimateCost(PlanBasic, 200000, 20, 0)

	// Should include base cost + overage
	if cost <= 29 {
		t.Errorf("expected cost > 29 (base cost), got %f", cost)
	}
}

func TestBillingManager_save_EmptyPath(t *testing.T) {
	bm := NewBillingManager("")

	// Should not panic
	err := bm.save()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBillingManager_load_EmptyPath(t *testing.T) {
	bm := NewBillingManager("")

	// Should not panic
	err := bm.load()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBillingManager_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "billing.json")

	bm1 := NewBillingManager(storePath)
	bm1.RecordUsage("tenant-1", 100000, 10*1024*1024*1024, 10)

	now := time.Now()
	bm1.GenerateInvoice("tenant-1", "Test Tenant", PlanBasic, now.AddDate(0, -1, 0), now)

	// Create new manager to load data
	bm2 := NewBillingManager(storePath)

	invoices := bm2.GetInvoices("tenant-1")
	if len(invoices) != 1 {
		t.Errorf("expected 1 invoice after load, got %d", len(invoices))
	}
}

func TestBillingManager_load_FileNotFound(t *testing.T) {
	bm := NewBillingManager("/non/existent/path.json")

	// Should not error when file doesn't exist
	err := bm.load()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGenerateInvoiceID(t *testing.T) {
	id := generateInvoiceID("tenant-12345")
	if id == "" {
		t.Error("expected non-empty ID")
	}

	// Should contain tenant prefix
	if len(id) < 10 {
		t.Error("expected ID to be reasonably long")
	}
}

func TestBillingManager_GenerateInvoice_PersistsToDisk(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "billing.json")

	bm := NewBillingManager(storePath)
	bm.RecordUsage("tenant-1", 100, 1024, 5)

	now := time.Now()
	bm.GenerateInvoice("tenant-1", "Test Tenant", PlanBasic, now.AddDate(0, -1, 0), now)

	// File should exist
	if _, err := os.Stat(storePath); os.IsNotExist(err) {
		t.Error("expected billing file to be created")
	}
}
