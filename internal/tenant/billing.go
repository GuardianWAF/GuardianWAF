package tenant

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// BillingPlan defines pricing for different tenant plans.
type BillingPlan string

const (
	PlanFree       BillingPlan = "free"
	PlanBasic      BillingPlan = "basic"
	PlanPro        BillingPlan = "pro"
	PlanEnterprise BillingPlan = "enterprise"
)

// PlanPricing defines the cost structure for a plan.
type PlanPricing struct {
	BaseMonthlyCost      float64 `json:"base_monthly_cost"`
	PerRequestCost       float64 `json:"per_request_cost"`       // per 1000 requests
	PerGBBandwidthCost   float64 `json:"per_gb_bandwidth_cost"`
	PerBlockedAttackCost float64 `json:"per_blocked_attack_cost"` // security value
	IncludedRequests     int64   `json:"included_requests"`
	IncludedBandwidthGB  int64   `json:"included_bandwidth_gb"`
	OverageRate          float64 `json:"overage_rate"` // multiplier for overage
}

// DefaultPlanPricing returns default pricing for plans.
func DefaultPlanPricing(plan BillingPlan) PlanPricing {
	switch plan {
	case PlanFree:
		return PlanPricing{
			BaseMonthlyCost:     0,
			PerRequestCost:      0,
			PerGBBandwidthCost:  0,
			IncludedRequests:    10000,
			IncludedBandwidthGB: 1,
		}
	case PlanBasic:
		return PlanPricing{
			BaseMonthlyCost:      29,
			PerRequestCost:       0.50,
			PerGBBandwidthCost:   0.10,
			PerBlockedAttackCost: 0.01,
			IncludedRequests:     100000,
			IncludedBandwidthGB:  10,
			OverageRate:          1.5,
		}
	case PlanPro:
		return PlanPricing{
			BaseMonthlyCost:      99,
			PerRequestCost:       0.30,
			PerGBBandwidthCost:   0.08,
			PerBlockedAttackCost: 0.005,
			IncludedRequests:     1000000,
			IncludedBandwidthGB:  100,
			OverageRate:          1.2,
		}
	case PlanEnterprise:
		return PlanPricing{
			BaseMonthlyCost:      499,
			PerRequestCost:       0.10,
			PerGBBandwidthCost:   0.05,
			PerBlockedAttackCost: 0.001,
			IncludedRequests:     10000000,
			IncludedBandwidthGB:  1000,
			OverageRate:          1.0,
		}
	default:
		return DefaultPlanPricing(PlanBasic)
	}
}

// UsageMetrics tracks billable usage for a tenant.
type UsageMetrics struct {
	Requests       int64   `json:"requests"`
	BytesTransferred int64 `json:"bytes_transferred"`
	BlockedAttacks int64   `json:"blocked_attacks"`
	PeriodStart    time.Time `json:"period_start"`
	PeriodEnd      time.Time `json:"period_end"`
}

// Invoice represents a billing invoice for a tenant.
type Invoice struct {
	ID              string      `json:"id"`
	TenantID        string      `json:"tenant_id"`
	TenantName      string      `json:"tenant_name"`
	Plan            BillingPlan `json:"plan"`
	PeriodStart     time.Time   `json:"period_start"`
	PeriodEnd       time.Time   `json:"period_end"`
	Usage           UsageMetrics `json:"usage"`
	BaseCost        float64     `json:"base_cost"`
	RequestCost     float64     `json:"request_cost"`
	BandwidthCost   float64     `json:"bandwidth_cost"`
	SecurityCost    float64     `json:"security_cost"`
	TotalCost       float64     `json:"total_cost"`
	Status          string      `json:"status"` // "draft", "pending", "paid", "overdue"
	CreatedAt       time.Time   `json:"created_at"`
}

// BillingManager handles tenant billing and metering.
type BillingManager struct {
	mu          sync.RWMutex
	pricing     map[BillingPlan]PlanPricing
	invoices    map[string][]Invoice // key: tenant ID
	currentUsage map[string]*UsageMetrics // key: tenant ID
	storePath   string
}

// NewBillingManager creates a new billing manager.
func NewBillingManager(storePath string) *BillingManager {
	bm := &BillingManager{
		pricing:      make(map[BillingPlan]PlanPricing),
		invoices:     make(map[string][]Invoice),
		currentUsage: make(map[string]*UsageMetrics),
		storePath:    storePath,
	}

	// Initialize default pricing
	bm.pricing[PlanFree] = DefaultPlanPricing(PlanFree)
	bm.pricing[PlanBasic] = DefaultPlanPricing(PlanBasic)
	bm.pricing[PlanPro] = DefaultPlanPricing(PlanPro)
	bm.pricing[PlanEnterprise] = DefaultPlanPricing(PlanEnterprise)

	// Load persisted data
	if err := bm.load(); err != nil {
		log.Printf("[billing] warning: failed to load billing data: %v", err)
	}

	return bm
}

// RecordUsage records usage for billing calculation.
func (bm *BillingManager) RecordUsage(tenantID string, requests int64, bytesTransferred int64, blockedAttacks int64) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	usage, exists := bm.currentUsage[tenantID]
	if !exists {
		usage = &UsageMetrics{
			PeriodStart: time.Now(),
		}
		bm.currentUsage[tenantID] = usage
	}

	usage.Requests += requests
	usage.BytesTransferred += bytesTransferred
	usage.BlockedAttacks += blockedAttacks
	usage.PeriodEnd = time.Now()
}

// GetCurrentUsage returns current usage for a tenant.
func (bm *BillingManager) GetCurrentUsage(tenantID string) *UsageMetrics {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	if usage, exists := bm.currentUsage[tenantID]; exists {
		// Return copy
		copy := *usage
		return &copy
	}
	return nil
}

// GenerateInvoice creates an invoice for a tenant's usage.
func (bm *BillingManager) GenerateInvoice(tenantID, tenantName string, plan BillingPlan, periodStart, periodEnd time.Time) (*Invoice, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	usage := bm.currentUsage[tenantID]
	if usage == nil {
		usage = &UsageMetrics{}
	}

	pricing := bm.pricing[plan]

	// Calculate costs
	baseCost := pricing.BaseMonthlyCost

	// Request costs (overage)
	requestOverage := usage.Requests - pricing.IncludedRequests
	var requestCost float64
	if requestOverage > 0 {
		requestCost = float64(requestOverage) / 1000 * pricing.PerRequestCost * pricing.OverageRate
	}

	// Bandwidth costs (overage)
	bandwidthGB := float64(usage.BytesTransferred) / (1024 * 1024 * 1024)
	bandwidthOverage := bandwidthGB - float64(pricing.IncludedBandwidthGB)
	var bandwidthCost float64
	if bandwidthOverage > 0 {
		bandwidthCost = float64(bandwidthOverage) * pricing.PerGBBandwidthCost * pricing.OverageRate
	}

	// Security value (blocked attacks)
	securityCost := float64(usage.BlockedAttacks) * pricing.PerBlockedAttackCost

	totalCost := baseCost + requestCost + bandwidthCost + securityCost

	invoice := &Invoice{
		ID:              generateInvoiceID(tenantID),
		TenantID:        tenantID,
		TenantName:      tenantName,
		Plan:            plan,
		PeriodStart:     periodStart,
		PeriodEnd:       periodEnd,
		Usage:           *usage,
		BaseCost:        baseCost,
		RequestCost:     requestCost,
		BandwidthCost:   bandwidthCost,
		SecurityCost:    securityCost,
		TotalCost:       totalCost,
		Status:          "draft",
		CreatedAt:       time.Now(),
	}

	// Store invoice
	bm.invoices[tenantID] = append(bm.invoices[tenantID], *invoice)

	// Reset current usage
	bm.currentUsage[tenantID] = &UsageMetrics{
		PeriodStart: time.Now(),
	}

	// Persist
	if err := bm.save(); err != nil {
		log.Printf("[billing] warning: failed to save billing data: %v", err)
	}

	return invoice, nil
}

// GetInvoices returns all invoices for a tenant.
func (bm *BillingManager) GetInvoices(tenantID string) []Invoice {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	if invoices, exists := bm.invoices[tenantID]; exists {
		// Return copy
		result := make([]Invoice, len(invoices))
		copy(result, invoices)
		return result
	}
	return nil
}

// GetAllInvoices returns all invoices.
func (bm *BillingManager) GetAllInvoices() []Invoice {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	var all []Invoice
	for _, invoices := range bm.invoices {
		all = append(all, invoices...)
	}
	return all
}

// UpdateInvoiceStatus updates the status of an invoice.
func (bm *BillingManager) UpdateInvoiceStatus(invoiceID, status string) bool {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	for tenantID, invoices := range bm.invoices {
		for i := range invoices {
			if invoices[i].ID == invoiceID {
				bm.invoices[tenantID][i].Status = status
				if err := bm.save(); err != nil {
					log.Printf("[billing] warning: failed to save billing data: %v", err)
				}
				return true
			}
		}
	}
	return false
}

// EstimateCost estimates the cost for projected usage.
func (bm *BillingManager) EstimateCost(plan BillingPlan, requests int64, bandwidthGB int64, blockedAttacks int64) float64 {
	pricing := bm.pricing[plan]

	baseCost := pricing.BaseMonthlyCost

	requestOverage := requests - pricing.IncludedRequests
	var requestCost float64
	if requestOverage > 0 {
		requestCost = float64(requestOverage) / 1000 * pricing.PerRequestCost * pricing.OverageRate
	}

	bandwidthOverage := bandwidthGB - pricing.IncludedBandwidthGB
	var bandwidthCost float64
	if bandwidthOverage > 0 {
		bandwidthCost = float64(bandwidthOverage) * pricing.PerGBBandwidthCost * pricing.OverageRate
	}

	securityCost := float64(blockedAttacks) * pricing.PerBlockedAttackCost

	return baseCost + requestCost + bandwidthCost + securityCost
}

// save persists billing data to disk.
func (bm *BillingManager) save() error {
	if bm.storePath == "" {
		return nil
	}

	data := struct {
		Invoices     map[string][]Invoice    `json:"invoices"`
		CurrentUsage map[string]*UsageMetrics `json:"current_usage"`
	}{
		Invoices:     bm.invoices,
		CurrentUsage: bm.currentUsage,
	}

	_ = os.MkdirAll(filepath.Dir(bm.storePath), 0755)
	file, err := os.Create(bm.storePath)
	if err != nil {
		return fmt.Errorf("creating billing store file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// load loads billing data from disk.
func (bm *BillingManager) load() error {
	if bm.storePath == "" {
		return nil
	}

	file, err := os.Open(bm.storePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	var data struct {
		Invoices     map[string][]Invoice     `json:"invoices"`
		CurrentUsage map[string]*UsageMetrics `json:"current_usage"`
	}

	if err := json.NewDecoder(file).Decode(&data); err != nil {
		return err
	}

	bm.invoices = data.Invoices
	bm.currentUsage = data.CurrentUsage
	return nil
}

func generateInvoiceID(tenantID string) string {
	prefix := tenantID
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	now := time.Now()
	return fmt.Sprintf("INV-%s-%d%03d", prefix, now.Unix(), now.Nanosecond()/1e6)
}
