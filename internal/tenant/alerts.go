package tenant

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// AlertSeverity represents the severity of an alert.
type AlertSeverity string

const (
	AlertInfo     AlertSeverity = "info"
	AlertWarning  AlertSeverity = "warning"
	AlertCritical AlertSeverity = "critical"
)

// AlertType represents the type of alert.
type AlertType string

const (
	AlertQuotaWarning   AlertType = "quota_warning"
	AlertQuotaExceeded  AlertType = "quota_exceeded"
	AlertRateLimit      AlertType = "rate_limit"
	AlertSecurityEvent  AlertType = "security_event"
	AlertBillingWarning AlertType = "billing_warning"
)

// Alert represents a tenant alert notification.
type Alert struct {
	ID           string         `json:"id"`
	TenantID     string         `json:"tenant_id"`
	Type         AlertType      `json:"type"`
	Severity     AlertSeverity  `json:"severity"`
	Title        string         `json:"title"`
	Message      string         `json:"message"`
	Timestamp    time.Time      `json:"timestamp"`
	Acknowledged bool           `json:"acknowledged"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// AlertHandler is called when an alert is triggered.
type AlertHandler func(alert *Alert)

// AlertManager manages tenant alerts and notifications.
type AlertManager struct {
	mu          sync.RWMutex
	alerts      map[string][]Alert // key: tenant ID
	handlers    []AlertHandler
	cooldowns   map[string]time.Time // key: alert cooldown key
	cooldownDur time.Duration
	maxAlerts   int // per tenant
	closed      bool

	// Bounded dispatch channel
	dispatchCh chan *Alert
	stopOnce   sync.Once
	wg         sync.WaitGroup
}

// NewAlertManager creates a new alert manager.
func NewAlertManager() *AlertManager {
	am := &AlertManager{
		alerts:      make(map[string][]Alert),
		handlers:    make([]AlertHandler, 0),
		cooldowns:   make(map[string]time.Time),
		cooldownDur: 5 * time.Minute,
		maxAlerts:   100,
		dispatchCh:  make(chan *Alert, 256),
	}
	// Start bounded dispatch workers
	am.wg.Add(1)
	go am.dispatchLoop()
	return am
}

// RegisterHandler registers an alert handler.
func (am *AlertManager) RegisterHandler(handler AlertHandler) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if am.closed {
		return
	}
	am.handlers = append(am.handlers, handler)
}

// TriggerAlert creates and dispatches a new alert.
func (am *AlertManager) TriggerAlert(tenantID string, alertType AlertType, severity AlertSeverity, title, message string, metadata map[string]any) *Alert {
	// Check cooldown
	cooldownKey := fmt.Sprintf("%s:%s", tenantID, alertType)
	am.mu.RLock()
	if am.closed {
		am.mu.RUnlock()
		return nil
	}
	if lastTime, exists := am.cooldowns[cooldownKey]; exists && time.Since(lastTime) < am.cooldownDur {
		am.mu.RUnlock()
		return nil // In cooldown
	}
	am.mu.RUnlock()

	alert := &Alert{
		ID:        generateAlertID(),
		TenantID:  tenantID,
		Type:      alertType,
		Severity:  severity,
		Title:     title,
		Message:   message,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}

	am.mu.Lock()
	if am.closed {
		am.mu.Unlock()
		return nil
	}
	// Store alert
	am.alerts[tenantID] = append(am.alerts[tenantID], *alert)
	// Trim if too many
	if len(am.alerts[tenantID]) > am.maxAlerts {
		am.alerts[tenantID] = am.alerts[tenantID][len(am.alerts[tenantID])-am.maxAlerts:]
	}
	// Update cooldown
	am.cooldowns[cooldownKey] = time.Now()

	// Dispatch to handlers via bounded channel
	select {
	case am.dispatchCh <- alert:
	default:
		// Channel full — drop alert dispatch to prevent backpressure
	}
	am.mu.Unlock()

	return alert
}

// CheckQuotaAlert checks and triggers quota-related alerts.
func (am *AlertManager) CheckQuotaAlert(tenant *Tenant, currentRPM int64) {
	if tenant == nil {
		return
	}

	if tenant.Quota.MaxRequestsPerMinute <= 0 {
		return // Unlimited
	}

	percentage := float64(currentRPM) / float64(tenant.Quota.MaxRequestsPerMinute) * 100

	if percentage >= 100 {
		am.TriggerAlert(
			tenant.ID,
			AlertQuotaExceeded,
			AlertCritical,
			"Quota Exceeded",
			fmt.Sprintf("Request rate limit exceeded: %d/%d requests per minute", currentRPM, tenant.Quota.MaxRequestsPerMinute),
			map[string]any{
				"current_rpm": currentRPM,
				"limit_rpm":   tenant.Quota.MaxRequestsPerMinute,
				"percentage":  percentage,
			},
		)
	} else if percentage >= 80 {
		am.TriggerAlert(
			tenant.ID,
			AlertQuotaWarning,
			AlertWarning,
			"Approaching Quota Limit",
			fmt.Sprintf("Request rate at %.0f%% of limit: %d/%d requests per minute", percentage, currentRPM, tenant.Quota.MaxRequestsPerMinute),
			map[string]any{
				"current_rpm": currentRPM,
				"limit_rpm":   tenant.Quota.MaxRequestsPerMinute,
				"percentage":  percentage,
			},
		)
	}
}

// GetAlerts returns all alerts for a tenant.
func (am *AlertManager) GetAlerts(tenantID string, includeAcknowledged bool) []Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	alerts, exists := am.alerts[tenantID]
	if !exists {
		return nil
	}

	var result []Alert
	for _, alert := range alerts {
		if !alert.Acknowledged || includeAcknowledged {
			result = append(result, alert)
		}
	}
	return result
}

// GetRecentAlerts returns recent alerts across all tenants.
func (am *AlertManager) GetRecentAlerts(since time.Duration) []Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	cutoff := time.Now().Add(-since)
	var result []Alert
	for _, alerts := range am.alerts {
		for _, alert := range alerts {
			if alert.Timestamp.After(cutoff) {
				result = append(result, alert)
			}
		}
	}
	return result
}

// AcknowledgeAlert marks an alert as acknowledged.
func (am *AlertManager) AcknowledgeAlert(tenantID, alertID string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()

	alerts, exists := am.alerts[tenantID]
	if !exists {
		return false
	}

	for i := range alerts {
		if alerts[i].ID == alertID {
			am.alerts[tenantID][i].Acknowledged = true
			return true
		}
	}
	return false
}

// ClearAlerts removes all alerts for a tenant.
func (am *AlertManager) ClearAlerts(tenantID string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	delete(am.alerts, tenantID)
}

// GetActiveAlertCount returns the number of unacknowledged alerts.
func (am *AlertManager) GetActiveAlertCount(tenantID string) int {
	am.mu.RLock()
	defer am.mu.RUnlock()

	count := 0
	for _, alert := range am.alerts[tenantID] {
		if !alert.Acknowledged {
			count++
		}
	}
	return count
}

// Cleanup removes old acknowledged alerts.
func (am *AlertManager) Cleanup(maxAge time.Duration) {
	am.mu.Lock()
	defer am.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for tenantID, alerts := range am.alerts {
		var filtered []Alert
		for _, alert := range alerts {
			// Keep unacknowledged or recent
			if !alert.Acknowledged || alert.Timestamp.After(cutoff) {
				filtered = append(filtered, alert)
			}
		}
		if len(filtered) == 0 {
			delete(am.alerts, tenantID)
		} else {
			am.alerts[tenantID] = filtered
		}
	}

	// Cleanup cooldowns
	for key, t := range am.cooldowns {
		if time.Since(t) > am.cooldownDur*2 {
			delete(am.cooldowns, key)
		}
	}
}

// dispatchLoop runs a bounded dispatch worker that calls handlers sequentially.
func (am *AlertManager) dispatchLoop() {
	defer am.wg.Done()
	for alert := range am.dispatchCh {
		am.mu.RLock()
		handlers := make([]AlertHandler, len(am.handlers))
		copy(handlers, am.handlers)
		am.mu.RUnlock()

		for _, handler := range handlers {
			handler(alert)
		}
	}
}

// Close stops the dispatch loop.
func (am *AlertManager) Close() {
	_ = am.CloseWithContext(context.Background())
}

// CloseWithContext stops the dispatch loop and waits within ctx for any active
// alert handler to return.
func (am *AlertManager) CloseWithContext(ctx context.Context) error {
	am.stopOnce.Do(func() {
		am.mu.Lock()
		am.closed = true
		close(am.dispatchCh)
		am.mu.Unlock()
	})
	return waitForAlertDispatch(ctx, &am.wg)
}

func waitForAlertDispatch(ctx context.Context, wg *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func generateAlertID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp (extremely unlikely)
		return fmt.Sprintf("ALERT-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("ALERT-%x", b)
}
