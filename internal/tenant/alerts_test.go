package tenant

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestAlertManager_RegisterHandler(t *testing.T) {
	am := NewAlertManager()

	handler := func(alert *Alert) {}

	am.RegisterHandler(handler)

	if len(am.handlers) != 1 {
		t.Errorf("expected 1 handler, got %d", len(am.handlers))
	}
}

func TestAlertManager_TriggerAlert(t *testing.T) {
	am := NewAlertManager()

	alert := am.TriggerAlert("tenant-1", AlertQuotaWarning, AlertWarning, "Test Alert", "Test message", nil)

	if alert == nil {
		t.Fatal("expected alert, got nil")
	}

	if alert.TenantID != "tenant-1" {
		t.Errorf("TenantID = %s, want tenant-1", alert.TenantID)
	}

	if alert.Type != AlertQuotaWarning {
		t.Errorf("Type = %s, want %s", alert.Type, AlertQuotaWarning)
	}

	if alert.Severity != AlertWarning {
		t.Errorf("Severity = %s, want %s", alert.Severity, AlertWarning)
	}
}

func TestAlertManager_TriggerAlert_Cooldown(t *testing.T) {
	am := NewAlertManager()
	am.cooldownDur = 100 * time.Millisecond

	// First alert should succeed
	alert1 := am.TriggerAlert("tenant-1", AlertQuotaWarning, AlertWarning, "Test", "Test", nil)
	if alert1 == nil {
		t.Fatal("expected first alert, got nil")
	}

	// Second alert within cooldown should return nil
	alert2 := am.TriggerAlert("tenant-1", AlertQuotaWarning, AlertWarning, "Test", "Test", nil)
	if alert2 != nil {
		t.Error("expected nil alert during cooldown, got alert")
	}

	// Wait for cooldown
	time.Sleep(150 * time.Millisecond)

	// Third alert after cooldown should succeed
	alert3 := am.TriggerAlert("tenant-1", AlertQuotaWarning, AlertWarning, "Test", "Test", nil)
	if alert3 == nil {
		t.Fatal("expected alert after cooldown, got nil")
	}
}

func TestAlertManager_TriggerAlert_WithHandler(t *testing.T) {
	am := NewAlertManager()

	var mu sync.Mutex
	received := make([]*Alert, 0)
	handler := func(alert *Alert) {
		mu.Lock()
		received = append(received, alert)
		mu.Unlock()
	}

	am.RegisterHandler(handler)

	alert := am.TriggerAlert("tenant-1", AlertSecurityEvent, AlertCritical, "Security", "Test", nil)

	// Handler is called asynchronously
	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	if len(received) != 1 {
		t.Errorf("expected 1 alert received, got %d", len(received))
	}
	if received[0].ID != alert.ID {
		t.Errorf("received alert ID = %s, want %s", received[0].ID, alert.ID)
	}
	mu.Unlock()
}

func TestAlertManager_CloseWithContextWaitsForDispatchLoop(t *testing.T) {
	am := NewAlertManager()
	am.TriggerAlert("tenant-1", AlertQuotaWarning, AlertWarning, "Test Alert", "Test message", nil)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := am.CloseWithContext(ctx); err != nil {
		t.Fatalf("CloseWithContext: %v", err)
	}
}

func TestAlertManager_CloseWithContextDrainsQueuedAlerts(t *testing.T) {
	am := NewAlertManager()
	entered := make(chan struct{})
	release := make(chan struct{})
	received := make(chan AlertType, 2)
	var once sync.Once

	am.RegisterHandler(func(alert *Alert) {
		received <- alert.Type
		if alert.Type == AlertQuotaWarning {
			once.Do(func() {
				close(entered)
				<-release
			})
		}
	})

	if alert := am.TriggerAlert("tenant-1", AlertQuotaWarning, AlertWarning, "First", "queued", nil); alert == nil {
		t.Fatal("expected first alert")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first alert handler did not start")
	}
	if alert := am.TriggerAlert("tenant-1", AlertSecurityEvent, AlertCritical, "Second", "queued", nil); alert == nil {
		t.Fatal("expected second alert")
	}

	closeDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		closeDone <- am.CloseWithContext(ctx)
	}()

	close(release)
	if err := <-closeDone; err != nil {
		t.Fatalf("CloseWithContext: %v", err)
	}

	got := map[AlertType]bool{}
	for i := 0; i < 2; i++ {
		select {
		case alertType := <-received:
			got[alertType] = true
		default:
			t.Fatalf("expected 2 dispatched alerts, got %d", i)
		}
	}
	if !got[AlertQuotaWarning] || !got[AlertSecurityEvent] {
		t.Fatalf("CloseWithContext did not drain queued alerts, got %v", got)
	}
}

func TestAlertManager_RejectsNewAlertsAfterClose(t *testing.T) {
	am := NewAlertManager()
	if err := am.CloseWithContext(context.Background()); err != nil {
		t.Fatalf("CloseWithContext: %v", err)
	}

	am.RegisterHandler(func(*Alert) {
		t.Fatal("handler should not be registered after close")
	})
	alert := am.TriggerAlert("tenant-1", AlertQuotaWarning, AlertWarning, "Test Alert", "Test message", nil)
	if alert != nil {
		t.Fatalf("expected nil alert after close, got %#v", alert)
	}
	if got := am.GetAlerts("tenant-1", true); len(got) != 0 {
		t.Fatalf("expected no stored alerts after close, got %d", len(got))
	}
}

func TestAlertManager_CloseWithContextHonorsDeadline(t *testing.T) {
	am := NewAlertManager()
	entered := make(chan struct{})
	release := make(chan struct{})
	am.RegisterHandler(func(*Alert) {
		close(entered)
		<-release
	})
	am.TriggerAlert("tenant-1", AlertQuotaWarning, AlertWarning, "Test Alert", "Test message", nil)

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	err := am.CloseWithContext(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseWithContext error = %v, want deadline exceeded", err)
	}

	close(release)
	if err := am.CloseWithContext(context.Background()); err != nil {
		t.Fatalf("final CloseWithContext: %v", err)
	}
}

func TestManager_CloseWithContextClosesAlertManager(t *testing.T) {
	m := NewManager(10)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.CloseWithContext(ctx); err != nil {
		t.Fatalf("CloseWithContext: %v", err)
	}
}

type blockingClusterSync struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockingClusterSync) BroadcastEvent(string, string, string, map[string]any) error {
	close(b.entered)
	<-b.release
	return nil
}

func TestManager_CloseWithContextWaitsForClusterBroadcast(t *testing.T) {
	m := NewManager(10)
	cs := &blockingClusterSync{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	m.SetClusterSync(cs)
	if _, err := m.CreateTenant("Tenant", "desc", []string{"tenant.example.com"}, nil); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	select {
	case <-cs.entered:
	case <-time.After(time.Second):
		t.Fatal("cluster broadcast did not start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	err := m.CloseWithContext(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseWithContext error = %v, want deadline exceeded", err)
	}

	close(cs.release)
	if err := m.CloseWithContext(context.Background()); err != nil {
		t.Fatalf("final CloseWithContext: %v", err)
	}
}

func TestManager_CloseWithContextRejectsNewClusterBroadcast(t *testing.T) {
	m := NewManager(10)
	cs := &mockClusterSync{}
	m.SetClusterSync(cs)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.CloseWithContext(ctx); err != nil {
		t.Fatalf("CloseWithContext: %v", err)
	}
	if _, err := m.CreateTenant("Tenant", "desc", []string{"tenant.example.com"}, nil); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()
	if len(cs.calls) != 0 {
		t.Fatalf("expected no cluster broadcasts after close, got %v", cs.calls)
	}
}

func TestAlertManager_CheckQuotaAlert(t *testing.T) {
	am := NewAlertManager()

	tenant := &Tenant{
		ID:    "tenant-1",
		Quota: ResourceQuota{MaxRequestsPerMinute: 100},
	}

	// Below threshold
	am.CheckQuotaAlert(tenant, 50)

	// At warning threshold (80%)
	am.CheckQuotaAlert(tenant, 85)

	// At exceeded threshold (100%)
	am.CheckQuotaAlert(tenant, 100)

	// Check that alerts were created
	alerts := am.GetAlerts("tenant-1", true)
	if len(alerts) < 2 {
		t.Errorf("expected at least 2 alerts, got %d", len(alerts))
	}
}

func TestAlertManager_CheckQuotaAlert_NilTenant(t *testing.T) {
	am := NewAlertManager()

	// Should not panic
	am.CheckQuotaAlert(nil, 100)
}

func TestAlertManager_GetAlerts(t *testing.T) {
	am := NewAlertManager()

	// No alerts
	alerts := am.GetAlerts("tenant-1", true)
	if alerts != nil {
		t.Error("expected nil for non-existent tenant")
	}

	// Create alert
	am.TriggerAlert("tenant-1", AlertQuotaWarning, AlertWarning, "Test", "Test", nil)

	// Get without acknowledged
	alerts = am.GetAlerts("tenant-1", false)
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(alerts))
	}

	// Acknowledge
	alerts = am.GetAlerts("tenant-1", true)
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(alerts))
	}
}

func TestAlertManager_GetRecentAlerts(t *testing.T) {
	am := NewAlertManager()

	am.TriggerAlert("tenant-1", AlertQuotaWarning, AlertWarning, "Test", "Test", nil)
	am.TriggerAlert("tenant-2", AlertQuotaWarning, AlertWarning, "Test", "Test", nil)

	// Last hour should include both (alerts are recent)
	alerts := am.GetRecentAlerts(1 * time.Hour)
	if len(alerts) != 2 {
		t.Errorf("expected 2 alerts, got %d", len(alerts))
	}

	// Future cutoff should include none (no alerts in the future)
	alerts = am.GetRecentAlerts(-1 * time.Hour)
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts for future cutoff, got %d", len(alerts))
	}
}

func TestAlertManager_AcknowledgeAlert(t *testing.T) {
	am := NewAlertManager()

	alert := am.TriggerAlert("tenant-1", AlertQuotaWarning, AlertWarning, "Test", "Test", nil)

	// Acknowledge
	ok := am.AcknowledgeAlert("tenant-1", alert.ID)
	if !ok {
		t.Error("expected successful acknowledgment")
	}

	// Acknowledging again still returns true but alert is already acknowledged
	ok = am.AcknowledgeAlert("tenant-1", alert.ID)
	if !ok {
		t.Error("expected true when acknowledging already acknowledged alert")
	}

	// Verify it's acknowledged
	alerts := am.GetAlerts("tenant-1", false)
	if len(alerts) != 0 {
		t.Error("expected 0 unacknowledged alerts after ack")
	}

	// Acknowledge non-existent should return false
	ok = am.AcknowledgeAlert("tenant-1", "non-existent")
	if ok {
		t.Error("expected false for non-existent alert")
	}
}

func TestAlertManager_ClearAlerts(t *testing.T) {
	am := NewAlertManager()

	am.TriggerAlert("tenant-1", AlertQuotaWarning, AlertWarning, "Test", "Test", nil)
	am.TriggerAlert("tenant-1", AlertQuotaExceeded, AlertCritical, "Test", "Test", nil)

	// Clear
	am.ClearAlerts("tenant-1")

	alerts := am.GetAlerts("tenant-1", true)
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts after clear, got %d", len(alerts))
	}
}

func TestAlertManager_GetActiveAlertCount(t *testing.T) {
	am := NewAlertManager()

	count := am.GetActiveAlertCount("tenant-1")
	if count != 0 {
		t.Errorf("expected 0 count, got %d", count)
	}

	alert := am.TriggerAlert("tenant-1", AlertQuotaWarning, AlertWarning, "Test", "Test", nil)

	count = am.GetActiveAlertCount("tenant-1")
	if count != 1 {
		t.Errorf("expected 1 count, got %d", count)
	}

	am.AcknowledgeAlert("tenant-1", alert.ID)

	count = am.GetActiveAlertCount("tenant-1")
	if count != 0 {
		t.Errorf("expected 0 count after ack, got %d", count)
	}
}

func TestAlertManager_Cleanup(t *testing.T) {
	am := NewAlertManager()

	alert := am.TriggerAlert("tenant-1", AlertQuotaWarning, AlertWarning, "Test", "Test", nil)
	am.AcknowledgeAlert("tenant-1", alert.ID)

	// Old cleanup
	am.Cleanup(24 * time.Hour)

	// Alerts should still exist (recent)
	alerts := am.GetAlerts("tenant-1", true)
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert after recent cleanup, got %d", len(alerts))
	}
}

func TestAlertManager_MultipleTenants(t *testing.T) {
	am := NewAlertManager()

	am.TriggerAlert("tenant-1", AlertQuotaWarning, AlertWarning, "Test1", "Test", nil)
	am.TriggerAlert("tenant-2", AlertQuotaWarning, AlertWarning, "Test2", "Test", nil)
	am.TriggerAlert("tenant-1", AlertQuotaExceeded, AlertCritical, "Test3", "Test", nil)

	if am.GetActiveAlertCount("tenant-1") != 2 {
		t.Errorf("expected 2 alerts for tenant-1, got %d", am.GetActiveAlertCount("tenant-1"))
	}

	if am.GetActiveAlertCount("tenant-2") != 1 {
		t.Errorf("expected 1 alert for tenant-2, got %d", am.GetActiveAlertCount("tenant-2"))
	}
}
