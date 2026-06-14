package tenant

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

func BenchmarkTenantResolve_ManyTenants(b *testing.B) {
	manager := NewManager(1000)
	manager.store = nil

	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("tenant-%03d", i)
		domain := fmt.Sprintf("tenant-%03d.example.com", i)
		manager.tenants[id] = &Tenant{
			ID:        id,
			Name:      fmt.Sprintf("Bench Tenant %03d", i),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Active:    true,
			Domains:   []string{domain},
			Quota:     DefaultQuota(),
		}
		manager.domains[domain] = id
		if i == 0 {
			manager.defaultTenantID = id
		}
	}

	req := httptest.NewRequest("GET", "https://tenant-999.example.com/api/data", nil)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if got := manager.ResolveTenant(req); got == nil {
			b.Fatal("tenant not resolved")
		}
	}
}
