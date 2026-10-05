package tenant

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUsageMetadataMatchesSingleAndAggregateEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name   string
		active bool
	}{
		{"Ordinary tenant", true},
		{"Disabled tenant", false},
		{"", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ten := &Tenant{ID: "ordinary", Name: tc.name, Active: tc.active, RequestCount: 7, ByteCount: 123}
			m := &Manager{tenants: map[string]*Tenant{ten.ID: ten}}
			h := NewHandlers(m)
			h.SetAPIKey("local-audit-key")
			r := httptest.NewRequest(http.MethodGet, "/usage", nil)
			r.Header.Set("X-API-Key", "local-audit-key")
			all := httptest.NewRecorder()
			h.GetAllUsage(all, r)
			var group struct {
				Tenants []UsageStats `json:"tenants"`
			}
			if err := json.Unmarshal(all.Body.Bytes(), &group); err != nil {
				t.Fatal(err)
			}
			if all.Code != http.StatusOK || len(group.Tenants) != 1 {
				t.Fatalf("aggregate usage: status=%d tenants=%d", all.Code, len(group.Tenants))
			}
			single := httptest.NewRecorder()
			h.GetTenantUsage(single, r, ten.ID)
			var got UsageStats
			if err := json.Unmarshal(single.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if single.Code != http.StatusOK || got.Name != tc.name || got.Active != tc.active {
				t.Fatalf("single usage: status=%d name=%q active=%v", single.Code, got.Name, got.Active)
			}
			if got != group.Tenants[0] || got.TotalRequests != 7 || got.BytesTransferred != 123 {
				t.Fatalf("single=%+v aggregate=%+v", got, group.Tenants[0])
			}
			missing := httptest.NewRecorder()
			h.GetTenantUsage(missing, r, "missing")
			if missing.Code != http.StatusNotFound {
				t.Fatalf("missing tenant: status=%d", missing.Code)
			}
		})
	}
}
