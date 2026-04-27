package v040

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

// ---------- NewIntegrator: Phase 2 and beyond features ----------

func TestNewIntegrator_WithGRPC(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.GRPC.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with gRPC failed: %v", err)
	}
	if i.grpcProxy == nil {
		t.Error("grpcProxy should be initialized")
	}
	if i.GetGRPCProxy() == nil {
		t.Error("GetGRPCProxy should return non-nil")
	}
}

func TestNewIntegrator_WithTenant(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Tenant.Enabled = true
	cfg.WAF.Tenant.MaxTenants = 10

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with tenant failed: %v", err)
	}
	if i.tenantIntegrator == nil {
		t.Error("tenantIntegrator should be initialized")
	}
	if i.GetTenantIntegrator() == nil {
		t.Error("GetTenantIntegrator should return non-nil")
	}
}

func TestNewIntegrator_WithDLP(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.DLP.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with DLP failed: %v", err)
	}
	if i.dlpLayer == nil {
		t.Error("dlpLayer should be initialized")
	}
	if i.GetDLPLayer() == nil {
		t.Error("GetDLPLayer should return non-nil")
	}
}

func TestNewIntegrator_WithZeroTrust(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ZeroTrust.Enabled = true
	cfg.WAF.ZeroTrust.DeviceTrustThreshold = "low"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with ZeroTrust failed: %v", err)
	}
	if i.zeroTrustService == nil {
		t.Error("zeroTrustService should be initialized")
	}
	if i.GetZeroTrustService() == nil {
		t.Error("GetZeroTrustService should return non-nil")
	}
}

func TestNewIntegrator_WithZeroTrust_HighThreshold(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ZeroTrust.Enabled = true
	cfg.WAF.ZeroTrust.DeviceTrustThreshold = "high"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with ZeroTrust high threshold failed: %v", err)
	}
	if i.zeroTrustService == nil {
		t.Error("zeroTrustService should be initialized")
	}
}

func TestNewIntegrator_WithZeroTrust_MaximumThreshold(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ZeroTrust.Enabled = true
	cfg.WAF.ZeroTrust.DeviceTrustThreshold = "maximum"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with ZeroTrust maximum threshold failed: %v", err)
	}
	if i.zeroTrustService == nil {
		t.Error("zeroTrustService should be initialized")
	}
}

func TestNewIntegrator_WithZeroTrust_NoneThreshold(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ZeroTrust.Enabled = true
	cfg.WAF.ZeroTrust.DeviceTrustThreshold = "none"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with ZeroTrust none threshold failed: %v", err)
	}
	if i.zeroTrustService == nil {
		t.Error("zeroTrustService should be initialized")
	}
}

func TestNewIntegrator_WithZeroTrust_MediumThreshold(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ZeroTrust.Enabled = true
	cfg.WAF.ZeroTrust.DeviceTrustThreshold = "medium"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with ZeroTrust medium threshold failed: %v", err)
	}
	if i.zeroTrustService == nil {
		t.Error("zeroTrustService should be initialized")
	}
}

func TestNewIntegrator_WithZeroTrust_DefaultThreshold(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ZeroTrust.Enabled = true
	cfg.WAF.ZeroTrust.DeviceTrustThreshold = "unknown_value"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with ZeroTrust default threshold failed: %v", err)
	}
	if i.zeroTrustService == nil {
		t.Error("zeroTrustService should be initialized (default should be medium)")
	}
}

func TestNewIntegrator_WithSIEM(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.SIEM.Enabled = true
	cfg.WAF.SIEM.Endpoint = "" // empty endpoint skips validation
	cfg.WAF.SIEM.Format = "json"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with SIEM failed: %v", err)
	}
	if i.siemExporter == nil {
		t.Error("siemExporter should be initialized")
	}
	if i.GetSIEMExporter() == nil {
		t.Error("GetSIEMExporter should return non-nil")
	}

	// Cleanup to stop the exporter goroutine
	i.Cleanup()
}

func TestNewIntegrator_WithCache(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Cache.Enabled = true
	cfg.WAF.Cache.Backend = "memory"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with Cache failed: %v", err)
	}
	if i.cacheLayer == nil {
		t.Error("cacheLayer should be initialized")
	}
}

func TestNewIntegrator_WithReplay(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "v040-replay-*")
	cfg := config.DefaultConfig()
	cfg.WAF.Replay.Enabled = true
	cfg.WAF.Replay.StoragePath = tmpDir

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with Replay failed: %v", err)
	}
	if i.replayManager == nil {
		t.Error("replayManager should be initialized")
	}
	if i.GetReplayManager() == nil {
		t.Error("GetReplayManager should return non-nil")
	}
	if i.replayManager != nil {
		_ = i.replayManager.Close()
	}
	i.Cleanup()
}

func TestNewIntegrator_WithReplaySubConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Replay.Enabled = false
	cfg.WAF.Replay.Replay.Enabled = true
	cfg.WAF.Replay.StoragePath = t.TempDir()

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with Replay sub-config failed: %v", err)
	}
	if i.replayManager == nil {
		t.Error("replayManager should be initialized when Replay.Replay.Enabled is true")
	}
	i.Cleanup()
}

func TestNewIntegrator_WithCanary(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Canary.Enabled = true
	cfg.WAF.Canary.Strategy = "percentage"
	cfg.WAF.Canary.Percentage = 20
	cfg.WAF.Canary.StableUpstream = "http://localhost:8080"
	cfg.WAF.Canary.CanaryUpstream = "http://localhost:8081"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with Canary failed: %v", err)
	}
	if i.canaryLayer == nil {
		t.Error("canaryLayer should be initialized")
	}
	if i.GetCanaryLayer() == nil {
		t.Error("GetCanaryLayer should return non-nil")
	}
}

func TestNewIntegrator_WithWebSocket(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.WebSocket.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with WebSocket failed: %v", err)
	}
	if i.websocketLayer == nil {
		t.Error("websocketLayer should be initialized")
	}
	if i.GetWebSocketLayer() == nil {
		t.Error("GetWebSocketLayer should return non-nil")
	}
}

func TestNewIntegrator_WithAnalytics(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Analytics.Enabled = true
	cfg.WAF.Analytics.StoragePath = t.TempDir()

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with Analytics failed: %v", err)
	}
	if i.analyticsLayer == nil {
		t.Error("analyticsLayer should be initialized")
	}
	if i.GetAnalyticsLayer() == nil {
		t.Error("GetAnalyticsLayer should return non-nil")
	}
}

func TestNewIntegrator_WithClusterSync(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ClusterSync.Enabled = true
	cfg.WAF.ClusterSync.NodeID = "node-1"
	cfg.WAF.ClusterSync.NodeName = "test-node"
	cfg.WAF.ClusterSync.Port = 0 // avoid binding
	cfg.WAF.ClusterSync.SharedSecret = "test-secret"
	cfg.WAF.ClusterSync.ConflictResolution = "source_priority"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with ClusterSync failed: %v", err)
	}
	if i.clusterSyncManager == nil {
		t.Error("clusterSyncManager should be initialized")
	}
	// Stop the background workers
	i.clusterSyncManager.Stop()
}

func TestNewIntegrator_WithClusterSync_ManualConflict(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ClusterSync.Enabled = true
	cfg.WAF.ClusterSync.NodeID = "node-2"
	cfg.WAF.ClusterSync.ConflictResolution = "manual"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with ClusterSync manual conflict resolution failed: %v", err)
	}
	if i.clusterSyncManager == nil {
		t.Error("clusterSyncManager should be initialized")
	}
	i.clusterSyncManager.Stop()
}

func TestNewIntegrator_WithClusterSync_DefaultConflict(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ClusterSync.Enabled = true
	cfg.WAF.ClusterSync.NodeID = "node-3"
	cfg.WAF.ClusterSync.ConflictResolution = "unknown"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with ClusterSync default conflict resolution failed: %v", err)
	}
	if i.clusterSyncManager == nil {
		t.Error("clusterSyncManager should be initialized")
	}
	i.clusterSyncManager.Stop()
}

func TestNewIntegrator_WithClusterSync_ClustersWithNodes(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ClusterSync.Enabled = true
	cfg.WAF.ClusterSync.NodeID = "node-1"
	cfg.WAF.ClusterSync.Clusters = []config.ClusterMembership{
		{
			ID:            "cluster-1",
			Name:          "Test Cluster",
			SyncScope:     "all",
			Bidirectional: true,
			Nodes: []config.ClusterNodeConfig{
				{ID: "node-1", Name: "Local", Address: "http://127.0.0.1:9445"},
				{ID: "node-2", Name: "Remote", Address: "http://127.0.0.1:9446"},
			},
		},
	}

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with ClusterSync clusters+nodes failed: %v", err)
	}
	if i.clusterSyncManager == nil {
		t.Error("clusterSyncManager should be initialized")
	}
	i.clusterSyncManager.Stop()
}

func TestNewIntegrator_WithRemediation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Remediation.Enabled = true
	cfg.WAF.Remediation.AutoApply = true
	cfg.WAF.Remediation.StoragePath = t.TempDir()

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with Remediation failed: %v", err)
	}
	if i.remediationLayer == nil {
		t.Error("remediationLayer should be initialized")
	}
	if i.GetRemediationLayer() == nil {
		t.Error("GetRemediationLayer should return non-nil")
	}
	if i.GetRemediationEngine() == nil {
		t.Error("GetRemediationEngine should return non-nil")
	}
}

// ---------- RegisterLayers ----------

func TestIntegrator_RegisterLayers(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.MLAnomaly.Enabled = true
	cfg.WAF.APIDiscovery.Enabled = true
	cfg.WAF.GraphQL.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Enabled = true
	cfg.WAF.DLP.Enabled = true
	cfg.WAF.GRPC.Enabled = true
	cfg.WAF.WebSocket.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(100), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// RegisterLayers should not panic
	i.RegisterLayers(eng)
}

func TestIntegrator_RegisterLayers_NilLayers(t *testing.T) {
	cfg := config.DefaultConfig()
	// All features disabled - no layers to register

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(100), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// Should not panic with all nil layers
	i.RegisterLayers(eng)
}

// ---------- RegisterHandlers ----------

func TestIntegrator_RegisterHandlers(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIDiscovery.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Biometric.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Captcha.Enabled = true
	cfg.WAF.Tenant.Enabled = true
	cfg.WAF.Tenant.MaxTenants = 10

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	mux := http.NewServeMux()
	// Should not panic
	i.RegisterHandlers(mux)
}

func TestIntegrator_RegisterHandlers_NilComponents(t *testing.T) {
	cfg := config.DefaultConfig()
	// All features disabled - no handlers to register

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	mux := http.NewServeMux()
	// Should not panic with all nil components
	i.RegisterHandlers(mux)
}

// ---------- RecordRequest ----------

func TestIntegrator_RecordRequest(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIDiscovery.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/users", nil)
	// Should not panic
	i.RecordRequest(req, 200)
}

func TestIntegrator_RecordRequest_Disabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIDiscovery.Enabled = false

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/users", nil)
	// Should not panic when discovery is nil
	i.RecordRequest(req, 200)
}

// ---------- RecordRequestForReplay ----------

func TestIntegrator_RecordRequestForReplay(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Replay.Enabled = true
	cfg.WAF.Replay.StoragePath = t.TempDir()

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	resp := &http.Response{StatusCode: 200}

	err = i.RecordRequestForReplay(req, resp, time.Millisecond*10)
	if err != nil {
		t.Errorf("RecordRequestForReplay should not error: %v", err)
	}
	i.Cleanup()
}

func TestIntegrator_RecordRequestForReplay_Nil(t *testing.T) {
	cfg := config.DefaultConfig()
	// Replay disabled

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	resp := &http.Response{StatusCode: 200}

	err = i.RecordRequestForReplay(req, resp, time.Millisecond*10)
	if err != nil {
		t.Errorf("RecordRequestForReplay should return nil when disabled, got: %v", err)
	}
}

// ---------- ZeroTrustMiddleware ----------

func TestIntegrator_ZeroTrustMiddleware(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ZeroTrust.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := i.ZeroTrustMiddleware(inner)
	if handler == nil {
		t.Fatal("ZeroTrustMiddleware should not return nil")
	}

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// The ZeroTrust middleware may block or pass; just ensure no panic
}

func TestIntegrator_ZeroTrustMiddleware_NilService(t *testing.T) {
	cfg := config.DefaultConfig()
	// ZeroTrust disabled

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := i.ZeroTrustMiddleware(inner)
	if handler == nil {
		t.Fatal("ZeroTrustMiddleware should not return nil even with nil service")
	}

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 with nil service (passthrough), got %d", rr.Code)
	}
}

// ---------- TenantMiddleware ----------

func TestIntegrator_TenantMiddleware(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Tenant.Enabled = true
	cfg.WAF.Tenant.MaxTenants = 10

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := i.TenantMiddleware(inner)
	if handler == nil {
		t.Fatal("TenantMiddleware should not return nil")
	}

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Just ensure no panic
}

func TestIntegrator_TenantMiddleware_NilIntegrator(t *testing.T) {
	cfg := config.DefaultConfig()
	// Tenant disabled

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := i.TenantMiddleware(inner)
	if handler == nil {
		t.Fatal("TenantMiddleware should not return nil")
	}

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 with nil tenant integrator (passthrough), got %d", rr.Code)
	}
}

// ---------- CanaryMiddleware ----------

func TestIntegrator_CanaryMiddleware_Nil(t *testing.T) {
	cfg := config.DefaultConfig()
	// Canary disabled

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := i.CanaryMiddleware(inner)
	if handler == nil {
		t.Fatal("CanaryMiddleware should not return nil")
	}

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 with nil canary (passthrough), got %d", rr.Code)
	}
}

// ---------- Get methods ----------

func TestIntegrator_GetMethods_AllNil(t *testing.T) {
	cfg := config.DefaultConfig()
	// Explicitly disable all features (some are enabled by default)
	cfg.WAF.MLAnomaly.Enabled = false
	cfg.WAF.APIDiscovery.Enabled = false
	cfg.WAF.GraphQL.Enabled = false
	cfg.WAF.BotDetection.Enhanced.Enabled = false
	cfg.WAF.GRPC.Enabled = false
	cfg.WAF.Tenant.Enabled = false
	cfg.WAF.DLP.Enabled = false
	cfg.WAF.ZeroTrust.Enabled = false
	cfg.WAF.SIEM.Enabled = false
	cfg.WAF.Cache.Enabled = false
	cfg.WAF.Replay.Enabled = false
	cfg.WAF.Replay.Replay.Enabled = false
	cfg.WAF.Canary.Enabled = false
	cfg.WAF.Analytics.Enabled = false
	cfg.WAF.ClusterSync.Enabled = false
	cfg.WAF.Remediation.Enabled = false
	cfg.WAF.WebSocket.Enabled = false

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	if i.GetAPIDiscovery() != nil {
		t.Error("GetAPIDiscovery should be nil when disabled")
	}
	if i.GetEnhancedBotLayer() != nil {
		t.Error("GetEnhancedBotLayer should be nil when disabled")
	}
	if i.GetGRPCProxy() != nil {
		t.Error("GetGRPCProxy should be nil when disabled")
	}
	if i.GetTenantIntegrator() != nil {
		t.Error("GetTenantIntegrator should be nil when disabled")
	}
	if i.GetDLPLayer() != nil {
		t.Error("GetDLPLayer should be nil when disabled")
	}
	if i.GetZeroTrustService() != nil {
		t.Error("GetZeroTrustService should be nil when disabled")
	}
	if i.GetSIEMExporter() != nil {
		t.Error("GetSIEMExporter should be nil when disabled")
	}
	if i.GetReplayManager() != nil {
		t.Error("GetReplayManager should be nil when disabled")
	}
	if i.GetCanaryLayer() != nil {
		t.Error("GetCanaryLayer should be nil when disabled")
	}
	if i.GetAnalyticsLayer() != nil {
		t.Error("GetAnalyticsLayer should be nil when disabled")
	}
	if i.GetClusterLayer() != nil {
		t.Error("GetClusterLayer should be nil when disabled")
	}
	if i.GetCluster() != nil {
		t.Error("GetCluster should be nil when clusterLayer is nil")
	}
	if i.GetRemediationLayer() != nil {
		t.Error("GetRemediationLayer should be nil when disabled")
	}
	if i.GetRemediationEngine() != nil {
		t.Error("GetRemediationEngine should be nil when remediationLayer is nil")
	}
	if i.GetWebSocketLayer() != nil {
		t.Error("GetWebSocketLayer should be nil when disabled")
	}
	if i.GetWebSocketSecurity() != nil {
		t.Error("GetWebSocketSecurity should be nil when websocketLayer is nil")
	}
	if i.WebSocketHandler() != nil {
		t.Error("WebSocketHandler should be nil when websocketLayer is nil")
	}
	if i.GetGRPCLayer() != nil {
		t.Error("GetGRPCLayer should be nil when gRPC layer is not initialized")
	}
	if i.GetGRPCSecurity() != nil {
		t.Error("GetGRPCSecurity should be nil when grpcLayer is nil")
	}
	if i.GRPCHandler() != nil {
		t.Error("GRPCHandler should be nil when grpcLayer is nil")
	}
}

// ---------- Cluster helper methods ----------

func TestIntegrator_ClusterMethods_Nil(t *testing.T) {
	cfg := config.DefaultConfig()

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	if i.IsClusterLeader() {
		t.Error("IsClusterLeader should be false when clusterLayer is nil")
	}
	if i.GetClusterNodeCount() != 1 {
		t.Errorf("GetClusterNodeCount should be 1 when clusterLayer is nil, got %d", i.GetClusterNodeCount())
	}
}

// ---------- Cleanup ----------

func TestIntegrator_Cleanup_AllComponents(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIDiscovery.Enabled = true
	cfg.WAF.MLAnomaly.Enabled = true
	cfg.WAF.SIEM.Enabled = true
	cfg.WAF.SIEM.Endpoint = "" // empty endpoint skips SIEM URL validation
	cfg.WAF.WebSocket.Enabled = true
	cfg.WAF.GRPC.Enabled = true
	cfg.WAF.Remediation.Enabled = true
	cfg.WAF.Remediation.StoragePath = t.TempDir()

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	// Cleanup should not panic with all components
	i.Cleanup()
}

// ---------- GetStats with various features enabled ----------

func TestIntegrator_GetStats_WithDLP(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.DLP.Enabled = true
	cfg.WAF.DLP.BlockOnMatch = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	stats := i.GetStats()
	if !stats.DLPEnabled {
		t.Error("DLPEnabled should be true")
	}
	if !stats.DLPBlockOnMatch {
		t.Error("DLPBlockOnMatch should be true")
	}
}

func TestIntegrator_GetStats_WithZeroTrust(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ZeroTrust.Enabled = true
	cfg.WAF.ZeroTrust.RequireMTLS = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	stats := i.GetStats()
	if !stats.ZeroTrustEnabled {
		t.Error("ZeroTrustEnabled should be true")
	}
	if !stats.ZeroTrustRequireMTLS {
		t.Error("ZeroTrustRequireMTLS should be true")
	}
}

func TestIntegrator_GetStats_WithSIEM(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.SIEM.Enabled = true
	cfg.WAF.SIEM.Format = "cef"
	cfg.WAF.SIEM.Endpoint = "" // empty endpoint skips SIEM URL validation

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}
	defer i.Cleanup()

	stats := i.GetStats()
	if !stats.SIEMEnabled {
		t.Error("SIEMEnabled should be true")
	}
	if stats.SIEMFormat != "cef" {
		t.Errorf("SIEMFormat should be 'cef', got '%s'", stats.SIEMFormat)
	}
}

func TestIntegrator_GetStats_WithCache(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Cache.Enabled = true
	cfg.WAF.Cache.Backend = "memory"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	stats := i.GetStats()
	if !stats.CacheEnabled {
		t.Error("CacheEnabled should be true")
	}
}

func TestIntegrator_GetStats_WithReplay(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Replay.Enabled = true
	cfg.WAF.Replay.StoragePath = t.TempDir()

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	stats := i.GetStats()
	if !stats.ReplayEnabled {
		t.Error("ReplayEnabled should be true")
	}
	if !stats.ReplayRecordingEnabled {
		t.Error("ReplayRecordingEnabled should be true")
	}
	i.Cleanup()
}

func TestIntegrator_GetStats_WithCanary(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Canary.Enabled = true
	cfg.WAF.Canary.Strategy = "header"
	cfg.WAF.Canary.StableUpstream = "http://localhost:8080"
	cfg.WAF.Canary.CanaryUpstream = "http://localhost:8081"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	stats := i.GetStats()
	if !stats.CanaryEnabled {
		t.Error("CanaryEnabled should be true")
	}
	if stats.CanaryStrategy != "header" {
		t.Errorf("CanaryStrategy should be 'header', got '%s'", stats.CanaryStrategy)
	}
}

func TestIntegrator_GetStats_WithAnalytics(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Analytics.Enabled = true
	cfg.WAF.Analytics.StoragePath = t.TempDir()

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	stats := i.GetStats()
	if !stats.AnalyticsEnabled {
		t.Error("AnalyticsEnabled should be true")
	}
}

func TestIntegrator_GetStats_WithRemediation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Remediation.Enabled = true
	cfg.WAF.Remediation.AutoApply = true
	cfg.WAF.Remediation.StoragePath = t.TempDir()

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	stats := i.GetStats()
	if !stats.RemediationEnabled {
		t.Error("RemediationEnabled should be true")
	}
	if !stats.RemediationAutoApply {
		t.Error("RemediationAutoApply should be true")
	}
}

func TestIntegrator_GetStats_WithWebSocket(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.WebSocket.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	stats := i.GetStats()
	if !stats.WebSocketEnabled {
		t.Error("WebSocketEnabled should be true")
	}
}

func TestIntegrator_GetStats_WithTenant(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Tenant.Enabled = true
	cfg.WAF.Tenant.MaxTenants = 5

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	stats := i.GetStats()
	if !stats.MultiTenancyEnabled {
		t.Error("MultiTenancyEnabled should be true")
	}
	// No tenants created, so count should be 0
	if stats.TenantCount != 0 {
		t.Errorf("TenantCount should be 0, got %d", stats.TenantCount)
	}
}

func TestIntegrator_GetStats_WithGRPC(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.GRPC.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	stats := i.GetStats()
	if !stats.GRPCEnabled {
		t.Error("GRPCEnabled should be true")
	}
}

// ---------- AnalyticsHandler ----------

func TestIntegrator_AnalyticsHandler(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Analytics.Enabled = true
	cfg.WAF.Analytics.StoragePath = t.TempDir()

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	handler := i.AnalyticsHandler()
	if handler == nil {
		t.Error("AnalyticsHandler should not be nil when analytics is enabled")
	}
}

func TestIntegrator_AnalyticsHandler_Nil(t *testing.T) {
	cfg := config.DefaultConfig()
	// Explicitly disable analytics (enabled by default)
	cfg.WAF.Analytics.Enabled = false

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	handler := i.AnalyticsHandler()
	if handler != nil {
		t.Error("AnalyticsHandler should be nil when analytics is disabled")
	}
}

// ---------- RemediationHandler ----------

func TestIntegrator_RemediationHandler(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Remediation.Enabled = true
	cfg.WAF.Remediation.StoragePath = t.TempDir()
	cfg.Dashboard.APIKey = "test-api-key"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	handler := i.RemediationHandler()
	if handler == nil {
		t.Error("RemediationHandler should not be nil when remediation is enabled")
	}
}

func TestIntegrator_RemediationHandler_Nil(t *testing.T) {
	cfg := config.DefaultConfig()
	// Remediation disabled

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	handler := i.RemediationHandler()
	if handler != nil {
		t.Error("RemediationHandler should be nil when remediation is disabled")
	}
}

// ---------- WebSocket Security/Handler ----------

func TestIntegrator_WebSocketSecurity(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.WebSocket.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	security := i.GetWebSocketSecurity()
	if security == nil {
		t.Error("GetWebSocketSecurity should not be nil when WebSocket is enabled")
	}
}

func TestIntegrator_WebSocketHandler(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.WebSocket.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	handler := i.WebSocketHandler()
	if handler == nil {
		t.Error("WebSocketHandler should not be nil when WebSocket is enabled")
	}
}

// ---------- gRPC Security/Handler ----------

func TestIntegrator_GRPCSecurity_Nil(t *testing.T) {
	cfg := config.DefaultConfig()
	// gRPC layer not initialized (only proxy is initialized)

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	if i.GetGRPCLayer() != nil {
		t.Error("GetGRPCLayer should be nil (grpcLayer is not set by initGRPC)")
	}
	if i.GetGRPCSecurity() != nil {
		t.Error("GetGRPCSecurity should be nil when grpcLayer is nil")
	}
	if i.GRPCHandler() != nil {
		t.Error("GRPCHandler should be nil when grpcLayer is nil")
	}
}

// ---------- handleDiscoveryExport HTTP handler ----------

func TestIntegrator_HandleDiscoveryExport(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIDiscovery.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	// Test default format (openapi)
	req := httptest.NewRequest("GET", "/gwaf/api/discovery/export", nil)
	rr := httptest.NewRecorder()
	i.handleDiscoveryExport(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 for openapi export, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Expected application/json content-type, got %s", ct)
	}
	cd := rr.Header().Get("Content-Disposition")
	if cd == "" {
		t.Error("Expected Content-Disposition header to be set")
	}
}

func TestIntegrator_HandleDiscoveryExport_ExplicitOpenAPI(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIDiscovery.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/gwaf/api/discovery/export?format=openapi", nil)
	rr := httptest.NewRecorder()
	i.handleDiscoveryExport(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
}

func TestIntegrator_HandleDiscoveryExport_UnknownFormat(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIDiscovery.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/gwaf/api/discovery/export?format=xml", nil)
	rr := httptest.NewRecorder()
	i.handleDiscoveryExport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for unknown format, got %d", rr.Code)
	}
}

func TestIntegrator_HandleDiscoveryExport_Disabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIDiscovery.Enabled = false

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/gwaf/api/discovery/export", nil)
	rr := httptest.NewRecorder()
	i.handleDiscoveryExport(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 when discovery disabled, got %d", rr.Code)
	}
}

// ---------- handleDiscoverySpec HTTP handler ----------

func TestIntegrator_HandleDiscoverySpec(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIDiscovery.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/gwaf/api/discovery/spec", nil)
	rr := httptest.NewRecorder()
	i.handleDiscoverySpec(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Expected application/json, got %s", ct)
	}
}

func TestIntegrator_HandleDiscoverySpec_Disabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIDiscovery.Enabled = false

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/gwaf/api/discovery/spec", nil)
	rr := httptest.NewRecorder()
	i.handleDiscoverySpec(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 when discovery disabled, got %d", rr.Code)
	}
}

// ---------- handleDiscoveryStats HTTP handler ----------

func TestIntegrator_HandleDiscoveryStats(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIDiscovery.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/gwaf/api/discovery/stats", nil)
	rr := httptest.NewRecorder()
	i.handleDiscoveryStats(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Expected application/json, got %s", ct)
	}
}

func TestIntegrator_HandleDiscoveryStats_Disabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIDiscovery.Enabled = false

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/gwaf/api/discovery/stats", nil)
	rr := httptest.NewRecorder()
	i.handleDiscoveryStats(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 when discovery disabled, got %d", rr.Code)
	}
}

// ---------- Enhanced Bot Detection with biometric/captcha ----------

func TestNewIntegrator_WithEnhancedBot_BiometricAndCaptcha(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.BotDetection.Enhanced.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Mode = "block"
	cfg.WAF.BotDetection.Enhanced.Biometric.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Biometric.MinEvents = 5
	cfg.WAF.BotDetection.Enhanced.Biometric.ScoreThreshold = 0.5
	cfg.WAF.BotDetection.Enhanced.Captcha.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Captcha.Provider = "recaptcha"
	cfg.WAF.BotDetection.Enhanced.Captcha.SiteKey = "test-site-key"
	cfg.WAF.BotDetection.Enhanced.Captcha.SecretKey = "test-secret-key"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with enhanced bot+biometric+captcha failed: %v", err)
	}
	if i.enhancedBotLayer == nil {
		t.Error("enhancedBotLayer should be initialized")
	}
	if i.botCollector == nil {
		t.Error("botCollector should be initialized when biometric is enabled")
	}
	if i.biometricHandler == nil {
		t.Error("biometricHandler should be set when biometric is enabled")
	}
	if i.challengeHandler == nil {
		t.Error("challengeHandler should be set when captcha is enabled")
	}
	if i.challengeVerify == nil {
		t.Error("challengeVerify should be set when captcha is enabled")
	}

	stats := i.GetStats()
	if !stats.EnhancedBotEnabled {
		t.Error("EnhancedBotEnabled should be true")
	}
	if !stats.BiometricEnabled {
		t.Error("BiometricEnabled should be true")
	}
	if !stats.CaptchaEnabled {
		t.Error("CaptchaEnabled should be true")
	}
}

// ---------- TenantIntegrator edge cases ----------

func TestNewTenantIntegrator_WithTenants(t *testing.T) {
	cfg := config.TenantConfig{
		Enabled:   true,
		MaxTenants: 10,
		Tenants: []config.TenantDefinition{
			{
				Name:        "test-tenant",
				Description: "Test tenant",
				Domains:     []string{"test.example.com"},
				Active:      true,
				Quota: config.ResourceQuotaConfig{
					MaxRequestsPerMinute: 100,
				},
			},
		},
	}

	ti, err := NewTenantIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewTenantIntegrator with tenants failed: %v", err)
	}
	if ti == nil {
		t.Fatal("Expected non-nil integrator")
	}

	stats := ti.Stats()
	if stats.TenantCount != 1 {
		t.Errorf("Expected 1 tenant, got %d", stats.TenantCount)
	}
}

func TestNewTenantIntegrator_WithTenants_ZeroRPM(t *testing.T) {
	cfg := config.TenantConfig{
		Enabled:   true,
		MaxTenants: 10,
		DefaultQuota: config.ResourceQuotaConfig{
			MaxRequestsPerMinute: 500,
			MaxRequestsPerHour:   10000,
		},
		Tenants: []config.TenantDefinition{
			{
				Name:        "default-quota-tenant",
				Description: "Tenant with zero RPM quota (should use default)",
				Domains:     []string{"default.example.com"},
				Active:      true,
				Quota: config.ResourceQuotaConfig{
					MaxRequestsPerMinute: 0, // zero RPM -> use default quota
				},
			},
		},
	}

	ti, err := NewTenantIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewTenantIntegrator with zero RPM tenant failed: %v", err)
	}
	if ti == nil {
		t.Fatal("Expected non-nil integrator")
	}

	stats := ti.Stats()
	if stats.TenantCount != 1 {
		t.Errorf("Expected 1 tenant, got %d", stats.TenantCount)
	}
}

func TestNewTenantIntegrator_WithDuplicateTenant(t *testing.T) {
	cfg := config.TenantConfig{
		Enabled:   true,
		MaxTenants: 10,
		Tenants: []config.TenantDefinition{
			{
				Name:    "dup-tenant",
				Domains: []string{"dup.example.com"},
				Active:  true,
			},
			{
				Name:    "dup-tenant", // duplicate name
				Domains: []string{"dup2.example.com"},
				Active:  true,
			},
		},
	}

	ti, err := NewTenantIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewTenantIntegrator with duplicate tenant should not error: %v", err)
	}
	if ti == nil {
		t.Fatal("Expected non-nil integrator")
	}
	// Duplicate name tenants: manager may or may not skip duplicates
	// The important thing is that it doesn't panic
	stats := ti.Stats()
	if stats.TenantCount < 1 {
		t.Errorf("Expected at least 1 tenant, got %d", stats.TenantCount)
	}
}

func TestTenantIntegrator_Middleware_WithRealMiddleware(t *testing.T) {
	cfg := config.TenantConfig{
		Enabled:   true,
		MaxTenants: 10,
	}

	ti, err := NewTenantIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewTenantIntegrator failed: %v", err)
	}

	middleware := ti.Middleware()
	if middleware == nil {
		t.Fatal("Middleware should not return nil")
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := middleware(inner)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// The middleware may return 503 if no tenant matches, or 200 if passthrough.
	// The important thing is that it doesn't panic.
	if rr.Code == 0 {
		t.Error("Expected a non-zero status code from middleware")
	}
}

func TestTenantIntegrator_Manager_NonNil(t *testing.T) {
	cfg := config.TenantConfig{
		Enabled:   true,
		MaxTenants: 10,
	}

	ti, err := NewTenantIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewTenantIntegrator failed: %v", err)
	}

	manager := ti.Manager()
	if manager == nil {
		t.Error("Manager should not be nil when integrator is initialized")
	}
}

func TestTenantIntegrator_RegisterHandlers_NilHandlers(t *testing.T) {
	// Create integrator with nil handlers field
	ti := &TenantIntegrator{}

	// Should not panic with nil handlers
	mux := http.NewServeMux()
	ti.RegisterHandlers(mux)
}

func TestTenantIntegrator_Middleware_WithNilIntegrator(t *testing.T) {
	var ti *TenantIntegrator = nil

	middleware := ti.Middleware()
	if middleware == nil {
		t.Fatal("Middleware should not return nil even for nil integrator")
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := middleware(inner)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 (passthrough), got %d", rr.Code)
	}
}

func TestTenantIntegrator_RegisterHandlers_NilIntegrator(t *testing.T) {
	var ti *TenantIntegrator = nil

	// Should not panic
	mux := http.NewServeMux()
	ti.RegisterHandlers(mux)
}

func TestTenantIntegrator_Manager_NilIntegrator(t *testing.T) {
	var ti *TenantIntegrator = nil

	manager := ti.Manager()
	if manager != nil {
		t.Error("Manager should be nil for nil integrator")
	}
}

func TestTenantIntegrator_Stats_NilIntegrator(t *testing.T) {
	var ti *TenantIntegrator = nil

	stats := ti.Stats()
	if stats.TenantCount != 0 {
		t.Errorf("Expected 0 tenant count for nil integrator, got %d", stats.TenantCount)
	}
}

// ---------- Stats struct coverage ----------

func TestIntegrator_GetStats_AllFieldsEnabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.MLAnomaly.Enabled = true
	cfg.WAF.APIDiscovery.Enabled = true
	cfg.WAF.GraphQL.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Biometric.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Captcha.Enabled = true
	cfg.WAF.GRPC.Enabled = true
	cfg.WAF.Tenant.Enabled = true
	cfg.WAF.Tenant.MaxTenants = 5
	cfg.WAF.DLP.Enabled = true
	cfg.WAF.DLP.BlockOnMatch = true
	cfg.WAF.ZeroTrust.Enabled = true
	cfg.WAF.ZeroTrust.RequireMTLS = true
	cfg.WAF.SIEM.Enabled = true
	cfg.WAF.SIEM.Format = "json"
	cfg.WAF.SIEM.Endpoint = "" // empty endpoint skips SIEM URL validation
	cfg.WAF.Cache.Enabled = true
	cfg.WAF.Cache.Backend = "memory"
	cfg.WAF.Replay.Enabled = true
	cfg.WAF.Replay.StoragePath = t.TempDir()
	cfg.WAF.Canary.Enabled = true
	cfg.WAF.Canary.Strategy = "percentage"
	cfg.WAF.Canary.StableUpstream = "http://localhost:8080"
	cfg.WAF.Canary.CanaryUpstream = "http://localhost:8081"
	cfg.WAF.Analytics.Enabled = true
	cfg.WAF.Analytics.StoragePath = t.TempDir()
	cfg.WAF.Remediation.Enabled = true
	cfg.WAF.Remediation.AutoApply = true
	cfg.WAF.Remediation.StoragePath = t.TempDir()
	cfg.WAF.WebSocket.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with all features failed: %v", err)
	}
	defer func() {
		if i.replayManager != nil {
			_ = i.replayManager.Close()
		}
		i.Cleanup()
	}()

	stats := i.GetStats()

	if !stats.MLAnomalyEnabled {
		t.Error("MLAnomalyEnabled should be true")
	}
	if !stats.APIDiscoveryEnabled {
		t.Error("APIDiscoveryEnabled should be true")
	}
	if !stats.GraphQLSecurityEnabled {
		t.Error("GraphQLSecurityEnabled should be true")
	}
	if !stats.EnhancedBotEnabled {
		t.Error("EnhancedBotEnabled should be true")
	}
	if !stats.BiometricEnabled {
		t.Error("BiometricEnabled should be true")
	}
	if !stats.CaptchaEnabled {
		t.Error("CaptchaEnabled should be true")
	}
	if !stats.GRPCEnabled {
		t.Error("GRPCEnabled should be true")
	}
	if !stats.MultiTenancyEnabled {
		t.Error("MultiTenancyEnabled should be true")
	}
	if !stats.DLPEnabled {
		t.Error("DLPEnabled should be true")
	}
	if !stats.DLPBlockOnMatch {
		t.Error("DLPBlockOnMatch should be true")
	}
	if !stats.ZeroTrustEnabled {
		t.Error("ZeroTrustEnabled should be true")
	}
	if !stats.ZeroTrustRequireMTLS {
		t.Error("ZeroTrustRequireMTLS should be true")
	}
	if !stats.SIEMEnabled {
		t.Error("SIEMEnabled should be true")
	}
	if stats.SIEMFormat != "json" {
		t.Errorf("SIEMFormat should be 'json', got '%s'", stats.SIEMFormat)
	}
	if !stats.CacheEnabled {
		t.Error("CacheEnabled should be true")
	}
	if !stats.ReplayEnabled {
		t.Error("ReplayEnabled should be true")
	}
	if !stats.ReplayRecordingEnabled {
		t.Error("ReplayRecordingEnabled should be true")
	}
	if !stats.CanaryEnabled {
		t.Error("CanaryEnabled should be true")
	}
	if stats.CanaryStrategy != "percentage" {
		t.Errorf("CanaryStrategy should be 'percentage', got '%s'", stats.CanaryStrategy)
	}
	if !stats.AnalyticsEnabled {
		t.Error("AnalyticsEnabled should be true")
	}
	if !stats.RemediationEnabled {
		t.Error("RemediationEnabled should be true")
	}
	if !stats.RemediationAutoApply {
		t.Error("RemediationAutoApply should be true")
	}
	if !stats.WebSocketEnabled {
		t.Error("WebSocketEnabled should be true")
	}
}

// ---------- Error paths ----------

func TestNewIntegrator_InitError_MLAnomaly(t *testing.T) {
	// ML anomaly layer doesn't fail with any threshold value, so test normal creation
	cfg := config.DefaultConfig()
	cfg.WAF.MLAnomaly.Enabled = true
	cfg.WAF.MLAnomaly.Threshold = 0.95

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator should succeed with ML anomaly enabled: %v", err)
	}
	if i.mlAnomalyLayer == nil {
		t.Error("mlAnomalyLayer should be initialized")
	}
}

func TestNewIntegrator_InitError_APIDiscovery(t *testing.T) {
	// Test API discovery with valid but minimal config
	cfg := config.DefaultConfig()
	cfg.WAF.APIDiscovery.Enabled = true
	cfg.WAF.APIDiscovery.RingBufferSize = 100

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with API discovery should succeed: %v", err)
	}
	if i.apiDiscovery == nil {
		t.Error("apiDiscovery should be initialized")
	}
}

func TestNewIntegrator_InitError_GraphQL(t *testing.T) {
	// GraphQL New() always returns nil error, so test normal creation
	cfg := config.DefaultConfig()
	cfg.WAF.GraphQL.Enabled = true
	cfg.WAF.GraphQL.MaxDepth = 5
	cfg.WAF.GraphQL.MaxComplexity = 100

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with GraphQL should succeed: %v", err)
	}
	if i.graphqlLayer == nil {
		t.Error("graphqlLayer should be initialized")
	}
}

// ---------- Tenant layer with context ----------

func TestTenantLayer_Process_WithContext(t *testing.T) {
	cfg := config.TenantConfig{
		Enabled:   true,
		MaxTenants: 5,
	}
	ti, err := NewTenantIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewTenantIntegrator failed: %v", err)
	}

	tl := NewTenantLayer(ti)

	ctx := &engine.RequestContext{
		Method: "POST",
		Path:   "/api/v1/test",
		Headers: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	result := tl.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected ActionPass, got %v", result.Action)
	}
}

// ---------- RegisterHandlers via integration (real handler registration) ----------

func TestIntegrator_RegisterHandlers_FullIntegration(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIDiscovery.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Biometric.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Captcha.Enabled = true
	cfg.WAF.Tenant.Enabled = true
	cfg.WAF.Tenant.MaxTenants = 10

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	mux := http.NewServeMux()
	i.RegisterHandlers(mux)

	// Test that the registered endpoints respond
	tests := []struct {
		path   string
		method string
	}{
		{"/gwaf/api/discovery/stats", "GET"},
		{"/gwaf/api/discovery/spec", "GET"},
		{"/gwaf/api/discovery/export", "GET"},
	}

	for _, tc := range tests {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		// Just verify the handlers were registered and respond
		if rr.Code == 0 {
			t.Errorf("Handler for %s returned status 0 (not registered?)", tc.path)
		}
	}
}

// ---------- Cluster config with cluster layer ----------

func TestIntegrator_ClusterLayer_Nil(t *testing.T) {
	cfg := config.DefaultConfig()

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	if i.GetClusterLayer() != nil {
		t.Error("GetClusterLayer should be nil when cluster is not configured")
	}
}

// ---------- RegisterHandlers registers biometric endpoints ----------

func TestIntegrator_RegisterHandlers_BiometricEndpoints(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.BotDetection.Enhanced.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Biometric.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	mux := http.NewServeMux()
	i.RegisterHandlers(mux)

	// Biometric collect endpoint should be registered
	req := httptest.NewRequest("POST", "/gwaf/biometric/collect", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	// Just verify handler was registered (may return various status codes)
	if rr.Code == 0 {
		t.Error("Biometric collect handler should be registered")
	}
}

func TestIntegrator_RegisterHandlers_ChallengeEndpoints(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.BotDetection.Enhanced.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Captcha.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	mux := http.NewServeMux()
	i.RegisterHandlers(mux)

	// Challenge page endpoint should be registered
	req := httptest.NewRequest("GET", "/gwaf/challenge", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code == 0 {
		t.Error("Challenge handler should be registered")
	}

	// Challenge verify endpoint should be registered
	req2 := httptest.NewRequest("POST", "/gwaf/challenge/verify", nil)
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)

	if rr2.Code == 0 {
		t.Error("Challenge verify handler should be registered")
	}
}

// ---------- Cleanup with cluster layer ----------

func TestIntegrator_Cleanup_WithClusterLayer(t *testing.T) {
	cfg := config.DefaultConfig()

	i := &Integrator{
		cfg: cfg,
		// clusterLayer is nil, so Cleanup should handle it gracefully
	}

	// Should not panic
	i.Cleanup()
}

// ---------- Cleanup with nil clusterLayer Stop error path ----------

func TestIntegrator_Cleanup_NilClusterLayer(t *testing.T) {
	cfg := config.DefaultConfig()

	i := &Integrator{
		cfg: cfg,
	}

	// All nil components - should not panic
	i.Cleanup()
}

// ---------- Test discovery export with registered handlers via ServeMux ----------

func TestIntegrator_DiscoveryExport_Integrated(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIDiscovery.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	mux := http.NewServeMux()
	i.RegisterHandlers(mux)

	// Test export via the registered handler
	req := httptest.NewRequest("GET", "/gwaf/api/discovery/export?format=openapi", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
}

// ---------- CanaryMiddleware with canary enabled ----------

func TestIntegrator_CanaryMiddleware_Enabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Canary.Enabled = true
	cfg.WAF.Canary.Strategy = "percentage"
	cfg.WAF.Canary.Percentage = 10
	cfg.WAF.Canary.StableUpstream = "http://localhost:8080"
	cfg.WAF.Canary.CanaryUpstream = "http://localhost:8081"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// CanaryMiddleware with canary enabled
	// Note: GetCanary() may return nil if the canary isn't fully set up without upstreams
	handler := i.CanaryMiddleware(inner)
	if handler == nil {
		t.Fatal("CanaryMiddleware should not return nil")
	}
}

// ---------- Test GetClusterNodeCount with cluster layer ----------

func TestIntegrator_GetClusterNodeCount_WithClusterLayer(t *testing.T) {
	cfg := config.DefaultConfig()

	i := &Integrator{
		cfg:          cfg,
		clusterLayer: nil, // explicitly nil
	}

	if i.GetClusterNodeCount() != 1 {
		t.Errorf("Expected 1 when clusterLayer is nil, got %d", i.GetClusterNodeCount())
	}
}

// ---------- Test IsClusterLeader with cluster layer ----------

func TestIntegrator_IsClusterLeader_WithNilClusterLayer(t *testing.T) {
	cfg := config.DefaultConfig()

	i := &Integrator{
		cfg:          cfg,
		clusterLayer: nil,
	}

	if i.IsClusterLeader() {
		t.Error("IsClusterLeader should be false when clusterLayer is nil")
	}
}

// ---------- Check temp directory cleanup in tests ----------

func TestNewIntegrator_WithRemediation_TempDir(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.WAF.Remediation.Enabled = true
	cfg.WAF.Remediation.StoragePath = tmpDir

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with remediation failed: %v", err)
	}

	// Verify temp dir was created
	if _, err := os.Stat(tmpDir); os.IsNotExist(err) {
		t.Error("Storage path should exist")
	}

	if i.GetRemediationEngine() == nil {
		t.Error("GetRemediationEngine should not be nil")
	}
}

// ---------- Multiple features enabled at once ----------

func TestNewIntegrator_MultipleFeatures(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.MLAnomaly.Enabled = true
	cfg.WAF.APIDiscovery.Enabled = true
	cfg.WAF.GraphQL.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Enabled = true
	cfg.WAF.DLP.Enabled = true
	cfg.WAF.ZeroTrust.Enabled = true
	cfg.WAF.SIEM.Enabled = true
	cfg.WAF.SIEM.Endpoint = "" // empty endpoint skips SIEM URL validation
	cfg.WAF.Cache.Enabled = true
	cfg.WAF.Cache.Backend = "memory"
	cfg.WAF.WebSocket.Enabled = true
	cfg.WAF.Remediation.Enabled = true
	cfg.WAF.Remediation.StoragePath = t.TempDir()
	cfg.WAF.GRPC.Enabled = true
	cfg.WAF.Tenant.Enabled = true
	cfg.WAF.Tenant.MaxTenants = 5
	cfg.WAF.Replay.Enabled = true
	cfg.WAF.Replay.StoragePath = t.TempDir()
	cfg.WAF.Canary.Enabled = true
	cfg.WAF.Canary.Strategy = "percentage"
	cfg.WAF.Canary.Percentage = 10
	cfg.WAF.Canary.StableUpstream = "http://localhost:8080"
	cfg.WAF.Canary.CanaryUpstream = "http://localhost:8081"
	cfg.WAF.Analytics.Enabled = true
	cfg.WAF.Analytics.StoragePath = t.TempDir()

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator with many features failed: %v", err)
	}

	// Verify all components are non-nil
	if i.mlAnomalyLayer == nil {
		t.Error("mlAnomalyLayer should be initialized")
	}
	if i.apiDiscovery == nil {
		t.Error("apiDiscovery should be initialized")
	}
	if i.graphqlLayer == nil {
		t.Error("graphqlLayer should be initialized")
	}
	if i.enhancedBotLayer == nil {
		t.Error("enhancedBotLayer should be initialized")
	}
	if i.dlpLayer == nil {
		t.Error("dlpLayer should be initialized")
	}
	if i.zeroTrustService == nil {
		t.Error("zeroTrustService should be initialized")
	}
	if i.siemExporter == nil {
		t.Error("siemExporter should be initialized")
	}
	if i.cacheLayer == nil {
		t.Error("cacheLayer should be initialized")
	}
	if i.websocketLayer == nil {
		t.Error("websocketLayer should be initialized")
	}
	if i.remediationLayer == nil {
		t.Error("remediationLayer should be initialized")
	}
	if i.grpcProxy == nil {
		t.Error("grpcProxy should be initialized")
	}
	if i.tenantIntegrator == nil {
		t.Error("tenantIntegrator should be initialized")
	}
	if i.replayManager == nil {
		t.Error("replayManager should be initialized")
	}
	if i.canaryLayer == nil {
		t.Error("canaryLayer should be initialized")
	}
	if i.analyticsLayer == nil {
		t.Error("analyticsLayer should be initialized")
	}

	// Cleanup should not panic
	i.Cleanup()
}
