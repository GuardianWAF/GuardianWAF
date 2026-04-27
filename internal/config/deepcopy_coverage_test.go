package config

import (
	"testing"
	"time"
)

// TestDeepCopy_NilConfig tests DeepCopy on nil Config.
func TestDeepCopy_NilConfig(t *testing.T) {
	var c *Config
	if got := c.DeepCopy(); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

// TestDeepCopy_FullConfig exercises every DeepCopy method via Config.DeepCopy.
func TestDeepCopy_FullConfig(t *testing.T) {
	cfg := fullConfig()
	cp := cfg.DeepCopy()
	if cp == nil {
		t.Fatal("DeepCopy returned nil")
	}
	// Verify independence: modify copy and check original is unchanged
	cp.Mode = "monitor"
	if cfg.Mode != "enforce" {
		t.Error("original Mode was mutated")
	}
	cp.Listen = ":9999"
	if cfg.Listen != ":8088" {
		t.Error("original Listen was mutated")
	}
	// Verify slices are independent
	cp.Upstreams[0].Name = "changed"
	if cfg.Upstreams[0].Name == "changed" {
		t.Error("Upstreams slice not deep copied")
	}
	cp.Routes[0].Path = "/changed"
	if cfg.Routes[0].Path == "/changed" {
		t.Error("Routes slice not deep copied")
	}
	cp.VirtualHosts[0].Domains[0] = "changed.example.com"
	if cfg.VirtualHosts[0].Domains[0] == "changed.example.com" {
		t.Error("VirtualHosts Domains not deep copied")
	}
	cp.TrustedProxies[0] = "0.0.0.0/0"
	if cfg.TrustedProxies[0] == "0.0.0.0/0" {
		t.Error("TrustedProxies not deep copied")
	}
	// Verify WAF sub-structs
	cp.WAF.Detection.Detectors["sqli"] = DetectorConfig{Enabled: false, Multiplier: 5.0}
	if cfg.WAF.Detection.Detectors["sqli"].Multiplier == 5.0 {
		t.Error("Detection.Detectors not deep copied")
	}
	cp.WAF.Detection.Exclusions[0].Path = "/changed"
	if cfg.WAF.Detection.Exclusions[0].Path == "/changed" {
		t.Error("Detection.Exclusions not deep copied")
	}
	cp.WAF.RateLimit.Rules[1].Paths[0] = "/changed" // index 1 = custom rule
	if cfg.WAF.RateLimit.Rules[1].Paths[0] == "/changed" {
		t.Error("RateLimit.Rules.Paths not deep copied")
	}
	// VirtualHost WAF
	cp.VirtualHosts[0].WAF.Detection.Threshold.Block = 999
	if cfg.VirtualHosts[0].WAF.Detection.Threshold.Block == 999 {
		t.Error("VirtualHost WAF not deep copied")
	}
	// Tenant deep copy
	cp.Tenant.Tenants[0].Domains[0] = "changed.example.com"
	if cfg.Tenant.Tenants[0].Domains[0] == "changed.example.com" {
		t.Error("Tenant.Domains not deep copied")
	}
	// SIEM Fields map
	cp.WAF.SIEM.Fields["key"] = "changed"
	if cfg.WAF.SIEM.Fields["key"] == "changed" {
		t.Error("SIEM Fields not deep copied")
	}
	// Remediation ExcludedPaths
	cp.WAF.Remediation.ExcludedPaths[0] = "/changed"
	if cfg.WAF.Remediation.ExcludedPaths[0] == "/changed" {
		t.Error("Remediation ExcludedPaths not deep copied")
	}
	// WebSocket slices
	cp.WAF.WebSocket.AllowedOrigins[0] = "changed"
	if cfg.WAF.WebSocket.AllowedOrigins[0] == "changed" {
		t.Error("WebSocket AllowedOrigins not deep copied")
	}
	cp.WAF.WebSocket.BlockedExtensions[0] = "changed"
	if cfg.WAF.WebSocket.BlockedExtensions[0] == "changed" {
		t.Error("WebSocket BlockedExtensions not deep copied")
	}
	// ClusterSync Clusters
	cp.WAF.ClusterSync.Clusters[0].Nodes[0].ID = "changed"
	if cfg.WAF.ClusterSync.Clusters[0].Nodes[0].ID == "changed" {
		t.Error("ClusterSync Clusters not deep copied")
	}
	// IPACL
	cp.WAF.IPACL.Whitelist[0] = "0.0.0.0"
	if cfg.WAF.IPACL.Whitelist[0] == "0.0.0.0" {
		t.Error("IPACL Whitelist not deep copied")
	}
	cp.WAF.IPACL.Blacklist[0] = "0.0.0.0"
	if cfg.WAF.IPACL.Blacklist[0] == "0.0.0.0" {
		t.Error("IPACL Blacklist not deep copied")
	}
	// Sanitizer
	cp.WAF.Sanitizer.AllowedMethods[0] = "PATCH"
	if cfg.WAF.Sanitizer.AllowedMethods[0] == "PATCH" {
		t.Error("Sanitizer AllowedMethods not deep copied")
	}
	// ThreatIntel
	cp.WAF.ThreatIntel.Feeds[0].URL = "http://changed"
	if cfg.WAF.ThreatIntel.Feeds[0].URL == "http://changed" {
		t.Error("ThreatIntel Feeds not deep copied")
	}
	// CORS
	cp.WAF.CORS.AllowOrigins[0] = "http://changed"
	if cfg.WAF.CORS.AllowOrigins[0] == "http://changed" {
		t.Error("CORS AllowOrigins not deep copied")
	}
	// ATO
	cp.WAF.ATOProtection.LoginPaths[0] = "/changed"
	if cfg.WAF.ATOProtection.LoginPaths[0] == "/changed" {
		t.Error("ATO LoginPaths not deep copied")
	}
	// APISecurity
	cp.WAF.APISecurity.SkipPaths[0] = "/changed"
	if cfg.WAF.APISecurity.SkipPaths[0] == "/changed" {
		t.Error("APISecurity SkipPaths not deep copied")
	}
	cp.WAF.APISecurity.JWT.Algorithms[0] = "changed"
	if cfg.WAF.APISecurity.JWT.Algorithms[0] == "changed" {
		t.Error("JWT Algorithms not deep copied")
	}
	cp.WAF.APISecurity.APIKeys.Keys[0].Name = "changed"
	if cfg.WAF.APISecurity.APIKeys.Keys[0].Name == "changed" {
		t.Error("APIKeys not deep copied")
	}
	// CustomRules
	cp.WAF.CustomRules.Rules[0].Conditions[0].Field = "changed"
	if cfg.WAF.CustomRules.Rules[0].Conditions[0].Field == "changed" {
		t.Error("CustomRules Conditions not deep copied")
	}
	// ClientSide
	cp.WAF.ClientSide.Exclusions[0] = "/changed"
	if cfg.WAF.ClientSide.Exclusions[0] == "/changed" {
		t.Error("ClientSide Exclusions not deep copied")
	}
	cp.WAF.ClientSide.MagecartDetection.KnownSkimmingDomains[0] = "changed"
	if cfg.WAF.ClientSide.MagecartDetection.KnownSkimmingDomains[0] == "changed" {
		t.Error("Magecart KnownSkimmingDomains not deep copied")
	}
	cp.WAF.ClientSide.AgentInjection.ProtectedPaths[0] = "/changed"
	if cfg.WAF.ClientSide.AgentInjection.ProtectedPaths[0] == "/changed" {
		t.Error("AgentInjection ProtectedPaths not deep copied")
	}
	// CSP
	cp.WAF.ClientSide.CSP.DefaultSrc[0] = "changed"
	if cfg.WAF.ClientSide.CSP.DefaultSrc[0] == "changed" {
		t.Error("CSP DefaultSrc not deep copied")
	}
	// DLP
	cp.WAF.DLP.Patterns[0] = "changed"
	if cfg.WAF.DLP.Patterns[0] == "changed" {
		t.Error("DLP Patterns not deep copied")
	}
	// ZeroTrust
	cp.WAF.ZeroTrust.AllowBypassPaths[0] = "/changed"
	if cfg.WAF.ZeroTrust.AllowBypassPaths[0] == "/changed" {
		t.Error("ZeroTrust AllowBypassPaths not deep copied")
	}
	// Cache
	cp.WAF.Cache.CacheMethods[0] = "changed"
	if cfg.WAF.Cache.CacheMethods[0] == "changed" {
		t.Error("Cache CacheMethods not deep copied")
	}
	cp.WAF.Cache.SkipPaths[0] = "/changed"
	if cfg.WAF.Cache.SkipPaths[0] == "/changed" {
		t.Error("Cache SkipPaths not deep copied")
	}
	// Replay
	cp.WAF.Replay.CaptureHeaders[0] = "changed"
	if cfg.WAF.Replay.CaptureHeaders[0] == "changed" {
		t.Error("Replay CaptureHeaders not deep copied")
	}
	cp.WAF.Replay.SkipPaths[0] = "/changed"
	if cfg.WAF.Replay.SkipPaths[0] == "/changed" {
		t.Error("Replay SkipPaths not deep copied")
	}
	cp.WAF.Replay.SkipMethods[0] = "changed"
	if cfg.WAF.Replay.SkipMethods[0] == "changed" {
		t.Error("Replay SkipMethods not deep copied")
	}
	cp.WAF.Replay.Replay.Headers["key"] = "changed"
	if cfg.WAF.Replay.Replay.Headers["key"] == "changed" {
		t.Error("Replay Headers not deep copied")
	}
	// Canary
	cp.WAF.Canary.Regions[0] = "changed"
	if cfg.WAF.Canary.Regions[0] == "changed" {
		t.Error("Canary Regions not deep copied")
	}
	cp.WAF.Canary.Metadata["key"] = "changed"
	if cfg.WAF.Canary.Metadata["key"] == "changed" {
		t.Error("Canary Metadata not deep copied")
	}
	// GraphQL
	cp.WAF.GraphQL.AllowEndpoints[0] = "/changed"
	if cfg.WAF.GraphQL.AllowEndpoints[0] == "/changed" {
		t.Error("GraphQL AllowEndpoints not deep copied")
	}
	// GRPC
	cp.WAF.GRPC.ProtoPaths[0] = "changed"
	if cfg.WAF.GRPC.ProtoPaths[0] == "changed" {
		t.Error("GRPC ProtoPaths not deep copied")
	}
	cp.WAF.GRPC.AllowedServices[0] = "changed"
	if cfg.WAF.GRPC.AllowedServices[0] == "changed" {
		t.Error("GRPC AllowedServices not deep copied")
	}
	cp.WAF.GRPC.BlockedServices[0] = "changed"
	if cfg.WAF.GRPC.BlockedServices[0] == "changed" {
		t.Error("GRPC BlockedServices not deep copied")
	}
	cp.WAF.GRPC.AllowedMethods[0] = "changed"
	if cfg.WAF.GRPC.AllowedMethods[0] == "changed" {
		t.Error("GRPC AllowedMethods not deep copied")
	}
	cp.WAF.GRPC.BlockedMethods[0] = "changed"
	if cfg.WAF.GRPC.BlockedMethods[0] == "changed" {
		t.Error("GRPC BlockedMethods not deep copied")
	}
	cp.WAF.GRPC.MethodRateLimits[0].Method = "changed"
	if cfg.WAF.GRPC.MethodRateLimits[0].Method == "changed" {
		t.Error("GRPC MethodRateLimits not deep copied")
	}
	// VirtualPatch
	cp.WAF.VirtualPatch.BlockSeverity[0] = "changed"
	if cfg.WAF.VirtualPatch.BlockSeverity[0] == "changed" {
		t.Error("VirtualPatch BlockSeverity not deep copied")
	}
	// CRS
	cp.WAF.CRS.Exclusions[0] = "changed"
	if cfg.WAF.CRS.Exclusions[0] == "changed" {
		t.Error("CRS Exclusions not deep copied")
	}
	cp.WAF.CRS.DisabledRules[0] = "changed"
	if cfg.WAF.CRS.DisabledRules[0] == "changed" {
		t.Error("CRS DisabledRules not deep copied")
	}
	// TLS ACME Domains
	cp.TLS.ACME.Domains[0] = "changed.example.com"
	if cfg.TLS.ACME.Domains[0] == "changed.example.com" {
		t.Error("ACME Domains not deep copied")
	}
	// VirtualHost Routes
	cp.VirtualHosts[0].Routes[0].Path = "/changed"
	if cfg.VirtualHosts[0].Routes[0].Path == "/changed" {
		t.Error("VirtualHost Routes not deep copied")
	}
}

// fullConfig returns a Config with every slice/map/pointer field populated.
func fullConfig() *Config {
	cfg := DefaultConfig()
	// Override nil/empty fields with non-empty values
	cfg.TrustedProxies = []string{"10.0.0.0/8", "172.16.0.0/12"}
	cfg.Upstreams = []UpstreamConfig{
		{
			Name:         "backend",
			LoadBalancer: "round_robin",
			Targets:      []TargetConfig{{URL: "http://localhost:8080", Weight: 1}},
			HealthCheck:  HealthCheckConfig{Enabled: true, Interval: 10 * time.Second, Timeout: 5 * time.Second, Path: "/healthz"},
		},
	}
	cfg.Routes = []RouteConfig{
		{Path: "/api", Upstream: "backend", Methods: []string{"GET", "POST"}, StripPrefix: true},
	}
	cfg.VirtualHosts = []VirtualHostConfig{
		{
			Domains: []string{"api.example.com", "*.api.example.com"},
			TLS:     VHostTLSConfig{CertFile: "/cert.pem", KeyFile: "/key.pem"},
			Routes:  []RouteConfig{{Path: "/v1", Upstream: "backend"}},
			WAF: &WAFConfig{
				Detection: DetectionConfig{
					Enabled: true,
					Threshold: ThresholdConfig{Block: 50, Log: 25},
					Detectors: map[string]DetectorConfig{"sqli": {Enabled: true, Multiplier: 1.0}},
				},
			},
		},
	}
	cfg.Features = map[string]bool{"feature_a": true}

	// WAF sub-configs with non-empty slices
	cfg.WAF.IPACL.Whitelist = []string{"10.0.0.1"}
	cfg.WAF.IPACL.Blacklist = []string{"192.168.1.1"}
	cfg.WAF.CustomRules = CustomRulesConfig{
		Enabled: true,
		Rules: []CustomRule{
			{
				ID: "rule-1", Name: "Block bad bots", Enabled: true, Priority: 10,
				Action: "block", Score: 50,
				Conditions: []RuleCondition{{Field: "user_agent", Op: "contains", Value: "badbot"}},
			},
		},
	}
	cfg.WAF.RateLimit.Rules = append(cfg.WAF.RateLimit.Rules, RateLimitRule{
		ID: "custom", Scope: "ip+path", Paths: []string{"/api"}, Limit: 100,
		Window: time.Minute, Burst: 20, Action: "block", AutoBanAfter: 5,
	})
	cfg.WAF.Sanitizer.AllowedMethods = []string{"GET", "POST", "PUT"}
	cfg.WAF.Sanitizer.PathOverrides = []PathOverride{{Path: "/upload", MaxBodySize: 50 * 1024 * 1024}}
	cfg.WAF.Detection.Exclusions = []ExclusionConfig{{Path: "/api/webhook", Detectors: []string{"sqli"}, Reason: "Third-party callback"}}
	cfg.WAF.BotDetection.TLSFingerprint = TLSFingerprintConfig{Enabled: true, KnownBotsAction: "block", UnknownAction: "log", MismatchAction: "log"}
	cfg.WAF.BotDetection.UserAgent = UAConfig{Enabled: true, BlockEmpty: true, BlockKnownScanners: true}
	cfg.WAF.BotDetection.Behavior = BehaviorConfig{Enabled: true, Window: 5 * time.Minute, RPSThreshold: 10, ErrorRateThreshold: 30}
	cfg.WAF.BotDetection.Enhanced = EnhancedBotDetectionConfig{
		Enabled: true, Mode: "enforce",
		Biometric:          BiometricDetectionConfig{Enabled: true, MinEvents: 20, ScoreThreshold: 50, TimeWindow: 5 * time.Minute},
		BrowserFingerprint: BrowserFingerprintConfig{Enabled: true, CheckCanvas: true, CheckWebGL: true, CheckFonts: true, CheckHeadless: true},
		Captcha:            CaptchaChallengeConfig{Enabled: true, Provider: "hcaptcha", SiteKey: "test", SecretKey: "test", Timeout: 30 * time.Second},
	}
	cfg.WAF.Response.SecurityHeaders = SecurityHeadersConfig{
		Enabled: true, HSTS: HSTSConfig{Enabled: true, MaxAge: 31536000, IncludeSubDomains: true},
		XContentTypeOptions: true, XFrameOptions: "SAMEORIGIN", ReferrerPolicy: "strict-origin-when-cross-origin",
	}
	cfg.WAF.Response.DataMasking = DataMaskingConfig{Enabled: true, MaskCreditCards: true, MaskSSN: true, MaskAPIKeys: true, StripStackTraces: true}
	cfg.WAF.Response.ErrorPages = ErrorPagesConfig{Enabled: true, Mode: "production"}
	cfg.WAF.ClientSide = ClientSideConfig{
		Enabled: true, Mode: "block",
		Exclusions: []string{"/api/health"},
		MagecartDetection: MagecartDetectionConfig{
			Enabled: true, DetectObfuscatedJS: true, DetectSuspiciousDomains: true,
			KnownSkimmingDomains: []string{"evil.com"}, BlockScore: 80,
		},
		AgentInjection: AgentInjectionConfig{
			Enabled: true, ScriptURL: "https://cdn.example.com/agent.js",
			ProtectedPaths: []string{"/checkout"},
		},
		CSP: CSPHeaderConfig{
			Enabled: true,
			DefaultSrc:      []string{"'self'"},
			ScriptSrc:       []string{"'self'"},
			StyleSrc:        []string{"'self'"},
			ImgSrc:          []string{"'self'"},
			ConnectSrc:      []string{"'self'"},
			FontSrc:         []string{"'self'"},
			ObjectSrc:       []string{"'none'"},
			MediaSrc:        []string{"'none'"},
			FrameSrc:        []string{"'none'"},
			FrameAncestors:  []string{"'none'"},
			FormAction:      []string{"'self'"},
		},
	}
	cfg.WAF.SIEM.Fields = map[string]string{"env": "prod"}
	cfg.WAF.Remediation.ExcludedPaths = []string{"/healthz", "/metrics"}
	cfg.WAF.WebSocket.AllowedOrigins = []string{"https://example.com"}
	cfg.WAF.WebSocket.BlockedExtensions = []string{"permessage-deflate"}
	cfg.WAF.ClusterSync.Clusters = []ClusterMembership{
		{ID: "c1", Name: "main", Nodes: []ClusterNodeConfig{{ID: "n1", Name: "node1", Address: "https://10.0.0.1:9444"}}, SyncScope: "all", Bidirectional: true},
	}
	cfg.WAF.ThreatIntel.Feeds = []ThreatFeedConfig{{Type: "url", URL: "https://feeds.example.com/threats.json", Refresh: time.Hour, Format: "json"}}
	cfg.WAF.CORS = CORSConfig{
		Enabled: true, AllowOrigins: []string{"https://example.com"},
		AllowMethods: []string{"GET", "POST"}, AllowHeaders: []string{"Content-Type"},
		ExposeHeaders: []string{"X-Custom"}, AllowCredentials: true, MaxAgeSeconds: 3600,
	}
	cfg.WAF.ATOProtection = ATOProtectionConfig{
		Enabled: true, LoginPaths: []string{"/login"},
		BruteForce:    BruteForceConfig{Enabled: true, Window: 5 * time.Minute, MaxAttemptsPerIP: 10, BlockDuration: time.Hour},
		CredStuffing:  CredentialStuffingConfig{Enabled: true, DistributedThreshold: 5, Window: time.Hour, BlockDuration: time.Hour},
		PasswordSpray: PasswordSprayConfig{Enabled: true, Threshold: 10, Window: time.Hour, BlockDuration: time.Hour},
		Travel:        ImpossibleTravelConfig{Enabled: true, MaxDistanceKm: 500, BlockDuration: time.Hour},
	}
	cfg.WAF.APISecurity = APISecurityConfig{
		Enabled: true, SkipPaths: []string{"/healthz"},
		JWT:     JWTConfig{Enabled: true, Algorithms: []string{"RS256"}, PublicKeyFile: "/pub.pem"},
		APIKeys: APIKeysConfig{Enabled: true, Keys: []APIKeyConfig{{Name: "test", KeyHash: "abc", KeyPrefix: "gwaf_", RateLimit: 100, AllowedPaths: []string{"/api"}, Enabled: true}}},
	}
	cfg.WAF.APIValidation = APIValidationConfig{Enabled: true, Schemas: []SchemaSourceConfig{{Path: "/schemas/api.yaml", Type: "openapi", AutoLearn: true}}}
	cfg.WAF.DLP.Patterns = []string{"credit_card", "ssn", "api_key"}
	cfg.WAF.ZeroTrust.AllowBypassPaths = []string{"/healthz"}
	cfg.WAF.Cache.CacheMethods = []string{"GET", "HEAD"}
	cfg.WAF.Cache.SkipPaths = []string{"/api/login"}
	cfg.WAF.Replay.CaptureHeaders = []string{"X-Request-ID"}
	cfg.WAF.Replay.SkipPaths = []string{"/healthz"}
	cfg.WAF.Replay.SkipMethods = []string{"OPTIONS"}
	cfg.WAF.Replay.Replay.Headers = map[string]string{"X-Source": "replay"}
	cfg.WAF.Canary.Regions = []string{"us-east-1"}
	cfg.WAF.Canary.Metadata = map[string]string{"version": "2.0"}
	cfg.WAF.GraphQL.AllowEndpoints = []string{"/graphql"}
	cfg.WAF.GRPC.ProtoPaths = []string{"/protos"}
	cfg.WAF.GRPC.AllowedServices = []string{"api.v1.Service"}
	cfg.WAF.GRPC.BlockedServices = []string{"admin.Service"}
	cfg.WAF.GRPC.AllowedMethods = []string{"api.v1.Service/Get"}
	cfg.WAF.GRPC.BlockedMethods = []string{"admin.Service/Delete"}
	cfg.WAF.GRPC.MethodRateLimits = []GRPCRateLimit{{Method: "api.v1.Service/Get", RequestsPerSecond: 100, BurstSize: 50}}
	cfg.WAF.VirtualPatch.BlockSeverity = []string{"CRITICAL", "HIGH"}
	cfg.WAF.CRS.Exclusions = []string{"941100"}
	cfg.WAF.CRS.DisabledRules = []string{"942100"}
	cfg.TLS.ACME.Domains = []string{"example.com", "*.example.com"}

	// Tenant
	cfg.Tenant.Tenants = []TenantDefinition{
		{ID: "t1", Name: "Tenant 1", Domains: []string{"t1.example.com"}, APIKey: "key1", Active: true},
	}

	return cfg
}

// TestDeepCopy_EmptySlices verifies DeepCopy handles nil slices correctly.
func TestDeepCopy_EmptySlices(t *testing.T) {
	cfg := &Config{}
	cp := cfg.DeepCopy()
	if cp == nil {
		t.Fatal("DeepCopy returned nil for empty config")
	}
	if cp.Upstreams != nil {
		t.Error("expected nil Upstreams")
	}
	if cp.Routes != nil {
		t.Error("expected nil Routes")
	}
	if cp.VirtualHosts != nil {
		t.Error("expected nil VirtualHosts")
	}
	if cp.TrustedProxies != nil {
		t.Error("expected nil TrustedProxies")
	}
}

// TestDeepCopy_NilWAFPointer tests VirtualHostConfig DeepCopy with nil WAF.
func TestDeepCopy_NilWAFPointer(t *testing.T) {
	vh := VirtualHostConfig{Domains: []string{"a.com"}}
	cp := vh.DeepCopy()
	if cp.WAF != nil {
		t.Error("expected nil WAF in copy")
	}
}

// TestDeepCopy_VHostWithWAF tests VirtualHostConfig DeepCopy with non-nil WAF.
func TestDeepCopy_VHostWithWAF(t *testing.T) {
	waf := DefaultWAFConfig()
	vh := VirtualHostConfig{Domains: []string{"a.com"}, WAF: &waf}
	cp := vh.DeepCopy()
	if cp.WAF == nil {
		t.Fatal("expected non-nil WAF in copy")
	}
	cp.WAF.Detection.Threshold.Block = 999
	if vh.WAF.Detection.Threshold.Block == 999 {
		t.Error("WAF not deep copied")
	}
}

// TestDeepCopy_EdgeCases tests individual DeepCopy methods with minimal inputs.
func TestDeepCopy_EdgeCases(t *testing.T) {
	t.Run("TLSConfig", func(t *testing.T) {
		tls := TLSConfig{Enabled: true, Listen: ":8443"}
		cp := tls.DeepCopy()
		if cp.Enabled != true || cp.Listen != ":8443" {
			t.Error("TLSConfig DeepCopy failed")
		}
	})
	t.Run("HTTP3Config", func(t *testing.T) {
		h := HTTP3Config{Enabled: true, MaxHeaderBytes: 1024}
		cp := h.DeepCopy()
		if !cp.Enabled || cp.MaxHeaderBytes != 1024 {
			t.Error("HTTP3Config DeepCopy failed")
		}
	})
	t.Run("TargetConfig", func(t *testing.T) {
		tc := TargetConfig{URL: "http://localhost", Weight: 5}
		cp := tc.DeepCopy()
		if cp.URL != "http://localhost" || cp.Weight != 5 {
			t.Error("TargetConfig DeepCopy failed")
		}
	})
	t.Run("HealthCheckConfig", func(t *testing.T) {
		hc := HealthCheckConfig{Enabled: true, Path: "/health"}
		cp := hc.DeepCopy()
		if !cp.Enabled || cp.Path != "/health" {
			t.Error("HealthCheckConfig DeepCopy failed")
		}
	})
	t.Run("DashboardConfig", func(t *testing.T) {
		d := DashboardConfig{Enabled: true, Listen: ":9443"}
		cp := d.DeepCopy()
		if !cp.Enabled || cp.Listen != ":9443" {
			t.Error("DashboardConfig DeepCopy failed")
		}
	})
	t.Run("MCPConfig", func(t *testing.T) {
		m := MCPConfig{Enabled: true, Transport: "stdio"}
		cp := m.DeepCopy()
		if !cp.Enabled || cp.Transport != "stdio" {
			t.Error("MCPConfig DeepCopy failed")
		}
	})
	t.Run("LogConfig", func(t *testing.T) {
		l := LogConfig{Level: "info", Format: "json"}
		cp := l.DeepCopy()
		if cp.Level != "info" || cp.Format != "json" {
			t.Error("LogConfig DeepCopy failed")
		}
	})
	t.Run("EventsConfig", func(t *testing.T) {
		e := EventsConfig{Storage: "memory", MaxEvents: 1000}
		cp := e.DeepCopy()
		if cp.Storage != "memory" || cp.MaxEvents != 1000 {
			t.Error("EventsConfig DeepCopy failed")
		}
	})
	t.Run("AlertingConfig", func(t *testing.T) {
		a := AlertingConfig{Enabled: true}
		cp := a.DeepCopy()
		if !cp.Enabled {
			t.Error("AlertingConfig DeepCopy failed")
		}
	})
	t.Run("DockerConfig", func(t *testing.T) {
		d := DockerConfig{Enabled: true, SocketPath: "/var/run/docker.sock"}
		cp := d.DeepCopy()
		if !cp.Enabled || cp.SocketPath != "/var/run/docker.sock" {
			t.Error("DockerConfig DeepCopy failed")
		}
	})
	t.Run("VHostTLSConfig", func(t *testing.T) {
		v := VHostTLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"}
		cp := v.DeepCopy()
		if cp.CertFile != "cert.pem" || cp.KeyFile != "key.pem" {
			t.Error("VHostTLSConfig DeepCopy failed")
		}
	})
	t.Run("PathOverride", func(t *testing.T) {
		p := PathOverride{Path: "/upload", MaxBodySize: 1024}
		cp := p.DeepCopy()
		if cp.Path != "/upload" || cp.MaxBodySize != 1024 {
			t.Error("PathOverride DeepCopy failed")
		}
	})
	t.Run("ResourceQuotaConfig", func(t *testing.T) {
		r := ResourceQuotaConfig{MaxRequestsPerMinute: 1000}
		cp := r.DeepCopy()
		if cp.MaxRequestsPerMinute != 1000 {
			t.Error("ResourceQuotaConfig DeepCopy failed")
		}
	})
	t.Run("RuleCondition", func(t *testing.T) {
		r := RuleCondition{Field: "path", Op: "contains", Value: "admin"}
		cp := r.DeepCopy()
		if cp.Field != "path" || cp.Op != "contains" {
			t.Error("RuleCondition DeepCopy failed")
		}
	})
	t.Run("GeoIPConfig", func(t *testing.T) {
		g := GeoIPConfig{Enabled: true, DBPath: "/geoip.db"}
		cp := g.DeepCopy()
		if !cp.Enabled || cp.DBPath != "/geoip.db" {
			t.Error("GeoIPConfig DeepCopy failed")
		}
	})
	t.Run("AutoBanConfig", func(t *testing.T) {
		a := AutoBanConfig{Enabled: true, DefaultTTL: time.Hour}
		cp := a.DeepCopy()
		if !cp.Enabled || cp.DefaultTTL != time.Hour {
			t.Error("AutoBanConfig DeepCopy failed")
		}
	})
	t.Run("ChallengeConfig", func(t *testing.T) {
		c := ChallengeConfig{Enabled: true, Difficulty: 20}
		cp := c.DeepCopy()
		if !cp.Enabled || cp.Difficulty != 20 {
			t.Error("ChallengeConfig DeepCopy failed")
		}
	})
	t.Run("HSTSConfig", func(t *testing.T) {
		h := HSTSConfig{Enabled: true, MaxAge: 31536000, IncludeSubDomains: true}
		cp := h.DeepCopy()
		if !cp.Enabled || cp.MaxAge != 31536000 {
			t.Error("HSTSConfig DeepCopy failed")
		}
	})
	t.Run("DataMaskingConfig", func(t *testing.T) {
		d := DataMaskingConfig{Enabled: true, MaskCreditCards: true}
		cp := d.DeepCopy()
		if !cp.Enabled || !cp.MaskCreditCards {
			t.Error("DataMaskingConfig DeepCopy failed")
		}
	})
	t.Run("ErrorPagesConfig", func(t *testing.T) {
		e := ErrorPagesConfig{Enabled: true, Mode: "production"}
		cp := e.DeepCopy()
		if !cp.Enabled || cp.Mode != "production" {
			t.Error("ErrorPagesConfig DeepCopy failed")
		}
	})
	t.Run("AnalyticsConfig", func(t *testing.T) {
		a := AnalyticsConfig{Enabled: true, RetentionDays: 30}
		cp := a.DeepCopy()
		if !cp.Enabled || cp.RetentionDays != 30 {
			t.Error("AnalyticsConfig DeepCopy failed")
		}
	})
	t.Run("AIAnalysisConfig", func(t *testing.T) {
		a := AIAnalysisConfig{Enabled: true, BatchSize: 20}
		cp := a.DeepCopy()
		if !cp.Enabled || cp.BatchSize != 20 {
			t.Error("AIAnalysisConfig DeepCopy failed")
		}
	})
	t.Run("MLAnomalyConfig", func(t *testing.T) {
		m := MLAnomalyConfig{Enabled: true, Threshold: 0.7}
		cp := m.DeepCopy()
		if !cp.Enabled || cp.Threshold != 0.7 {
			t.Error("MLAnomalyConfig DeepCopy failed")
		}
	})
	t.Run("APIDiscoveryConfig", func(t *testing.T) {
		a := APIDiscoveryConfig{Enabled: true, CaptureMode: "passive"}
		cp := a.DeepCopy()
		if !cp.Enabled || cp.CaptureMode != "passive" {
			t.Error("APIDiscoveryConfig DeepCopy failed")
		}
	})
	t.Run("GRPCRateLimit", func(t *testing.T) {
		g := GRPCRateLimit{Method: "svc/Method", RequestsPerSecond: 100}
		cp := g.DeepCopy()
		if cp.Method != "svc/Method" || cp.RequestsPerSecond != 100 {
			t.Error("GRPCRateLimit DeepCopy failed")
		}
	})
	t.Run("ThreatFeedConfig", func(t *testing.T) {
		tf := ThreatFeedConfig{Type: "url", URL: "http://feeds.example.com"}
		cp := tf.DeepCopy()
		if cp.Type != "url" || cp.URL != "http://feeds.example.com" {
			t.Error("ThreatFeedConfig DeepCopy failed")
		}
	})
	t.Run("SchemaSourceConfig", func(t *testing.T) {
		s := SchemaSourceConfig{Path: "/schema.yaml", Type: "openapi", AutoLearn: true}
		cp := s.DeepCopy()
		if cp.Path != "/schema.yaml" || !cp.AutoLearn {
			t.Error("SchemaSourceConfig DeepCopy failed")
		}
	})
	t.Run("APIKeyConfig", func(t *testing.T) {
		a := APIKeyConfig{Name: "test", Enabled: true}
		cp := a.DeepCopy()
		if cp.Name != "test" || !cp.Enabled {
			t.Error("APIKeyConfig DeepCopy failed")
		}
	})
	t.Run("ExclusionConfig", func(t *testing.T) {
		e := ExclusionConfig{Path: "/api", Detectors: []string{"sqli"}, Reason: "safe"}
		cp := e.DeepCopy()
		if cp.Path != "/api" {
			t.Error("ExclusionConfig DeepCopy failed")
		}
		// Verify independence
		cp.Detectors[0] = "xss"
		if e.Detectors[0] == "xss" {
			t.Error("ExclusionConfig Detectors not independent")
		}
	})
}

// TestFindVirtualHost_EdgeCases tests FindVirtualHost with various inputs.
func TestFindVirtualHost_EdgeCases(t *testing.T) {
	t.Run("empty host", func(t *testing.T) {
		if FindVirtualHost(nil, "") != nil {
			t.Error("expected nil for empty host")
		}
	})
	t.Run("empty vhosts", func(t *testing.T) {
		if FindVirtualHost([]VirtualHostConfig{}, "example.com") != nil {
			t.Error("expected nil for empty vhosts")
		}
	})
	t.Run("host with port", func(t *testing.T) {
		vhosts := []VirtualHostConfig{{Domains: []string{"example.com"}}}
		vh := FindVirtualHost(vhosts, "example.com:443")
		if vh == nil {
			t.Error("expected match for host:port")
		}
	})
	t.Run("ipv6 with port", func(t *testing.T) {
		vhosts := []VirtualHostConfig{{Domains: []string{"[::1]"}}}
		vh := FindVirtualHost(vhosts, "[::1]:8080")
		if vh == nil {
			t.Error("expected match for ipv6:port")
		}
	})
	t.Run("ipv6 without port", func(t *testing.T) {
		vhosts := []VirtualHostConfig{{Domains: []string{"[::1]"}}}
		vh := FindVirtualHost(vhosts, "[::1]")
		if vh == nil {
			t.Error("expected match for ipv6")
		}
	})
	t.Run("wildcard match", func(t *testing.T) {
		vhosts := []VirtualHostConfig{{Domains: []string{"*.example.com"}}}
		vh := FindVirtualHost(vhosts, "api.example.com")
		if vh == nil {
			t.Error("expected wildcard match")
		}
	})
	t.Run("wildcard no match", func(t *testing.T) {
		vhosts := []VirtualHostConfig{{Domains: []string{"*.example.com"}}}
		if FindVirtualHost(vhosts, "example.com") != nil {
			t.Error("wildcard should not match bare domain")
		}
	})
	t.Run("no match", func(t *testing.T) {
		vhosts := []VirtualHostConfig{{Domains: []string{"other.com"}}}
		if FindVirtualHost(vhosts, "example.com") != nil {
			t.Error("expected nil for no match")
		}
	})
}

// TestStripHostPort exercises stripHostPort directly.
func TestStripHostPort_Coverage(t *testing.T) {
	tests := []struct{ input, want string }{
		{"example.com:443", "example.com"},
		{"example.com", "example.com"},
		{"[::1]:8080", "[::1]"},
		{"[::1]", "[::1]"},
		{":8080", ""},
	}
	for _, tt := range tests {
		got := stripHostPort(tt.input)
		if got != tt.want {
			t.Errorf("stripHostPort(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
