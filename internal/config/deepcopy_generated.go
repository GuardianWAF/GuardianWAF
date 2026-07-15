// Code manually generated and maintained. The original generator (gen_deepcopy.py)
// is not in the repository. tools/deepcopy/main.go is an incomplete replacement
// that does not work with Go 1.26 (toolchain incompatibility). The methods below
// include hand-fixed patches for nested-slice and *bool pointer bugs.
//
// To regenerate when struct fields change, the tool must first be fixed:
//   cd tools/deepcopy && go run main.go ../../internal/config/config.go
// (This currently fails due to the go/parser directory restriction.)
// Until then, add new DeepCopy fields by hand following the existing pattern.
//
// DO NOT EDIT THE DEEP COPY LOGIC BY HAND — instead fix the generator and
// regenerate. Hand-patching is reserved for bugs in the generated output.

package config

func (in *Config) DeepCopy() *Config {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Mode = in.Mode
	out.Listen = in.Listen
	out.TLS = *in.TLS.DeepCopy()
	if in.Upstreams != nil {
		out.Upstreams = make([]UpstreamConfig, len(in.Upstreams))
		for i := range out.Upstreams {
			out.Upstreams[i] = *in.Upstreams[i].DeepCopy()
		}
	}
	if in.Routes != nil {
		out.Routes = make([]RouteConfig, len(in.Routes))
		for i := range out.Routes {
			out.Routes[i] = *in.Routes[i].DeepCopy()
		}
	}
	if in.VirtualHosts != nil {
		out.VirtualHosts = make([]VirtualHostConfig, len(in.VirtualHosts))
		for i := range out.VirtualHosts {
			out.VirtualHosts[i] = *in.VirtualHosts[i].DeepCopy()
		}
	}
	out.WAF = *in.WAF.DeepCopy()
	out.Dashboard = *in.Dashboard.DeepCopy()
	out.MCP = *in.MCP.DeepCopy()
	out.Docker = *in.Docker.DeepCopy()
	out.Alerting = *in.Alerting.DeepCopy()
	out.Logging = *in.Logging.DeepCopy()
	out.Events = *in.Events.DeepCopy()
	out.Tenant = *in.Tenant.DeepCopy()
	if in.TrustedProxies != nil {
		out.TrustedProxies = make([]string, len(in.TrustedProxies))
		copy(out.TrustedProxies, in.TrustedProxies)
	}
	if in.AllowPrivateUpstreams != nil {
		v := *in.AllowPrivateUpstreams
		out.AllowPrivateUpstreams = &v
	}
	if in.AllowedUpstreamCIDRs != nil {
		out.AllowedUpstreamCIDRs = make([]string, len(in.AllowedUpstreamCIDRs))
		copy(out.AllowedUpstreamCIDRs, in.AllowedUpstreamCIDRs)
	}
	out.Tracing = *in.Tracing.DeepCopy()
	if in.Features != nil {
		out.Features = make(map[string]bool, len(in.Features))
		for k, v := range in.Features {
			out.Features[k] = v
		}
	}
	out.Compliance = *in.Compliance.DeepCopy()
	return &out
}

func (in *AlertingConfig) DeepCopy() *AlertingConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	if in.Webhooks != nil {
		out.Webhooks = make([]WebhookConfig, len(in.Webhooks))
		for i := range out.Webhooks {
			out.Webhooks[i] = *in.Webhooks[i].DeepCopy()
		}
	}
	if in.Emails != nil {
		out.Emails = make([]EmailConfig, len(in.Emails))
		for i := range out.Emails {
			out.Emails[i] = *in.Emails[i].DeepCopy()
		}
	}
	return &out
}

func (in *WebhookConfig) DeepCopy() *WebhookConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Name = in.Name
	out.URL = in.URL
	out.Type = in.Type
	if in.Events != nil {
		out.Events = make([]string, len(in.Events))
		copy(out.Events, in.Events)
	}
	out.MinScore = in.MinScore
	out.Cooldown = in.Cooldown
	if in.Headers != nil {
		out.Headers = make(map[string]string, len(in.Headers))
		for k, v := range in.Headers {
			out.Headers[k] = v
		}
	}
	return &out
}

func (in *EmailConfig) DeepCopy() *EmailConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Name = in.Name
	out.SMTPHost = in.SMTPHost
	out.SMTPPort = in.SMTPPort
	out.Username = in.Username
	out.Password = in.Password
	out.From = in.From
	if in.To != nil {
		out.To = make([]string, len(in.To))
		copy(out.To, in.To)
	}
	out.UseTLS = in.UseTLS
	if in.Events != nil {
		out.Events = make([]string, len(in.Events))
		copy(out.Events, in.Events)
	}
	out.MinScore = in.MinScore
	out.Cooldown = in.Cooldown
	out.Subject = in.Subject
	out.Template = in.Template
	return &out
}

func (in *DockerConfig) DeepCopy() *DockerConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.SocketPath = in.SocketPath
	out.TLSVerify = in.TLSVerify
	out.TLSCACert = in.TLSCACert
	out.TLSCert = in.TLSCert
	out.TLSKey = in.TLSKey
	out.LabelPrefix = in.LabelPrefix
	out.PollInterval = in.PollInterval
	out.Network = in.Network
	return &out
}

func (in *TLSConfig) DeepCopy() *TLSConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Listen = in.Listen
	out.CertFile = in.CertFile
	out.KeyFile = in.KeyFile
	out.HTTPRedirect = in.HTTPRedirect
	out.ACME = *in.ACME.DeepCopy()
	out.HTTP3 = *in.HTTP3.DeepCopy()
	return &out
}

func (in *ACMEConfig) DeepCopy() *ACMEConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Email = in.Email
	if in.Domains != nil {
		out.Domains = make([]string, len(in.Domains))
		copy(out.Domains, in.Domains)
	}
	out.CacheDir = in.CacheDir
	return &out
}

func (in *HTTP3Config) DeepCopy() *HTTP3Config {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Listen = in.Listen
	out.MaxHeaderBytes = in.MaxHeaderBytes
	out.ReadTimeout = in.ReadTimeout
	out.WriteTimeout = in.WriteTimeout
	out.IdleTimeout = in.IdleTimeout
	out.Enable0RTT = in.Enable0RTT
	out.EnableDatagrams = in.EnableDatagrams
	out.AltSvcPort = in.AltSvcPort
	out.AdvertiseAltSvc = in.AdvertiseAltSvc
	return &out
}

func (in *UpstreamConfig) DeepCopy() *UpstreamConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Name = in.Name
	if in.Targets != nil {
		out.Targets = make([]TargetConfig, len(in.Targets))
		for i := range out.Targets {
			out.Targets[i] = *in.Targets[i].DeepCopy()
		}
	}
	out.HealthCheck = *in.HealthCheck.DeepCopy()
	out.LoadBalancer = in.LoadBalancer
	return &out
}

func (in *TargetConfig) DeepCopy() *TargetConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.URL = in.URL
	out.Weight = in.Weight
	return &out
}

func (in *HealthCheckConfig) DeepCopy() *HealthCheckConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Interval = in.Interval
	out.Timeout = in.Timeout
	out.Path = in.Path
	return &out
}

func (in *RouteConfig) DeepCopy() *RouteConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Path = in.Path
	out.Upstream = in.Upstream
	out.StripPrefix = in.StripPrefix
	if in.Methods != nil {
		out.Methods = make([]string, len(in.Methods))
		copy(out.Methods, in.Methods)
	}
	return &out
}

func (in *VirtualHostConfig) DeepCopy() *VirtualHostConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	if in.Domains != nil {
		out.Domains = make([]string, len(in.Domains))
		copy(out.Domains, in.Domains)
	}
	out.TLS = *in.TLS.DeepCopy()
	if in.Routes != nil {
		out.Routes = make([]RouteConfig, len(in.Routes))
		for i := range out.Routes {
			out.Routes[i] = *in.Routes[i].DeepCopy()
		}
	}
	if in.WAF != nil {
		waf := in.WAF.DeepCopy()
		out.WAF = waf
	} else {
		out.WAF = nil
	}
	return &out
}

func (in *VHostTLSConfig) DeepCopy() *VHostTLSConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.CertFile = in.CertFile
	out.KeyFile = in.KeyFile
	return &out
}

func (in *CustomRulesConfig) DeepCopy() *CustomRulesConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	if in.Rules != nil {
		out.Rules = make([]CustomRule, len(in.Rules))
		for i := range out.Rules {
			out.Rules[i] = *in.Rules[i].DeepCopy()
		}
	}
	return &out
}

func (in *CustomRule) DeepCopy() *CustomRule {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.ID = in.ID
	out.Name = in.Name
	out.Enabled = in.Enabled
	out.Priority = in.Priority
	if in.Conditions != nil {
		out.Conditions = make([]RuleCondition, len(in.Conditions))
		for i := range out.Conditions {
			out.Conditions[i] = *in.Conditions[i].DeepCopy()
		}
	}
	out.Action = in.Action
	out.Score = in.Score
	return &out
}

func (in *RuleCondition) DeepCopy() *RuleCondition {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Field = in.Field
	out.Op = in.Op
	out.Value = in.Value
	return &out
}

func (in *GeoIPConfig) DeepCopy() *GeoIPConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.DBPath = in.DBPath
	out.AutoDownload = in.AutoDownload
	out.DownloadURL = in.DownloadURL
	out.RequireReady = in.RequireReady
	return &out
}

func (in *WAFConfig) DeepCopy() *WAFConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.IPACL = *in.IPACL.DeepCopy()
	out.CustomRules = *in.CustomRules.DeepCopy()
	out.GeoIP = *in.GeoIP.DeepCopy()
	out.ThreatIntel = *in.ThreatIntel.DeepCopy()
	out.CORS = *in.CORS.DeepCopy()
	out.RateLimit = *in.RateLimit.DeepCopy()
	out.ATOProtection = *in.ATOProtection.DeepCopy()
	out.APISecurity = *in.APISecurity.DeepCopy()
	out.APIValidation = *in.APIValidation.DeepCopy()
	out.Sanitizer = *in.Sanitizer.DeepCopy()
	out.Detection = *in.Detection.DeepCopy()
	out.BotDetection = *in.BotDetection.DeepCopy()
	out.Challenge = *in.Challenge.DeepCopy()
	out.Response = *in.Response.DeepCopy()
	out.ClientSide = *in.ClientSide.DeepCopy()
	out.AIAnalysis = *in.AIAnalysis.DeepCopy()
	out.MLAnomaly = *in.MLAnomaly.DeepCopy()
	out.APIDiscovery = *in.APIDiscovery.DeepCopy()
	out.GraphQL = *in.GraphQL.DeepCopy()
	out.GRPC = *in.GRPC.DeepCopy()
	out.Tenant = *in.Tenant.DeepCopy()
	out.DLP = *in.DLP.DeepCopy()
	out.ZeroTrust = *in.ZeroTrust.DeepCopy()
	out.SIEM = *in.SIEM.DeepCopy()
	out.Cache = *in.Cache.DeepCopy()
	out.Replay = *in.Replay.DeepCopy()
	out.Canary = *in.Canary.DeepCopy()
	out.Analytics = *in.Analytics.DeepCopy()
	out.ClusterSync = *in.ClusterSync.DeepCopy()
	out.Cluster = *in.Cluster.DeepCopy()
	out.Remediation = *in.Remediation.DeepCopy()
	out.WebSocket = *in.WebSocket.DeepCopy()
	out.CRS = *in.CRS.DeepCopy()
	out.VirtualPatch = *in.VirtualPatch.DeepCopy()
	return &out
}

func (in *AIAnalysisConfig) DeepCopy() *AIAnalysisConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.StorePath = in.StorePath
	out.CatalogURL = in.CatalogURL
	out.BatchSize = in.BatchSize
	out.BatchInterval = in.BatchInterval
	out.MinScore = in.MinScore
	out.MaxTokensPerHour = in.MaxTokensPerHour
	out.MaxTokensPerDay = in.MaxTokensPerDay
	out.MaxRequestsHour = in.MaxRequestsHour
	out.AutoBlock = in.AutoBlock
	out.AutoBlockTTL = in.AutoBlockTTL
	return &out
}

func (in *DLPConfig) DeepCopy() *DLPConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.ScanRequest = in.ScanRequest
	out.ScanResponse = in.ScanResponse
	out.BlockOnMatch = in.BlockOnMatch
	out.MaskResponse = in.MaskResponse
	out.MaxBodySize = in.MaxBodySize
	if in.Patterns != nil {
		out.Patterns = make([]string, len(in.Patterns))
		copy(out.Patterns, in.Patterns)
	}
	return &out
}

func (in *ZeroTrustConfig) DeepCopy() *ZeroTrustConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.RequireMTLS = in.RequireMTLS
	out.RequireAttestation = in.RequireAttestation
	out.SessionTTL = in.SessionTTL
	out.AttestationTTL = in.AttestationTTL
	out.TrustedCAPath = in.TrustedCAPath
	out.DeviceTrustThreshold = in.DeviceTrustThreshold
	if in.AllowBypassPaths != nil {
		out.AllowBypassPaths = make([]string, len(in.AllowBypassPaths))
		copy(out.AllowBypassPaths, in.AllowBypassPaths)
	}
	return &out
}

func (in *CacheConfig) DeepCopy() *CacheConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Backend = in.Backend
	out.TTL = in.TTL
	out.MaxSize = in.MaxSize
	out.RedisAddr = in.RedisAddr
	out.RedisPass = in.RedisPass
	out.RedisDB = in.RedisDB
	out.Prefix = in.Prefix
	if in.CacheMethods != nil {
		out.CacheMethods = make([]string, len(in.CacheMethods))
		copy(out.CacheMethods, in.CacheMethods)
	}
	if in.CacheStatusCodes != nil {
		out.CacheStatusCodes = make([]int, len(in.CacheStatusCodes))
		copy(out.CacheStatusCodes, in.CacheStatusCodes)
	}
	if in.SkipPaths != nil {
		out.SkipPaths = make([]string, len(in.SkipPaths))
		copy(out.SkipPaths, in.SkipPaths)
	}
	out.MaxCacheSize = in.MaxCacheSize
	out.StaleWhileRevalidate = in.StaleWhileRevalidate
	return &out
}

func (in *ReplayConfig) DeepCopy() *ReplayConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.StoragePath = in.StoragePath
	out.Format = in.Format
	out.MaxFileSize = in.MaxFileSize
	out.MaxFiles = in.MaxFiles
	out.RetentionDays = in.RetentionDays
	out.CaptureRequest = in.CaptureRequest
	out.CaptureResponse = in.CaptureResponse
	if in.CaptureHeaders != nil {
		out.CaptureHeaders = make([]string, len(in.CaptureHeaders))
		copy(out.CaptureHeaders, in.CaptureHeaders)
	}
	if in.SkipPaths != nil {
		out.SkipPaths = make([]string, len(in.SkipPaths))
		copy(out.SkipPaths, in.SkipPaths)
	}
	if in.SkipMethods != nil {
		out.SkipMethods = make([]string, len(in.SkipMethods))
		copy(out.SkipMethods, in.SkipMethods)
	}
	out.Compress = in.Compress
	out.Replay = *in.Replay.DeepCopy()
	return &out
}

func (in *ReplayEngineConfig) DeepCopy() *ReplayEngineConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.TargetBaseURL = in.TargetBaseURL
	out.RateLimit = in.RateLimit
	out.Concurrency = in.Concurrency
	out.Timeout = in.Timeout
	out.FollowRedirects = in.FollowRedirects
	out.ModifyHost = in.ModifyHost
	out.PreserveIDs = in.PreserveIDs
	out.DryRun = in.DryRun
	if in.Headers != nil {
		out.Headers = make(map[string]string, len(in.Headers))
		for k, v := range in.Headers {
			out.Headers[k] = v
		}
	}
	return &out
}

func (in *CanaryConfig) DeepCopy() *CanaryConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.CanaryVersion = in.CanaryVersion
	out.StableUpstream = in.StableUpstream
	out.CanaryUpstream = in.CanaryUpstream
	out.Strategy = in.Strategy
	out.Percentage = in.Percentage
	out.HeaderName = in.HeaderName
	out.HeaderValue = in.HeaderValue
	out.CookieName = in.CookieName
	out.CookieValue = in.CookieValue
	if in.Regions != nil {
		out.Regions = make([]string, len(in.Regions))
		copy(out.Regions, in.Regions)
	}
	out.AutoRollback = in.AutoRollback
	out.ErrorThreshold = in.ErrorThreshold
	out.LatencyThreshold = in.LatencyThreshold
	out.HealthCheckPath = in.HealthCheckPath
	if in.Metadata != nil {
		out.Metadata = make(map[string]string, len(in.Metadata))
		for k, v := range in.Metadata {
			out.Metadata[k] = v
		}
	}
	return &out
}

func (in *AnalyticsConfig) DeepCopy() *AnalyticsConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.StoragePath = in.StoragePath
	out.RetentionDays = in.RetentionDays
	out.FlushInterval = in.FlushInterval
	out.MaxDataPoints = in.MaxDataPoints
	out.EnableTimeSeries = in.EnableTimeSeries
	return &out
}

func (in *ClusterNodeConfig) DeepCopy() *ClusterNodeConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.ID = in.ID
	out.Name = in.Name
	out.Address = in.Address
	return &out
}

func (in *ClusterSyncConfig) DeepCopy() *ClusterSyncConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.NodeID = in.NodeID
	out.NodeName = in.NodeName
	out.Listen = in.Listen
	out.Port = in.Port
	out.SharedSecret = in.SharedSecret
	if in.Clusters != nil {
		out.Clusters = make([]ClusterMembership, len(in.Clusters))
		for i := range out.Clusters {
			out.Clusters[i] = *in.Clusters[i].DeepCopy()
		}
	}
	out.SyncInterval = in.SyncInterval
	out.ConflictResolution = in.ConflictResolution
	out.MaxRetries = in.MaxRetries
	out.RetryDelay = in.RetryDelay
	return &out
}

func (in *ClusterConfig) DeepCopy() *ClusterConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Config = in.Config
	return &out
}

func (in *ClusterMembership) DeepCopy() *ClusterMembership {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.ID = in.ID
	out.Name = in.Name
	if in.Nodes != nil {
		out.Nodes = make([]ClusterNodeConfig, len(in.Nodes))
		for i := range out.Nodes {
			out.Nodes[i] = *in.Nodes[i].DeepCopy()
		}
	}
	out.SyncScope = in.SyncScope
	out.Bidirectional = in.Bidirectional
	return &out
}

func (in *RemediationConfig) DeepCopy() *RemediationConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.AutoApply = in.AutoApply
	out.ConfidenceThreshold = in.ConfidenceThreshold
	out.MaxRulesPerDay = in.MaxRulesPerDay
	out.RuleTTL = in.RuleTTL
	if in.ExcludedPaths != nil {
		out.ExcludedPaths = make([]string, len(in.ExcludedPaths))
		copy(out.ExcludedPaths, in.ExcludedPaths)
	}
	out.StoragePath = in.StoragePath
	return &out
}

func (in *WebSocketConfig) DeepCopy() *WebSocketConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.MaxMessageSize = in.MaxMessageSize
	out.MaxFrameSize = in.MaxFrameSize
	out.RateLimitPerSecond = in.RateLimitPerSecond
	out.RateLimitBurst = in.RateLimitBurst
	if in.AllowedOrigins != nil {
		out.AllowedOrigins = make([]string, len(in.AllowedOrigins))
		copy(out.AllowedOrigins, in.AllowedOrigins)
	}
	if in.BlockedExtensions != nil {
		out.BlockedExtensions = make([]string, len(in.BlockedExtensions))
		copy(out.BlockedExtensions, in.BlockedExtensions)
	}
	out.BlockEmptyMessages = in.BlockEmptyMessages
	out.BlockBinaryMessages = in.BlockBinaryMessages
	out.MaxConcurrentPerIP = in.MaxConcurrentPerIP
	out.HandshakeTimeout = in.HandshakeTimeout
	out.IdleTimeout = in.IdleTimeout
	out.ScanPayloads = in.ScanPayloads
	return &out
}

func (in *SIEMConfig) DeepCopy() *SIEMConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Endpoint = in.Endpoint
	out.Format = in.Format
	out.APIKey = in.APIKey
	out.Index = in.Index
	out.BatchSize = in.BatchSize
	out.FlushInterval = in.FlushInterval
	out.Timeout = in.Timeout
	out.SkipVerify = in.SkipVerify
	if in.Fields != nil {
		out.Fields = make(map[string]string, len(in.Fields))
		for k, v := range in.Fields {
			out.Fields[k] = v
		}
	}
	return &out
}

func (in *IPACLConfig) DeepCopy() *IPACLConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	if in.Whitelist != nil {
		out.Whitelist = make([]string, len(in.Whitelist))
		copy(out.Whitelist, in.Whitelist)
	}
	if in.Blacklist != nil {
		out.Blacklist = make([]string, len(in.Blacklist))
		copy(out.Blacklist, in.Blacklist)
	}
	out.AutoBan = *in.AutoBan.DeepCopy()
	return &out
}

func (in *AutoBanConfig) DeepCopy() *AutoBanConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.DefaultTTL = in.DefaultTTL
	out.MaxTTL = in.MaxTTL
	out.MaxAutoBanEntries = in.MaxAutoBanEntries
	out.PersistPath = in.PersistPath
	out.PersistInterval = in.PersistInterval
	return &out
}

func (in *RateLimitConfig) DeepCopy() *RateLimitConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	if in.Rules != nil {
		out.Rules = make([]RateLimitRule, len(in.Rules))
		for i := range out.Rules {
			out.Rules[i] = *in.Rules[i].DeepCopy()
		}
	}
	return &out
}

func (in *RateLimitRule) DeepCopy() *RateLimitRule {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.ID = in.ID
	out.Scope = in.Scope
	if in.Paths != nil {
		out.Paths = make([]string, len(in.Paths))
		copy(out.Paths, in.Paths)
	}
	out.Limit = in.Limit
	out.Window = in.Window
	out.Burst = in.Burst
	out.Action = in.Action
	out.AutoBanAfter = in.AutoBanAfter
	return &out
}

func (in *SanitizerConfig) DeepCopy() *SanitizerConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.MaxURLLength = in.MaxURLLength
	out.MaxHeaderSize = in.MaxHeaderSize
	out.MaxHeaderCount = in.MaxHeaderCount
	out.MaxBodySize = in.MaxBodySize
	out.MaxCookieSize = in.MaxCookieSize
	out.BlockNullBytes = in.BlockNullBytes
	out.NormalizeEncoding = in.NormalizeEncoding
	out.StripHopByHop = in.StripHopByHop
	if in.AllowedMethods != nil {
		out.AllowedMethods = make([]string, len(in.AllowedMethods))
		copy(out.AllowedMethods, in.AllowedMethods)
	}
	if in.PathOverrides != nil {
		out.PathOverrides = make([]PathOverride, len(in.PathOverrides))
		copy(out.PathOverrides, in.PathOverrides)
	}
	return &out
}

func (in *PathOverride) DeepCopy() *PathOverride {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Path = in.Path
	out.MaxBodySize = in.MaxBodySize
	return &out
}

func (in *DetectionConfig) DeepCopy() *DetectionConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Threshold = *in.Threshold.DeepCopy()
	if in.Detectors != nil {
		out.Detectors = make(map[string]DetectorConfig, len(in.Detectors))
		for k, v := range in.Detectors {
			out.Detectors[k] = v
		}
	}
	if in.Exclusions != nil {
		out.Exclusions = make([]ExclusionConfig, len(in.Exclusions))
		for i := range out.Exclusions {
			out.Exclusions[i] = *in.Exclusions[i].DeepCopy()
		}
	}
	return &out
}

func (in *ThresholdConfig) DeepCopy() *ThresholdConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Block = in.Block
	out.Log = in.Log
	return &out
}

func (in *DetectorConfig) DeepCopy() *DetectorConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Multiplier = in.Multiplier
	return &out
}

func (in *ExclusionConfig) DeepCopy() *ExclusionConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Path = in.Path
	if in.Detectors != nil {
		out.Detectors = make([]string, len(in.Detectors))
		copy(out.Detectors, in.Detectors)
	}
	out.Reason = in.Reason
	return &out
}

func (in *BotDetectionConfig) DeepCopy() *BotDetectionConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Mode = in.Mode
	out.TLSFingerprint = *in.TLSFingerprint.DeepCopy()
	out.UserAgent = *in.UserAgent.DeepCopy()
	out.Behavior = *in.Behavior.DeepCopy()
	return &out
}

func (in *TLSFingerprintConfig) DeepCopy() *TLSFingerprintConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.KnownBotsAction = in.KnownBotsAction
	out.UnknownAction = in.UnknownAction
	out.MismatchAction = in.MismatchAction
	return &out
}

func (in *UAConfig) DeepCopy() *UAConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.BlockEmpty = in.BlockEmpty
	out.BlockKnownScanners = in.BlockKnownScanners
	return &out
}

func (in *BehaviorConfig) DeepCopy() *BehaviorConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Window = in.Window
	out.RPSThreshold = in.RPSThreshold
	out.ErrorRateThreshold = in.ErrorRateThreshold
	return &out
}

func (in *ChallengeConfig) DeepCopy() *ChallengeConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Difficulty = in.Difficulty
	out.CookieTTL = in.CookieTTL
	out.CookieName = in.CookieName
	out.SecretKey = in.SecretKey
	return &out
}

func (in *ResponseConfig) DeepCopy() *ResponseConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.SecurityHeaders = *in.SecurityHeaders.DeepCopy()
	out.DataMasking = *in.DataMasking.DeepCopy()
	out.ErrorPages = *in.ErrorPages.DeepCopy()
	return &out
}

func (in *ClientSideConfig) DeepCopy() *ClientSideConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Mode = in.Mode
	out.MagecartDetection = *in.MagecartDetection.DeepCopy()
	out.AgentInjection = *in.AgentInjection.DeepCopy()
	out.CSP = *in.CSP.DeepCopy()
	if in.Exclusions != nil {
		out.Exclusions = make([]string, len(in.Exclusions))
		copy(out.Exclusions, in.Exclusions)
	}
	return &out
}

func (in *MagecartDetectionConfig) DeepCopy() *MagecartDetectionConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.DetectObfuscatedJS = in.DetectObfuscatedJS
	out.DetectSuspiciousDomains = in.DetectSuspiciousDomains
	out.DetectFormExfiltration = in.DetectFormExfiltration
	out.DetectKeyloggers = in.DetectKeyloggers
	if in.KnownSkimmingDomains != nil {
		out.KnownSkimmingDomains = make([]string, len(in.KnownSkimmingDomains))
		copy(out.KnownSkimmingDomains, in.KnownSkimmingDomains)
	}
	out.BlockScore = in.BlockScore
	out.AlertScore = in.AlertScore
	return &out
}

func (in *AgentInjectionConfig) DeepCopy() *AgentInjectionConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.ScriptURL = in.ScriptURL
	out.InjectInHTML = in.InjectInHTML
	out.InjectPosition = in.InjectPosition
	out.MonitorDOM = in.MonitorDOM
	out.MonitorNetwork = in.MonitorNetwork
	out.MonitorForms = in.MonitorForms
	if in.ProtectedPaths != nil {
		out.ProtectedPaths = make([]string, len(in.ProtectedPaths))
		copy(out.ProtectedPaths, in.ProtectedPaths)
	}
	return &out
}

func (in *CSPHeaderConfig) DeepCopy() *CSPHeaderConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.ReportOnly = in.ReportOnly
	if in.DefaultSrc != nil {
		out.DefaultSrc = make([]string, len(in.DefaultSrc))
		copy(out.DefaultSrc, in.DefaultSrc)
	}
	if in.ScriptSrc != nil {
		out.ScriptSrc = make([]string, len(in.ScriptSrc))
		copy(out.ScriptSrc, in.ScriptSrc)
	}
	if in.StyleSrc != nil {
		out.StyleSrc = make([]string, len(in.StyleSrc))
		copy(out.StyleSrc, in.StyleSrc)
	}
	if in.ImgSrc != nil {
		out.ImgSrc = make([]string, len(in.ImgSrc))
		copy(out.ImgSrc, in.ImgSrc)
	}
	if in.ConnectSrc != nil {
		out.ConnectSrc = make([]string, len(in.ConnectSrc))
		copy(out.ConnectSrc, in.ConnectSrc)
	}
	if in.FontSrc != nil {
		out.FontSrc = make([]string, len(in.FontSrc))
		copy(out.FontSrc, in.FontSrc)
	}
	if in.ObjectSrc != nil {
		out.ObjectSrc = make([]string, len(in.ObjectSrc))
		copy(out.ObjectSrc, in.ObjectSrc)
	}
	if in.MediaSrc != nil {
		out.MediaSrc = make([]string, len(in.MediaSrc))
		copy(out.MediaSrc, in.MediaSrc)
	}
	if in.FrameSrc != nil {
		out.FrameSrc = make([]string, len(in.FrameSrc))
		copy(out.FrameSrc, in.FrameSrc)
	}
	if in.FrameAncestors != nil {
		out.FrameAncestors = make([]string, len(in.FrameAncestors))
		copy(out.FrameAncestors, in.FrameAncestors)
	}
	if in.FormAction != nil {
		out.FormAction = make([]string, len(in.FormAction))
		copy(out.FormAction, in.FormAction)
	}
	if in.BaseURI != nil {
		out.BaseURI = make([]string, len(in.BaseURI))
		copy(out.BaseURI, in.BaseURI)
	}
	out.ReportURI = in.ReportURI
	out.UpgradeInsecure = in.UpgradeInsecure
	return &out
}

func (in *SecurityHeadersConfig) DeepCopy() *SecurityHeadersConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.HSTS = *in.HSTS.DeepCopy()
	out.XContentTypeOptions = in.XContentTypeOptions
	out.XFrameOptions = in.XFrameOptions
	out.ReferrerPolicy = in.ReferrerPolicy
	out.PermissionsPolicy = in.PermissionsPolicy
	return &out
}

func (in *HSTSConfig) DeepCopy() *HSTSConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.MaxAge = in.MaxAge
	out.IncludeSubDomains = in.IncludeSubDomains
	return &out
}

func (in *DataMaskingConfig) DeepCopy() *DataMaskingConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.MaskCreditCards = in.MaskCreditCards
	out.MaskSSN = in.MaskSSN
	out.MaskAPIKeys = in.MaskAPIKeys
	out.StripStackTraces = in.StripStackTraces
	return &out
}

func (in *ErrorPagesConfig) DeepCopy() *ErrorPagesConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Mode = in.Mode
	return &out
}

func (in *MLAnomalyConfig) DeepCopy() *MLAnomalyConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Mode = in.Mode
	out.Threshold = in.Threshold
	out.WindowSize = in.WindowSize
	out.MinSamples = in.MinSamples
	out.FeatureBuckets = in.FeatureBuckets
	out.AutoBlock = in.AutoBlock
	out.BlockThreshold = in.BlockThreshold
	return &out
}

func (in *APIDiscoveryConfig) DeepCopy() *APIDiscoveryConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.CaptureMode = in.CaptureMode
	out.RingBufferSize = in.RingBufferSize
	out.MinSamples = in.MinSamples
	out.ClusterThreshold = in.ClusterThreshold
	out.ExportPath = in.ExportPath
	out.ExportFormat = in.ExportFormat
	out.AutoExport = in.AutoExport
	out.ExportInterval = in.ExportInterval
	return &out
}

func (in *GraphQLConfig) DeepCopy() *GraphQLConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.MaxDepth = in.MaxDepth
	out.MaxComplexity = in.MaxComplexity
	out.BlockIntrospection = in.BlockIntrospection
	if in.AllowEndpoints != nil {
		out.AllowEndpoints = make([]string, len(in.AllowEndpoints))
		copy(out.AllowEndpoints, in.AllowEndpoints)
	}
	return &out
}

func (in *GRPCConfig) DeepCopy() *GRPCConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.GRPCWebEnabled = in.GRPCWebEnabled
	if in.ProtoPaths != nil {
		out.ProtoPaths = make([]string, len(in.ProtoPaths))
		copy(out.ProtoPaths, in.ProtoPaths)
	}
	if in.AllowedServices != nil {
		out.AllowedServices = make([]string, len(in.AllowedServices))
		copy(out.AllowedServices, in.AllowedServices)
	}
	if in.BlockedServices != nil {
		out.BlockedServices = make([]string, len(in.BlockedServices))
		copy(out.BlockedServices, in.BlockedServices)
	}
	if in.AllowedMethods != nil {
		out.AllowedMethods = make([]string, len(in.AllowedMethods))
		copy(out.AllowedMethods, in.AllowedMethods)
	}
	if in.BlockedMethods != nil {
		out.BlockedMethods = make([]string, len(in.BlockedMethods))
		copy(out.BlockedMethods, in.BlockedMethods)
	}
	out.ValidateProto = in.ValidateProto
	out.ReflectionEnabled = in.ReflectionEnabled
	out.MaxMessageSize = in.MaxMessageSize
	out.MaxStreamDuration = in.MaxStreamDuration
	out.MaxConcurrentStreams = in.MaxConcurrentStreams
	if in.MethodRateLimits != nil {
		out.MethodRateLimits = make([]GRPCRateLimit, len(in.MethodRateLimits))
		copy(out.MethodRateLimits, in.MethodRateLimits)
	}
	out.RequireTLS = in.RequireTLS
	return &out
}

func (in *GRPCRateLimit) DeepCopy() *GRPCRateLimit {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Method = in.Method
	out.RequestsPerSecond = in.RequestsPerSecond
	out.BurstSize = in.BurstSize
	return &out
}

func (in *TenantConfig) DeepCopy() *TenantConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.MaxTenants = in.MaxTenants
	out.HeaderName = in.HeaderName
	out.DefaultQuota = *in.DefaultQuota.DeepCopy()
	out.StorePath = in.StorePath
	if in.Tenants != nil {
		out.Tenants = make([]TenantDefinition, len(in.Tenants))
		for i := range out.Tenants {
			out.Tenants[i] = *in.Tenants[i].DeepCopy()
		}
	}
	return &out
}

func (in *ResourceQuotaConfig) DeepCopy() *ResourceQuotaConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.MaxRequestsPerMinute = in.MaxRequestsPerMinute
	out.MaxRequestsPerHour = in.MaxRequestsPerHour
	out.MaxBandwidthMbps = in.MaxBandwidthMbps
	out.MaxRules = in.MaxRules
	out.MaxRateLimitRules = in.MaxRateLimitRules
	out.MaxIPACLs = in.MaxIPACLs
	return &out
}

func (in *TenantDefinition) DeepCopy() *TenantDefinition {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.ID = in.ID
	out.Name = in.Name
	out.Description = in.Description
	if in.Domains != nil {
		out.Domains = make([]string, len(in.Domains))
		copy(out.Domains, in.Domains)
	}
	out.APIKey = in.APIKey
	out.Active = in.Active
	out.Quota = *in.Quota.DeepCopy()
	return &out
}

func (in *DashboardConfig) DeepCopy() *DashboardConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Listen = in.Listen
	out.APIKey = in.APIKey
	out.AdminKey = in.AdminKey
	out.TLS = in.TLS
	return &out
}

func (in *MCPConfig) DeepCopy() *MCPConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Transport = in.Transport
	return &out
}

func (in *LogConfig) DeepCopy() *LogConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Level = in.Level
	out.Format = in.Format
	out.Output = in.Output
	out.LogAllowed = in.LogAllowed
	out.LogBlocked = in.LogBlocked
	out.LogBody = in.LogBody
	out.MaxSizeMB = in.MaxSizeMB
	out.MaxBackups = in.MaxBackups
	out.MaxAgeDays = in.MaxAgeDays
	return &out
}

func (in *EventsConfig) DeepCopy() *EventsConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Storage = in.Storage
	out.MaxEvents = in.MaxEvents
	out.FilePath = in.FilePath
	return &out
}

func (in *ThreatIntelConfig) DeepCopy() *ThreatIntelConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.IPReputation = *in.IPReputation.DeepCopy()
	out.DomainRep = *in.DomainRep.DeepCopy()
	out.CacheSize = in.CacheSize
	out.CacheTTL = in.CacheTTL
	if in.Feeds != nil {
		out.Feeds = make([]ThreatFeedConfig, len(in.Feeds))
		for i := range out.Feeds {
			out.Feeds[i] = *in.Feeds[i].DeepCopy()
		}
	}
	return &out
}

func (in *IPReputationConfig) DeepCopy() *IPReputationConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.BlockMalicious = in.BlockMalicious
	out.ScoreThreshold = in.ScoreThreshold
	return &out
}

func (in *DomainReputationConfig) DeepCopy() *DomainReputationConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.BlockMalicious = in.BlockMalicious
	out.CheckRedirects = in.CheckRedirects
	return &out
}

func (in *ThreatFeedConfig) DeepCopy() *ThreatFeedConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Type = in.Type
	out.Path = in.Path
	out.URL = in.URL
	out.Refresh = in.Refresh
	out.Format = in.Format
	return &out
}

func (in *CORSConfig) DeepCopy() *CORSConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	if in.AllowOrigins != nil {
		out.AllowOrigins = make([]string, len(in.AllowOrigins))
		copy(out.AllowOrigins, in.AllowOrigins)
	}
	if in.AllowMethods != nil {
		out.AllowMethods = make([]string, len(in.AllowMethods))
		copy(out.AllowMethods, in.AllowMethods)
	}
	if in.AllowHeaders != nil {
		out.AllowHeaders = make([]string, len(in.AllowHeaders))
		copy(out.AllowHeaders, in.AllowHeaders)
	}
	if in.ExposeHeaders != nil {
		out.ExposeHeaders = make([]string, len(in.ExposeHeaders))
		copy(out.ExposeHeaders, in.ExposeHeaders)
	}
	out.AllowCredentials = in.AllowCredentials
	out.MaxAgeSeconds = in.MaxAgeSeconds
	out.StrictMode = in.StrictMode
	out.PreflightCacheSeconds = in.PreflightCacheSeconds
	return &out
}

func (in *ATOProtectionConfig) DeepCopy() *ATOProtectionConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	if in.LoginPaths != nil {
		out.LoginPaths = make([]string, len(in.LoginPaths))
		copy(out.LoginPaths, in.LoginPaths)
	}
	out.BruteForce = *in.BruteForce.DeepCopy()
	out.CredStuffing = *in.CredStuffing.DeepCopy()
	out.PasswordSpray = *in.PasswordSpray.DeepCopy()
	out.Travel = *in.Travel.DeepCopy()
	out.GeoDBPath = in.GeoDBPath
	return &out
}

func (in *BruteForceConfig) DeepCopy() *BruteForceConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Window = in.Window
	out.MaxAttemptsPerIP = in.MaxAttemptsPerIP
	out.MaxAttemptsPerEmail = in.MaxAttemptsPerEmail
	out.BlockDuration = in.BlockDuration
	return &out
}

func (in *CredentialStuffingConfig) DeepCopy() *CredentialStuffingConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.DistributedThreshold = in.DistributedThreshold
	out.Window = in.Window
	out.BlockDuration = in.BlockDuration
	return &out
}

func (in *PasswordSprayConfig) DeepCopy() *PasswordSprayConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Threshold = in.Threshold
	out.Window = in.Window
	out.BlockDuration = in.BlockDuration
	return &out
}

func (in *ImpossibleTravelConfig) DeepCopy() *ImpossibleTravelConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.MaxDistanceKm = in.MaxDistanceKm
	out.MaxTimeHours = in.MaxTimeHours
	out.BlockDuration = in.BlockDuration
	return &out
}

func (in *APISecurityConfig) DeepCopy() *APISecurityConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.JWT = *in.JWT.DeepCopy()
	out.APIKeys = *in.APIKeys.DeepCopy()
	if in.SkipPaths != nil {
		out.SkipPaths = make([]string, len(in.SkipPaths))
		copy(out.SkipPaths, in.SkipPaths)
	}
	out.HeaderName = in.HeaderName
	out.QueryParam = in.QueryParam
	return &out
}

func (in *JWTConfig) DeepCopy() *JWTConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.Issuer = in.Issuer
	out.Audience = in.Audience
	if in.Algorithms != nil {
		out.Algorithms = make([]string, len(in.Algorithms))
		copy(out.Algorithms, in.Algorithms)
	}
	out.PublicKeyFile = in.PublicKeyFile
	out.JWKSURL = in.JWKSURL
	out.ClockSkewSeconds = in.ClockSkewSeconds
	out.PublicKeyPEM = in.PublicKeyPEM
	return &out
}

func (in *APIKeysConfig) DeepCopy() *APIKeysConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.HeaderName = in.HeaderName
	out.QueryParam = in.QueryParam
	if in.Keys != nil {
		out.Keys = make([]APIKeyConfig, len(in.Keys))
		for i := range out.Keys {
			out.Keys[i] = *in.Keys[i].DeepCopy()
		}
	}
	return &out
}

func (in *APIKeyConfig) DeepCopy() *APIKeyConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Name = in.Name
	out.KeyHash = in.KeyHash
	out.KeyPrefix = in.KeyPrefix
	out.RateLimit = in.RateLimit
	if in.AllowedPaths != nil {
		out.AllowedPaths = make([]string, len(in.AllowedPaths))
		copy(out.AllowedPaths, in.AllowedPaths)
	}
	out.Enabled = in.Enabled
	return &out
}

func (in *APIValidationConfig) DeepCopy() *APIValidationConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.ValidateRequest = in.ValidateRequest
	out.ValidateResponse = in.ValidateResponse
	out.StrictMode = in.StrictMode
	out.BlockOnViolation = in.BlockOnViolation
	out.ViolationScore = in.ViolationScore
	out.CacheSize = in.CacheSize
	if in.Schemas != nil {
		out.Schemas = make([]SchemaSourceConfig, len(in.Schemas))
		copy(out.Schemas, in.Schemas)
	}
	return &out
}

func (in *SchemaSourceConfig) DeepCopy() *SchemaSourceConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Path = in.Path
	out.Type = in.Type
	out.AutoLearn = in.AutoLearn
	return &out
}

func (in *TracingConfig) DeepCopy() *TracingConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.ServiceName = in.ServiceName
	out.SamplingRate = in.SamplingRate
	out.ExporterType = in.ExporterType
	return &out
}

func (in *ComplianceConfig) DeepCopy() *ComplianceConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	if in.Frameworks != nil {
		out.Frameworks = make([]string, len(in.Frameworks))
		copy(out.Frameworks, in.Frameworks)
	}
	out.ReportDir = in.ReportDir
	out.AuditTrail = *in.AuditTrail.DeepCopy()
	out.Retention = *in.Retention.DeepCopy()
	if in.ScheduledReports != nil {
		out.ScheduledReports = make([]ScheduledReportConfig, len(in.ScheduledReports))
		for i := range out.ScheduledReports {
			out.ScheduledReports[i] = *in.ScheduledReports[i].DeepCopy()
		}
	}
	return &out
}

func (in *AuditTrailConfig) DeepCopy() *AuditTrailConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.HashAlgorithm = in.HashAlgorithm
	out.PersistPath = in.PersistPath
	return &out
}

func (in *RetentionConfig) DeepCopy() *RetentionConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.DefaultDays = in.DefaultDays
	if in.PerFramework != nil {
		out.PerFramework = make(map[string]int, len(in.PerFramework))
		for k, v := range in.PerFramework {
			out.PerFramework[k] = v
		}
	}
	out.AutoDelete = in.AutoDelete
	out.ArchivePath = in.ArchivePath
	return &out
}

func (in *ScheduledReportConfig) DeepCopy() *ScheduledReportConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.ID = in.ID
	out.Framework = in.Framework
	out.Schedule = in.Schedule
	if in.Format != nil {
		out.Format = make([]string, len(in.Format))
		copy(out.Format, in.Format)
	}
	out.TenantID = in.TenantID
	out.OutputDir = in.OutputDir
	return &out
}

func (in *CRSConfig) DeepCopy() *CRSConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.RulePath = in.RulePath
	out.ParanoiaLevel = in.ParanoiaLevel
	out.AnomalyThreshold = in.AnomalyThreshold
	if in.Exclusions != nil {
		out.Exclusions = make([]string, len(in.Exclusions))
		copy(out.Exclusions, in.Exclusions)
	}
	if in.DisabledRules != nil {
		out.DisabledRules = make([]string, len(in.DisabledRules))
		copy(out.DisabledRules, in.DisabledRules)
	}
	return &out
}

func (in *VirtualPatchConfig) DeepCopy() *VirtualPatchConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Enabled = in.Enabled
	out.AutoUpdate = in.AutoUpdate
	out.UpdateInterval = in.UpdateInterval
	out.CVEPath = in.CVEPath
	out.NVDFeedURL = in.NVDFeedURL
	out.AutoGenerateRules = in.AutoGenerateRules
	if in.BlockSeverity != nil {
		out.BlockSeverity = make([]string, len(in.BlockSeverity))
		copy(out.BlockSeverity, in.BlockSeverity)
	}
	out.NotifyOnPatch = in.NotifyOnPatch
	return &out
}

func (in *ValidationError) DeepCopy() *ValidationError {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	return &out
}

func (in *FieldError) DeepCopy() *FieldError {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	return &out
}

func (in *Node) DeepCopy() *Node {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	return &out
}

func (in *ParseError) DeepCopy() *ParseError {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	return &out
}

func (in *parser) DeepCopy() *parser {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	return &out
}
