package config

import "testing"

func TestGeneratedDeepCopyNilReceivers(t *testing.T) {
	if ((*ACMEConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ACMEConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*AgentInjectionConfig)(nil)).DeepCopy() != nil {
		t.Errorf("AgentInjectionConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*AIAnalysisConfig)(nil)).DeepCopy() != nil {
		t.Errorf("AIAnalysisConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*AlertingConfig)(nil)).DeepCopy() != nil {
		t.Errorf("AlertingConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*AnalyticsConfig)(nil)).DeepCopy() != nil {
		t.Errorf("AnalyticsConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*APIKeyConfig)(nil)).DeepCopy() != nil {
		t.Errorf("APIKeyConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*APIKeysConfig)(nil)).DeepCopy() != nil {
		t.Errorf("APIKeysConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*APISecurityConfig)(nil)).DeepCopy() != nil {
		t.Errorf("APISecurityConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*APIValidationConfig)(nil)).DeepCopy() != nil {
		t.Errorf("APIValidationConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ATOProtectionConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ATOProtectionConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*AuditTrailConfig)(nil)).DeepCopy() != nil {
		t.Errorf("AuditTrailConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*AutoBanConfig)(nil)).DeepCopy() != nil {
		t.Errorf("AutoBanConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*BehaviorConfig)(nil)).DeepCopy() != nil {
		t.Errorf("BehaviorConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*BotDetectionConfig)(nil)).DeepCopy() != nil {
		t.Errorf("BotDetectionConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*BruteForceConfig)(nil)).DeepCopy() != nil {
		t.Errorf("BruteForceConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*CacheConfig)(nil)).DeepCopy() != nil {
		t.Errorf("CacheConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*CanaryConfig)(nil)).DeepCopy() != nil {
		t.Errorf("CanaryConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ChallengeConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ChallengeConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ClientSideConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ClientSideConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ClusterConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ClusterConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ClusterMembership)(nil)).DeepCopy() != nil {
		t.Errorf("ClusterMembership.DeepCopy nil receiver returned non-nil")
	}
	if ((*ClusterNodeConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ClusterNodeConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ClusterSyncConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ClusterSyncConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ComplianceConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ComplianceConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*Config)(nil)).DeepCopy() != nil {
		t.Errorf("Config.DeepCopy nil receiver returned non-nil")
	}
	if ((*CORSConfig)(nil)).DeepCopy() != nil {
		t.Errorf("CORSConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*CredentialStuffingConfig)(nil)).DeepCopy() != nil {
		t.Errorf("CredentialStuffingConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*CRSConfig)(nil)).DeepCopy() != nil {
		t.Errorf("CRSConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*CSPHeaderConfig)(nil)).DeepCopy() != nil {
		t.Errorf("CSPHeaderConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*CustomRule)(nil)).DeepCopy() != nil {
		t.Errorf("CustomRule.DeepCopy nil receiver returned non-nil")
	}
	if ((*CustomRulesConfig)(nil)).DeepCopy() != nil {
		t.Errorf("CustomRulesConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*DashboardConfig)(nil)).DeepCopy() != nil {
		t.Errorf("DashboardConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*DataMaskingConfig)(nil)).DeepCopy() != nil {
		t.Errorf("DataMaskingConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*DetectionConfig)(nil)).DeepCopy() != nil {
		t.Errorf("DetectionConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*DetectorConfig)(nil)).DeepCopy() != nil {
		t.Errorf("DetectorConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*DLPConfig)(nil)).DeepCopy() != nil {
		t.Errorf("DLPConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*DockerConfig)(nil)).DeepCopy() != nil {
		t.Errorf("DockerConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*DomainReputationConfig)(nil)).DeepCopy() != nil {
		t.Errorf("DomainReputationConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*EmailConfig)(nil)).DeepCopy() != nil {
		t.Errorf("EmailConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ErrorPagesConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ErrorPagesConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*EventsConfig)(nil)).DeepCopy() != nil {
		t.Errorf("EventsConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ExclusionConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ExclusionConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*FieldError)(nil)).DeepCopy() != nil {
		t.Errorf("FieldError.DeepCopy nil receiver returned non-nil")
	}
	if ((*GeoIPConfig)(nil)).DeepCopy() != nil {
		t.Errorf("GeoIPConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*GraphQLConfig)(nil)).DeepCopy() != nil {
		t.Errorf("GraphQLConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*GRPCConfig)(nil)).DeepCopy() != nil {
		t.Errorf("GRPCConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*GRPCRateLimit)(nil)).DeepCopy() != nil {
		t.Errorf("GRPCRateLimit.DeepCopy nil receiver returned non-nil")
	}
	if ((*HealthCheckConfig)(nil)).DeepCopy() != nil {
		t.Errorf("HealthCheckConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*HSTSConfig)(nil)).DeepCopy() != nil {
		t.Errorf("HSTSConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*HTTP3Config)(nil)).DeepCopy() != nil {
		t.Errorf("HTTP3Config.DeepCopy nil receiver returned non-nil")
	}
	if ((*ImpossibleTravelConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ImpossibleTravelConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*IPACLConfig)(nil)).DeepCopy() != nil {
		t.Errorf("IPACLConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*IPReputationConfig)(nil)).DeepCopy() != nil {
		t.Errorf("IPReputationConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*JWTConfig)(nil)).DeepCopy() != nil {
		t.Errorf("JWTConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*LogConfig)(nil)).DeepCopy() != nil {
		t.Errorf("LogConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*MagecartDetectionConfig)(nil)).DeepCopy() != nil {
		t.Errorf("MagecartDetectionConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*MCPConfig)(nil)).DeepCopy() != nil {
		t.Errorf("MCPConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*Node)(nil)).DeepCopy() != nil {
		t.Errorf("Node.DeepCopy nil receiver returned non-nil")
	}
	if ((*ParseError)(nil)).DeepCopy() != nil {
		t.Errorf("ParseError.DeepCopy nil receiver returned non-nil")
	}
	if ((*parser)(nil)).DeepCopy() != nil {
		t.Errorf("parser.DeepCopy nil receiver returned non-nil")
	}
	if ((*PasswordSprayConfig)(nil)).DeepCopy() != nil {
		t.Errorf("PasswordSprayConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*PathOverride)(nil)).DeepCopy() != nil {
		t.Errorf("PathOverride.DeepCopy nil receiver returned non-nil")
	}
	if ((*RateLimitConfig)(nil)).DeepCopy() != nil {
		t.Errorf("RateLimitConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*RateLimitRule)(nil)).DeepCopy() != nil {
		t.Errorf("RateLimitRule.DeepCopy nil receiver returned non-nil")
	}
	if ((*RemediationConfig)(nil)).DeepCopy() != nil {
		t.Errorf("RemediationConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ReplayConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ReplayConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ReplayEngineConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ReplayEngineConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ResourceQuotaConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ResourceQuotaConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ResponseConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ResponseConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*RetentionConfig)(nil)).DeepCopy() != nil {
		t.Errorf("RetentionConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*RouteConfig)(nil)).DeepCopy() != nil {
		t.Errorf("RouteConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*RuleCondition)(nil)).DeepCopy() != nil {
		t.Errorf("RuleCondition.DeepCopy nil receiver returned non-nil")
	}
	if ((*SanitizerConfig)(nil)).DeepCopy() != nil {
		t.Errorf("SanitizerConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ScheduledReportConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ScheduledReportConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*SchemaSourceConfig)(nil)).DeepCopy() != nil {
		t.Errorf("SchemaSourceConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*SecurityHeadersConfig)(nil)).DeepCopy() != nil {
		t.Errorf("SecurityHeadersConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*SIEMConfig)(nil)).DeepCopy() != nil {
		t.Errorf("SIEMConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*TargetConfig)(nil)).DeepCopy() != nil {
		t.Errorf("TargetConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*TenantConfig)(nil)).DeepCopy() != nil {
		t.Errorf("TenantConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*TenantDefinition)(nil)).DeepCopy() != nil {
		t.Errorf("TenantDefinition.DeepCopy nil receiver returned non-nil")
	}
	if ((*ThreatFeedConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ThreatFeedConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ThreatIntelConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ThreatIntelConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ThresholdConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ThresholdConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*TLSConfig)(nil)).DeepCopy() != nil {
		t.Errorf("TLSConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*TLSFingerprintConfig)(nil)).DeepCopy() != nil {
		t.Errorf("TLSFingerprintConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*TracingConfig)(nil)).DeepCopy() != nil {
		t.Errorf("TracingConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*UAConfig)(nil)).DeepCopy() != nil {
		t.Errorf("UAConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*UpstreamConfig)(nil)).DeepCopy() != nil {
		t.Errorf("UpstreamConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ValidationError)(nil)).DeepCopy() != nil {
		t.Errorf("ValidationError.DeepCopy nil receiver returned non-nil")
	}
	if ((*VHostTLSConfig)(nil)).DeepCopy() != nil {
		t.Errorf("VHostTLSConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*VirtualHostConfig)(nil)).DeepCopy() != nil {
		t.Errorf("VirtualHostConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*VirtualPatchConfig)(nil)).DeepCopy() != nil {
		t.Errorf("VirtualPatchConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*WAFConfig)(nil)).DeepCopy() != nil {
		t.Errorf("WAFConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*WebhookConfig)(nil)).DeepCopy() != nil {
		t.Errorf("WebhookConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*WebSocketConfig)(nil)).DeepCopy() != nil {
		t.Errorf("WebSocketConfig.DeepCopy nil receiver returned non-nil")
	}
	if ((*ZeroTrustConfig)(nil)).DeepCopy() != nil {
		t.Errorf("ZeroTrustConfig.DeepCopy nil receiver returned non-nil")
	}
}
