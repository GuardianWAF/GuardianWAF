package mcp

// NewFeatureTools returns MCP tool definitions for the 6 new features.
func NewFeatureTools() []ToolDefinition {
	return []ToolDefinition{
		// CRS Tools
		{
			Name:        "guardianwaf_get_crs_rules",
			Description: "Get all OWASP CRS rules with their status, severity, and current configuration",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"phase": map[string]any{
						"type":        "integer",
						"description": "Filter by rule phase (1=request headers, 2=request body)",
						"enum":        []int{1, 2, 3, 4, 5},
					},
					"severity": map[string]any{
						"type":        "string",
						"description": "Filter by severity level",
						"enum":        []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NOTICE"},
					},
				},
			},
		},
		{
			Name:        "guardianwaf_enable_crs_rule",
			Description: "Enable or disable a specific CRS rule by ID",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"rule_id": map[string]any{
						"type":        "string",
						"description": "CRS rule ID to enable/disable (e.g., '942100')",
					},
					"enabled": map[string]any{
						"type":        "boolean",
						"description": "true to enable, false to disable",
					},
				},
				"required": []string{"rule_id", "enabled"},
			},
		},
		{
			Name:        "guardianwaf_set_paranoia_level",
			Description: "Set the CRS paranoia level (1=low, 2=medium, 3=high, 4=very high). Higher levels enable more rules but may cause false positives",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"level": map[string]any{
						"type":        "integer",
						"description": "Paranoia level from 1 to 4",
						"minimum":     1,
						"maximum":     4,
					},
				},
				"required": []string{"level"},
			},
		},
		{
			Name:        "guardianwaf_add_crs_exclusion",
			Description: "Add a CRS rule exclusion to skip specific rules for certain paths or parameters",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"rule_id": map[string]any{
						"type":        "string",
						"description": "Rule ID to exclude (e.g., '942100')",
					},
					"path": map[string]any{
						"type":        "string",
						"description": "Path prefix to apply exclusion (optional, default: all paths)",
					},
					"parameter": map[string]any{
						"type":        "string",
						"description": "Parameter name to exclude (optional)",
					},
					"reason": map[string]any{
						"type":        "string",
						"description": "Reason for the exclusion",
					},
				},
				"required": []string{"rule_id"},
			},
		},

		// Virtual Patch Tools
		{
			Name:        "guardianwaf_get_virtual_patches",
			Description: "Get all virtual patches (CVE-based rules) with their status and hit statistics",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"severity": map[string]any{
						"type":        "string",
						"description": "Filter by severity",
						"enum":        []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"},
					},
					"active_only": map[string]any{
						"type":        "boolean",
						"description": "Only return active patches",
					},
				},
			},
		},
		{
			Name:        "guardianwaf_enable_virtual_patch",
			Description: "Enable or disable a virtual patch by ID",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"patch_id": map[string]any{
						"type":        "string",
						"description": "Patch ID (e.g., 'VP-LOG4SHELL-001')",
					},
					"enabled": map[string]any{
						"type":        "boolean",
						"description": "true to enable, false to disable",
					},
				},
				"required": []string{"patch_id", "enabled"},
			},
		},
		{
			Name:        "guardianwaf_add_custom_patch",
			Description: "Add a custom virtual patch for zero-day protection",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "Unique patch ID",
					},
					"name": map[string]any{
						"type":        "string",
						"description": "Human-readable name",
					},
					"description": map[string]any{
						"type":        "string",
						"description": "Description of the vulnerability",
					},
					"cve_id": map[string]any{
						"type":        "string",
						"description": "Associated CVE ID (optional)",
					},
					"pattern": map[string]any{
						"type":        "string",
						"description": "Pattern to match (regex or literal)",
					},
					"pattern_type": map[string]any{
						"type":        "string",
						"description": "Type of pattern matching",
						"enum":        []string{"regex", "contains", "exact", "starts_with", "ends_with"},
					},
					"target": map[string]any{
						"type":        "string",
						"description": "Where to search for pattern",
						"enum":        []string{"path", "query", "header", "body", "user_agent"},
					},
					"action": map[string]any{
						"type":        "string",
						"description": "Action when pattern matches",
						"enum":        []string{"block", "log", "challenge"},
					},
					"severity": map[string]any{
						"type":        "string",
						"description": "Severity level",
						"enum":        []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"},
					},
					"score": map[string]any{
						"type":        "integer",
						"description": "Threat score (0-100)",
						"minimum":     0,
						"maximum":     100,
					},
				},
				"required": []string{"id", "name", "pattern", "pattern_type", "target", "action"},
			},
		},
		{
			Name:        "guardianwaf_update_cve_database",
			Description: "Manually trigger CVE database update from NVD (National Vulnerability Database)",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},

		// API Validation Tools
		{
			Name:        "guardianwaf_get_api_schemas",
			Description: "Get all loaded OpenAPI schemas and their validation status",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "guardianwaf_upload_api_schema",
			Description: "Upload and load an OpenAPI schema for request validation (JSON or YAML format)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{
						"type":        "string",
						"description": "Schema name/identifier",
					},
					"content": map[string]any{
						"type":        "string",
						"description": "Schema content (JSON or YAML)",
					},
					"format": map[string]any{
						"type":        "string",
						"description": "Schema format",
						"enum":        []string{"json", "yaml"},
					},
					"strict_mode": map[string]any{
						"type":        "boolean",
						"description": "Reject requests with unknown fields",
					},
				},
				"required": []string{"name", "content", "format"},
			},
		},
		{
			Name:        "guardianwaf_remove_api_schema",
			Description: "Remove an uploaded OpenAPI schema",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{
						"type":        "string",
						"description": "Schema name to remove",
					},
				},
				"required": []string{"name"},
			},
		},
		{
			Name:        "guardianwaf_set_api_validation_mode",
			Description: "Configure API validation mode (strict mode, request/response validation)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"validate_request": map[string]any{
						"type":        "boolean",
						"description": "Enable request validation",
					},
					"validate_response": map[string]any{
						"type":        "boolean",
						"description": "Enable response validation",
					},
					"strict_mode": map[string]any{
						"type":        "boolean",
						"description": "Reject unknown fields and endpoints",
					},
					"block_on_violation": map[string]any{
						"type":        "boolean",
						"description": "Block requests that violate schema",
					},
				},
			},
		},
		{
			Name:        "guardianwaf_test_api_schema",
			Description: "Test a request against loaded API schemas without blocking",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"method": map[string]any{
						"type":        "string",
						"description": "HTTP method",
					},
					"path": map[string]any{
						"type":        "string",
						"description": "Request path",
					},
					"body": map[string]any{
						"type":        "string",
						"description": "Request body (JSON)",
					},
				},
				"required": []string{"method", "path"},
			},
		},

		// Client-Side Protection Tools
		{
			Name:        "guardianwaf_get_clientside_stats",
			Description: "Get client-side protection statistics (Magecart detection, CSP enforcement, script injections)",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "guardianwaf_set_clientside_mode",
			Description: "Set client-side protection mode (monitor, block, inject)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"mode": map[string]any{
						"type":        "string",
						"description": "Protection mode",
						"enum":        []string{"monitor", "block", "inject"},
					},
					"magecart_detection": map[string]any{
						"type":        "boolean",
						"description": "Enable Magecart/skimming detection",
					},
					"agent_injection": map[string]any{
						"type":        "boolean",
						"description": "Enable security agent injection",
					},
					"csp_enabled": map[string]any{
						"type":        "boolean",
						"description": "Enable Content Security Policy headers",
					},
				},
				"required": []string{"mode"},
			},
		},
		{
			Name:        "guardianwaf_add_skimming_domain",
			Description: "Add a known skimming domain to the block list",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"domain": map[string]any{
						"type":        "string",
						"description": "Domain to block (e.g., 'evil-skimmer.com')",
					},
				},
				"required": []string{"domain"},
			},
		},
		{
			Name:        "guardianwaf_get_csp_report",
			Description: "Get CSP violation reports",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{
						"type":        "integer",
						"description": "Maximum number of reports to return",
					},
				},
			},
		},

		// Advanced DLP Tools
		{
			Name:        "guardianwaf_get_dlp_alerts",
			Description: "Get Data Loss Prevention alerts (credit cards, SSN, API keys detected in requests)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{
						"type":        "integer",
						"description": "Maximum number of alerts to return",
					},
					"pattern_type": map[string]any{
						"type":        "string",
						"description": "Filter by pattern type",
						"enum":        []string{"credit_card", "ssn", "iban", "email", "api_key", "custom"},
					},
				},
			},
		},
		{
			Name:        "guardianwaf_add_dlp_pattern",
			Description: "Add a custom DLP pattern for detecting sensitive data",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "Unique pattern ID",
					},
					"name": map[string]any{
						"type":        "string",
						"description": "Human-readable name",
					},
					"pattern": map[string]any{
						"type":        "string",
						"description": "Regex pattern",
					},
					"description": map[string]any{
						"type":        "string",
						"description": "What this pattern detects",
					},
					"action": map[string]any{
						"type":        "string",
						"description": "Action when detected",
						"enum":        []string{"block", "mask", "log"},
					},
					"score": map[string]any{
						"type":        "integer",
						"description": "Threat score (0-100)",
						"minimum":     0,
						"maximum":     100,
					},
				},
				"required": []string{"id", "name", "pattern", "action"},
			},
		},
		{
			Name:        "guardianwaf_remove_dlp_pattern",
			Description: "Remove a custom DLP pattern",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "Pattern ID to remove",
					},
				},
				"required": []string{"id"},
			},
		},
		{
			Name:        "guardianwaf_test_dlp_pattern",
			Description: "Test a DLP pattern against sample data",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pattern": map[string]any{
						"type":        "string",
						"description": "Regex pattern to test",
					},
					"test_data": map[string]any{
						"type":        "string",
						"description": "Sample data to test against",
					},
				},
				"required": []string{"pattern", "test_data"},
			},
		},

		// HTTP/3 Tools
		{
			Name:        "guardianwaf_get_http3_status",
			Description: "Get HTTP/3 and QUIC server status and statistics",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "guardianwaf_set_http3_config",
			Description: "Configure HTTP/3 settings (requires rebuild with -tags http3 to enable)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"enabled": map[string]any{
						"type":        "boolean",
						"description": "Enable HTTP/3 support",
					},
					"enable_0rtt": map[string]any{
						"type":        "boolean",
						"description": "Enable 0-RTT handshake",
					},
					"advertise_alt_svc": map[string]any{
						"type":        "boolean",
						"description": "Advertise HTTP/3 via Alt-Svc header",
					},
				},
			},
		},
	}
}
