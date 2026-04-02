package mcp

// ToolDefinition describes an MCP tool with its name, description, and input schema.
type ToolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// AllTools returns all GuardianWAF MCP tool definitions.
func AllTools() []ToolDefinition {
	return []ToolDefinition{
		{
			Name:        "guardianwaf_get_stats",
			Description: "Get WAF runtime statistics including total requests, blocked requests, passed requests, and average latency",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "guardianwaf_get_events",
			Description: "Search and filter WAF security events with pagination, time range, action filter, and IP filter",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{
						"type":        "integer",
						"description": "Maximum number of events to return (default: 20)",
					},
					"offset": map[string]any{
						"type":        "integer",
						"description": "Number of events to skip for pagination",
					},
					"action": map[string]any{
						"type":        "string",
						"description": "Filter by action: blocked, logged, passed",
						"enum":        []string{"blocked", "logged", "passed"},
					},
					"client_ip": map[string]any{
						"type":        "string",
						"description": "Filter by client IP address",
					},
					"min_score": map[string]any{
						"type":        "integer",
						"description": "Minimum threat score to include",
					},
					"path": map[string]any{
						"type":        "string",
						"description": "Filter by path prefix",
					},
				},
			},
		},
		{
			Name:        "guardianwaf_add_whitelist",
			Description: "Add an IP address or CIDR range to the WAF whitelist (requests from whitelisted IPs bypass all checks)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"ip": map[string]any{
						"type":        "string",
						"description": "IP address or CIDR range to whitelist (e.g., '10.0.0.1' or '10.0.0.0/24')",
					},
				},
				"required": []string{"ip"},
			},
		},
		{
			Name:        "guardianwaf_remove_whitelist",
			Description: "Remove an IP address or CIDR range from the WAF whitelist",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"ip": map[string]any{
						"type":        "string",
						"description": "IP address or CIDR range to remove from whitelist",
					},
				},
				"required": []string{"ip"},
			},
		},
		{
			Name:        "guardianwaf_add_blacklist",
			Description: "Add an IP address or CIDR range to the WAF blacklist (requests from blacklisted IPs are blocked)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"ip": map[string]any{
						"type":        "string",
						"description": "IP address or CIDR range to blacklist (e.g., '192.168.1.100' or '192.168.0.0/16')",
					},
				},
				"required": []string{"ip"},
			},
		},
		{
			Name:        "guardianwaf_remove_blacklist",
			Description: "Remove an IP address or CIDR range from the WAF blacklist",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"ip": map[string]any{
						"type":        "string",
						"description": "IP address or CIDR range to remove from blacklist",
					},
				},
				"required": []string{"ip"},
			},
		},
		{
			Name:        "guardianwaf_add_ratelimit",
			Description: "Add a new rate limiting rule to the WAF",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "Unique identifier for the rate limit rule",
					},
					"scope": map[string]any{
						"type":        "string",
						"description": "Rate limit scope: ip or ip+path",
						"enum":        []string{"ip", "ip+path"},
					},
					"limit": map[string]any{
						"type":        "integer",
						"description": "Maximum requests per window",
					},
					"window": map[string]any{
						"type":        "string",
						"description": "Time window (e.g., '1m', '5m', '1h')",
					},
					"action": map[string]any{
						"type":        "string",
						"description": "Action when limit is exceeded: block or log",
						"enum":        []string{"block", "log"},
					},
				},
				"required": []string{"id", "limit", "window"},
			},
		},
		{
			Name:        "guardianwaf_remove_ratelimit",
			Description: "Remove a rate limiting rule by its ID",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "ID of the rate limit rule to remove",
					},
				},
				"required": []string{"id"},
			},
		},
		{
			Name:        "guardianwaf_add_exclusion",
			Description: "Add a detection exclusion for a specific path (skip certain detectors for paths like webhooks or APIs)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Path prefix to exclude (e.g., '/api/webhook')",
					},
					"detectors": map[string]any{
						"type":        "array",
						"description": "Detector names to skip (e.g., ['sqli', 'xss'])",
						"items": map[string]any{
							"type": "string",
						},
					},
					"reason": map[string]any{
						"type":        "string",
						"description": "Reason for the exclusion",
					},
				},
				"required": []string{"path", "detectors"},
			},
		},
		{
			Name:        "guardianwaf_remove_exclusion",
			Description: "Remove a detection exclusion by its path prefix",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Path prefix of the exclusion to remove",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "guardianwaf_set_mode",
			Description: "Set the WAF operating mode (enforce: block threats, monitor: log only, disabled: pass all traffic)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"mode": map[string]any{
						"type":        "string",
						"description": "WAF mode: enforce, monitor, or disabled",
						"enum":        []string{"enforce", "monitor", "disabled"},
					},
				},
				"required": []string{"mode"},
			},
		},
		{
			Name:        "guardianwaf_get_config",
			Description: "Get the current WAF configuration including all layers, thresholds, and settings",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "guardianwaf_test_request",
			Description: "Test a request against the WAF engine without actually sending it (dry-run). Returns the score, action, and any findings",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"method": map[string]any{
						"type":        "string",
						"description": "HTTP method (default: GET)",
					},
					"url": map[string]any{
						"type":        "string",
						"description": "URL to test (e.g., '/search?q=test')",
					},
					"headers": map[string]any{
						"type":        "object",
						"description": "HTTP headers as key-value pairs",
					},
				},
				"required": []string{"url"},
			},
		},
		{
			Name:        "guardianwaf_get_top_ips",
			Description: "Get the top IP addresses by request count or blocked count",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"count": map[string]any{
						"type":        "integer",
						"description": "Number of top IPs to return (default: 10)",
					},
				},
			},
		},
		{
			Name:        "guardianwaf_get_detectors",
			Description: "Get the list of all active detectors with their current configuration, enabled status, and multiplier",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
	}
}
