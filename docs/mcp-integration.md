# MCP Integration

GuardianWAF includes a built-in [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that enables AI agents to monitor, query, and manage the WAF through structured tool calls.

---

## What is MCP

MCP (Model Context Protocol) is an open protocol that connects AI assistants (like Claude) to external tools and data sources. Instead of screen-scraping or manual API calls, an AI agent calls structured tools with typed parameters and receives structured responses.

GuardianWAF's MCP server turns the WAF into an AI-accessible security tool: an LLM agent can query threat data, investigate incidents, adjust rules, and test detection -- all through natural language.

---

## Enabling MCP

MCP is enabled by default in standalone mode:

```yaml
mcp:
  enabled: true
  transport: stdio
```

The MCP server supports two transports:

- **stdio** — JSON-RPC over stdin/stdout (local process, for Claude Code CLI)
- **SSE** — Server-Sent Events over HTTP (remote, for Claude Desktop, VS Code, web clients)

Both transports expose the same 15 tools.

---

## Transport: stdio (Local)

For Claude Code CLI and local AI agents:

```yaml
mcp:
  enabled: true
  transport: stdio
```

```json
// Claude Code .claude.json
{
  "mcpServers": {
    "guardianwaf": {
      "command": "guardianwaf",
      "args": ["serve", "-c", "/path/to/guardianwaf.yaml"]
    }
  }
}
```

---

## Transport: SSE (Remote)

For Claude Desktop, VS Code, or any remote MCP client. SSE runs on the dashboard port, protected by the same API key:

```yaml
mcp:
  enabled: true
  transport: stdio   # stdio still works locally; SSE is always available on dashboard port

dashboard:
  enabled: true
  listen: ":9443"
  api_key: "your-secret-key"
```

**Endpoints:**
- `GET /mcp/sse` — Establishes SSE stream (server → client events)
- `POST /mcp/message` — Receives JSON-RPC requests (client → server)

**Authentication:** `X-API-Key` header or `?api_key` query parameter (same as dashboard API).

**Claude Desktop / VS Code config:**
```json
{
  "mcpServers": {
    "guardianwaf": {
      "url": "http://localhost:9443/mcp/sse",
      "headers": {
        "X-API-Key": "your-secret-key"
      }
    }
  }
}
```

**SSE Protocol Flow:**
```
Client                          GuardianWAF
  |                                  |
  |--- GET /mcp/sse --------------->|  (opens SSE stream)
  |<-- event: endpoint              |  (returns POST URL)
  |    data: http://host/mcp/message|
  |                                  |
  |--- POST /mcp/message ---------->|  (JSON-RPC request)
  |    {"jsonrpc":"2.0","id":1,     |
  |     "method":"tools/call",...}  |
  |                                  |
  |<-- event: message               |  (JSON-RPC response via SSE)
  |    data: {"jsonrpc":"2.0",...}  |
  |                                  |
```

**curl example:**
```bash
# Open SSE stream in background
curl -N -H "X-API-Key: your-key" http://localhost:9443/mcp/sse &

# Send a tool call
curl -X POST -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  http://localhost:9443/mcp/message \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"guardianwaf_get_stats","arguments":{}}}'

# Response arrives on the SSE stream:
# event: message
# data: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{...stats...}"}]}}
```

---

## Example Prompts

Once configured, you can ask Claude natural language questions like:
- "Show me the latest blocked requests"
- "What are the top attacking IPs?"
- "Add 10.0.0.0/8 to the whitelist"
- "Test if this URL would be blocked: `/search?q=' OR 1=1 --`"
- "Switch to monitor mode"
- "What detectors are enabled?"
- "Add a rate limit: 5 requests per minute on /api/login"
- "Exclude /webhook from SQL injection detection"

---

## All 15 MCP Tools

### 1. guardianwaf_get_stats

Get WAF runtime statistics.

**Parameters:** None

**Example call:**
```json
{
  "name": "guardianwaf_get_stats",
  "arguments": {}
}
```

**Response:**
```json
{
  "total_requests": 15420,
  "blocked_requests": 87,
  "logged_requests": 234,
  "passed_requests": 15099,
  "avg_latency_us": 142
}
```

---

### 2. guardianwaf_get_events

Search and filter security events.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `limit` | integer | No | Max events to return (default: 20) |
| `offset` | integer | No | Pagination offset |
| `action` | string | No | Filter: `blocked`, `logged`, `passed` |
| `client_ip` | string | No | Filter by client IP |
| `min_score` | integer | No | Minimum threat score |
| `path` | string | No | Filter by path prefix |

**Example:**
```json
{
  "name": "guardianwaf_get_events",
  "arguments": {
    "action": "blocked",
    "limit": 5,
    "min_score": 50
  }
}
```

---

### 3. guardianwaf_add_whitelist

Add an IP or CIDR range to the whitelist.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `ip` | string | Yes | IP address or CIDR (e.g., `10.0.0.0/24`) |

**Example:**
```json
{
  "name": "guardianwaf_add_whitelist",
  "arguments": {
    "ip": "10.0.0.0/8"
  }
}
```

---

### 4. guardianwaf_remove_whitelist

Remove an IP or CIDR from the whitelist.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `ip` | string | Yes | IP or CIDR to remove |

---

### 5. guardianwaf_add_blacklist

Add an IP or CIDR range to the blacklist.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `ip` | string | Yes | IP address or CIDR (e.g., `203.0.113.0/24`) |

---

### 6. guardianwaf_remove_blacklist

Remove an IP or CIDR from the blacklist.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `ip` | string | Yes | IP or CIDR to remove |

---

### 7. guardianwaf_add_ratelimit

Add a rate limiting rule.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Unique rule identifier |
| `scope` | string | No | `ip` or `ip+path` |
| `limit` | integer | Yes | Max requests per window |
| `window` | string | Yes | Time window (e.g., `1m`, `5m`, `1h`) |
| `action` | string | No | `block` or `log` |

**Example:**
```json
{
  "name": "guardianwaf_add_ratelimit",
  "arguments": {
    "id": "api-login",
    "scope": "ip+path",
    "limit": 5,
    "window": "1m",
    "action": "block"
  }
}
```

---

### 8. guardianwaf_remove_ratelimit

Remove a rate limiting rule by ID.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Rule ID to remove |

---

### 9. guardianwaf_add_exclusion

Add a detection exclusion for a specific path.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `path` | string | Yes | Path prefix (e.g., `/api/webhook`) |
| `detectors` | array | Yes | Detector names to skip (e.g., `["sqli", "xss"]`) |
| `reason` | string | No | Reason for the exclusion |

**Example:**
```json
{
  "name": "guardianwaf_add_exclusion",
  "arguments": {
    "path": "/api/webhook",
    "detectors": ["sqli", "xss"],
    "reason": "Webhook receives arbitrary payloads"
  }
}
```

---

### 10. guardianwaf_remove_exclusion

Remove a detection exclusion by path.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `path` | string | Yes | Path prefix to remove |

---

### 11. guardianwaf_set_mode

Set the WAF operating mode.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `mode` | string | Yes | `enforce`, `monitor`, or `disabled` |

**Example:**
```json
{
  "name": "guardianwaf_set_mode",
  "arguments": {
    "mode": "monitor"
  }
}
```

---

### 12. guardianwaf_get_config

Get the current WAF configuration.

**Parameters:** None

**Response:**
```json
{
  "mode": "enforce",
  "listen": ":8088",
  "waf": {
    "ip_acl_enabled": true,
    "rate_limit_enabled": true,
    "detection_enabled": true,
    "bot_detect_enabled": true,
    "threshold_block": 50,
    "threshold_log": 25
  },
  "dashboard": {
    "enabled": true,
    "listen": ":9443"
  },
  "mcp": {
    "enabled": true,
    "transport": "stdio"
  }
}
```

---

### 13. guardianwaf_test_request

Dry-run a request against the WAF engine.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `url` | string | Yes | URL to test (e.g., `/search?q=test`) |
| `method` | string | No | HTTP method (default: `GET`) |
| `headers` | object | No | HTTP headers as key-value pairs |

**Example:**
```json
{
  "name": "guardianwaf_test_request",
  "arguments": {
    "method": "GET",
    "url": "/search?q=' OR 1=1 --"
  }
}
```

**Response:**
```json
{
  "action": "block",
  "score": 130,
  "findings": [
    {
      "detector": "sqli",
      "category": "sqli",
      "severity": "high",
      "score": 85,
      "description": "Boolean-based SQL injection with tautology detected",
      "location": "query"
    },
    {
      "detector": "sqli",
      "category": "sqli",
      "severity": "medium",
      "score": 35,
      "description": "Comment used after string literal (possible evasion)",
      "location": "query"
    }
  ],
  "duration": "142µs"
}
```

---

### 14. guardianwaf_get_top_ips

Get top IP addresses by request count.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `count` | integer | No | Number of IPs to return (default: 10) |

---

### 15. guardianwaf_get_detectors

Get the list of all detectors with their status and configuration.

**Parameters:** None

**Response:**
```json
[
  {"name": "sqli", "enabled": true, "multiplier": 1.0},
  {"name": "xss", "enabled": true, "multiplier": 1.0},
  {"name": "lfi", "enabled": true, "multiplier": 1.0},
  {"name": "cmdi", "enabled": true, "multiplier": 1.0},
  {"name": "xxe", "enabled": true, "multiplier": 1.0},
  {"name": "ssrf", "enabled": true, "multiplier": 1.0}
]
```

---

## Tool Categories

| Category | Tools |
|---|---|
| **Monitoring** | `get_stats`, `get_events`, `get_top_ips`, `get_detectors` |
| **Configuration** | `get_config`, `set_mode` |
| **IP Management** | `add_whitelist`, `remove_whitelist`, `add_blacklist`, `remove_blacklist` |
| **Rate Limiting** | `add_ratelimit`, `remove_ratelimit` |
| **Detection Tuning** | `add_exclusion`, `remove_exclusion` |
| **Testing** | `test_request` |

---

## Use Cases

**Incident response:** "Show me all blocked requests from the last hour with score above 80. Then blacklist the top attacking IP."

**False positive investigation:** "Test this URL against the WAF: `/api/search?q=SELECT brand FROM products`. What detectors triggered? Add an exclusion for the search endpoint."

**Mode switching:** "Switch to monitor mode while we deploy the new API endpoint, then switch back to enforce after testing."

**Status check:** "How many requests has the WAF processed today? What's the block rate? What's the average latency?"
