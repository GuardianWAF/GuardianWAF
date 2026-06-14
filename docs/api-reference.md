# API Reference

GuardianWAF exposes a REST API through the dashboard server (default `:9443`). Runtime management endpoints are prefixed with `/api/v1/`; cross-tenant operator endpoints are prefixed with `/api/admin/`.

---

## Authentication

If `dashboard.api_key` is set in the configuration, `/api/v1/*` API requests must include the `X-API-Key` header:

```bash
curl -H "X-API-Key: your-secret-key" http://localhost:9443/api/v1/stats
```

Requests without a valid API key receive `401 Unauthorized`.

Query-string API keys are rejected; send credentials with `X-API-Key` or use an authenticated dashboard session cookie for browser-driven streams.

`/api/admin/*` endpoints do not accept the dashboard session cookie or `dashboard.api_key`. They require `dashboard.admin_key` in `X-API-Key` and remain inaccessible when `dashboard.admin_key` is unset.

---

## Error Format

All errors follow this structure:

```json
{
  "error": {
    "code": "bad_request",
    "message": "Missing 'value' field"
  }
}
```

Common error codes:

| HTTP Status | Code | Meaning |
|---|---|---|
| 400 | `bad_request` | Invalid request body or missing required field |
| 401 | `unauthorized` | Missing or invalid API key |
| 404 | `not_found` | Resource not found |
| 500 | `internal_error` | Server-side error |

---

## Endpoints

### GET /api/v1/stats

Get WAF runtime statistics.

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

### GET /api/v1/health

Health check endpoint.

**Response:**

```json
{
  "status": "healthy",
  "uptime": "2h15m30s"
}
```

---

### GET /api/v1/version

Get server version information.

**Response:**

```json
{
  "version": "0.1.0",
  "go_version": "go1.25",
  "name": "GuardianWAF"
}
```

---

### GET /api/v1/events

Search and filter security events with pagination.

**Query Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | int | 50 | Max events to return (max: 1000) |
| `offset` | int | 0 | Skip N events for pagination |
| `action` | string | | Filter: `blocked`, `logged`, `passed` |
| `client_ip` | string | | Filter by client IP |
| `path` | string | | Filter by path prefix |
| `min_score` | int | | Minimum threat score |
| `since` | string | | Start time (RFC 3339) |
| `until` | string | | End time (RFC 3339) |
| `sort_by` | string | | Sort field |
| `sort_order` | string | | `asc` or `desc` |

**Example:**

```bash
curl "http://localhost:9443/api/v1/events?action=blocked&limit=10&min_score=50"
```

**Response:**

```json
{
  "events": [
    {
      "request_id": "a1b2c3d4",
      "timestamp": "2026-03-17T10:30:00Z",
      "client_ip": "203.0.113.45",
      "method": "GET",
      "path": "/search",
      "action": "block",
      "score": 85,
      "findings": [
        {
          "detector": "sqli",
          "category": "sqli",
          "severity": "high",
          "score": 85,
          "description": "Boolean-based SQL injection with tautology detected",
          "location": "query"
        }
      ],
      "duration": "142µs"
    }
  ],
  "total": 87,
  "limit": 10,
  "offset": 0
}
```

---

### GET /api/v1/events/{id}

Get a single event by its request ID.

**Response:** Single event object (same structure as above).

**Error:** `404` if event not found.

---

### GET /api/v1/config

Get the current WAF configuration.

**Response:** Full configuration object.

```bash
curl http://localhost:9443/api/v1/config
```

---

### PUT /api/v1/config

Update configuration fields.

**Request:**

```bash
curl -X PUT http://localhost:9443/api/v1/config \
  -H "Content-Type: application/json" \
  -d '{"mode": "monitor"}'
```

**Response:**

```json
{
  "status": "ok",
  "message": "Configuration updated and saved"
}
```

This endpoint updates supported in-memory request-policy fields and persists through the dashboard save callback when configured. It does not recreate listeners, startup-owned background services, or WAF layer instances. Patches that change WAF layer topology or layer-instance configuration return `409 Conflict` and leave the active config unchanged. See [Runtime Reload Contract](runtime-reload.md).

---

### POST /api/v1/config/reload

Re-apply the current in-memory configuration and rebuild routing state where configured. This endpoint does not reread the YAML file from disk.

```bash
curl -X POST http://localhost:9443/api/v1/config/reload \
  -H "X-API-Key: your-secret-key"
```

**Response:**

```json
{
  "status": "ok",
  "message": "Configuration reloaded"
}
```

Use a rolling restart for listener, TLS/ACME, event store, Docker watcher, AI, alerting, tenant, MCP, tracing, compliance, SIEM, cluster, WAF layer topology/configuration, or other startup-owned service changes.

---

### GET /api/v1/ipacl

List whitelisted and blacklisted IP/CIDR entries.

**Response:**

```json
{
  "whitelist": ["10.0.0.0/8"],
  "blacklist": ["203.0.113.0/24"]
}
```

---

### POST /api/v1/ipacl

Add an IP/CIDR to the whitelist or blacklist.

**Request:**

```json
{
  "list": "blacklist",
  "ip": "203.0.113.0/24"
}
```

**Response:**

```json
{
  "status": "ok",
  "ip": "203.0.113.0/24",
  "list": "blacklist"
}
```

---

### DELETE /api/v1/ipacl

Remove an IP/CIDR from the whitelist or blacklist.

**Request:**

```json
{
  "list": "blacklist",
  "ip": "203.0.113.0/24"
}
```

**Response:**

```json
{
  "status": "ok",
  "ip": "203.0.113.0/24",
  "list": "blacklist"
}
```

---

### GET /api/v1/bans

List active temporary bans.

**Response:**

```json
{
  "bans": []
}
```

---

### POST /api/v1/bans

Add a temporary ban.

**Request:**

```json
{
  "ip": "203.0.113.45",
  "duration": "1h",
  "reason": "manual incident response"
}
```

**Response:**

```json
{
  "status": "ok",
  "ip": "203.0.113.45",
  "duration": "1h0m0s"
}
```

---

### DELETE /api/v1/bans

Remove a temporary ban.

**Request:**

```json
{
  "ip": "203.0.113.45"
}
```

---

### GET /api/v1/rules

List custom WAF rules managed by the dashboard.

**Response:**

```json
{
  "rules": []
}
```

---

### POST /api/v1/rules

Add a custom WAF rule. The rule body depends on the active rule store implementation.

**Response:**

```json
{
  "status": "ok"
}
```

---

### PUT /api/v1/rules/{id}

Update a custom WAF rule.

---

### DELETE /api/v1/rules/{id}

Delete a custom WAF rule.

---

### GET /api/v1/events/export

Export events as JSON or CSV.

**Query Parameters:** same filters as `GET /api/v1/events`, plus `format=json|csv`.

---

### GET /api/v1/sse

Open the dashboard Server-Sent Events stream. `GET /api/v1/events/stream` is also supported as a compatibility alias.

---

## Endpoint Summary

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/stats` | Runtime statistics |
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/version` | Version info |
| GET | `/api/v1/events` | List events (with filters) |
| GET | `/api/v1/events/{id}` | Get single event |
| GET | `/api/v1/config` | Get configuration |
| PUT | `/api/v1/config` | Update configuration |
| POST | `/api/v1/config/reload` | Reload configuration |
| GET | `/api/v1/ipacl` | List IP whitelist/blacklist |
| POST | `/api/v1/ipacl` | Add whitelist/blacklist entry |
| DELETE | `/api/v1/ipacl` | Remove whitelist/blacklist entry |
| GET | `/api/v1/bans` | List temporary bans |
| POST | `/api/v1/bans` | Add temporary ban |
| DELETE | `/api/v1/bans` | Remove temporary ban |
| GET | `/api/v1/rules` | List custom WAF rules |
| POST | `/api/v1/rules` | Add custom WAF rule |
| PUT | `/api/v1/rules/{id}` | Update custom WAF rule |
| DELETE | `/api/v1/rules/{id}` | Delete custom WAF rule |
| GET | `/api/v1/events/export` | Export events |
| GET | `/api/v1/sse` | Dashboard SSE stream |
| GET | `/api/v1/events/stream` | SSE compatibility alias |
