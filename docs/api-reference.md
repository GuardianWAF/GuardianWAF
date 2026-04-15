# API Reference

GuardianWAF exposes a REST API through the dashboard server (default `:9443`). All endpoints are prefixed with `/api/v1/`.

---

## Authentication

If `dashboard.api_key` is set in the configuration, all API requests must include the `X-API-Key` header:

```bash
curl -H "X-API-Key: your-secret-key" http://localhost:9443/api/v1/stats
```

Requests without a valid API key receive `401 Unauthorized`.

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
  "message": "Configuration update received",
  "updates": {
    "mode": "monitor"
  }
}
```

---

### POST /api/v1/config/reload

Trigger a configuration reload.

```bash
curl -X POST http://localhost:9443/api/v1/config/reload
```

**Response:**

```json
{
  "message": "Configuration reloaded successfully"
}
```

---

### GET /api/v1/rules/whitelist

List all whitelisted IPs.

**Response:**

```json
{
  "rules": [
    {
      "id": "1",
      "value": "10.0.0.0/8",
      "reason": "Internal network",
      "created_at": "2026-03-17T08:00:00Z"
    }
  ]
}
```

---

### POST /api/v1/rules/whitelist

Add an IP to the whitelist.

**Request:**

```json
{
  "value": "10.0.0.0/8",
  "reason": "Internal network"
}
```

**Response:** `201 Created` with the created entry including its `id`.

---

### DELETE /api/v1/rules/whitelist/{id}

Remove a whitelist entry by ID.

**Response:**

```json
{
  "message": "Removed"
}
```

---

### GET /api/v1/rules/blacklist

List all blacklisted IPs.

**Response:** Same structure as whitelist.

---

### POST /api/v1/rules/blacklist

Add an IP to the blacklist.

**Request:**

```json
{
  "value": "203.0.113.0/24",
  "reason": "Known attacker range"
}
```

**Response:** `201 Created`.

---

### DELETE /api/v1/rules/blacklist/{id}

Remove a blacklist entry by ID.

---

### GET /api/v1/rules/ratelimit

List all rate limit rules.

**Response:**

```json
{
  "rules": [
    {
      "id": "1",
      "path": "/api/login",
      "limit": 5,
      "window": "1m",
      "action": "block"
    }
  ]
}
```

---

### POST /api/v1/rules/ratelimit

Add a rate limit rule.

**Request:**

```json
{
  "path": "/api/login",
  "limit": 5,
  "window": "1m",
  "action": "block"
}
```

**Response:** `201 Created`.

---

### DELETE /api/v1/rules/ratelimit/{id}

Remove a rate limit rule by ID.

---

### GET /api/v1/rules/exclusions

List all detection exclusions.

**Response:**

```json
{
  "rules": [
    {
      "id": "1",
      "path": "/api/webhook",
      "detectors": ["sqli", "xss"],
      "reason": "Webhook receives arbitrary payloads"
    }
  ]
}
```

---

### POST /api/v1/rules/exclusions

Add a detection exclusion.

**Request:**

```json
{
  "path": "/api/webhook",
  "detectors": ["sqli", "xss"],
  "reason": "Webhook receives arbitrary payloads"
}
```

**Response:** `201 Created`.

---

### DELETE /api/v1/rules/exclusions/{id}

Remove an exclusion by ID.

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
| GET | `/api/v1/rules/whitelist` | List whitelist |
| POST | `/api/v1/rules/whitelist` | Add to whitelist |
| DELETE | `/api/v1/rules/whitelist/{id}` | Remove from whitelist |
| GET | `/api/v1/rules/blacklist` | List blacklist |
| POST | `/api/v1/rules/blacklist` | Add to blacklist |
| DELETE | `/api/v1/rules/blacklist/{id}` | Remove from blacklist |
| GET | `/api/v1/rules/ratelimit` | List rate limits |
| POST | `/api/v1/rules/ratelimit` | Add rate limit |
| DELETE | `/api/v1/rules/ratelimit/{id}` | Remove rate limit |
| GET | `/api/v1/rules/exclusions` | List exclusions |
| POST | `/api/v1/rules/exclusions` | Add exclusion |
| DELETE | `/api/v1/rules/exclusions/{id}` | Remove exclusion |
