# GuardianWAF API Examples

Complete examples for interacting with GuardianWAF's REST API and MCP server.

## Table of Contents

- [REST API Examples](#rest-api-examples)
  - [cURL](#curl)
  - [Go](#go)
  - [Python](#python)
  - [JavaScript/Node.js](#javascriptnodejs)
- [MCP Server Examples](#mcp-server-examples)
- [Authentication](#authentication)

---

## REST API Examples

### Base URL

```
http://localhost:9443/api/v1
```

### Authentication

```bash
# Dashboard API Key header
curl -H "X-API-Key: your-api-key" http://localhost:9443/api/v1/stats

# Or query parameter
curl "http://localhost:9443/api/v1/stats?api_key=your-api-key"
```

---

## cURL

### Get Statistics

```bash
# Basic stats
curl -s http://localhost:9443/api/v1/stats | jq

# Full stats with API key
curl -s -H "X-API-Key: secret123" \
  http://localhost:9443/api/v1/stats | jq
```

**Response:**
```json
{
  "requests_total": 15234,
  "requests_blocked": 45,
  "requests_challenged": 123,
  "avg_score": 12.5,
  "top_ips": ["192.168.1.1", "10.0.0.5"],
  "active_connections": 23
}
```

### Get Events

```bash
# Recent events (last 100)
curl -s http://localhost:9443/api/v1/events | jq

# Filtered events
curl -s "http://localhost:9443/api/v1/events?action=block&limit=10" | jq

# Events with score threshold
curl -s "http://localhost:9443/api/v1/events?min_score=50&since=1h" | jq
```

### IP ACL Management

```bash
# Add to whitelist
curl -X POST http://localhost:9443/api/v1/acl/whitelist \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.0/24", "comment": "Office network"}'

# Add to blacklist
curl -X POST http://localhost:9443/api/v1/acl/blacklist \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.0.0.99", "comment": "Attacker"}'

# Remove from whitelist
curl -X DELETE http://localhost:9443/api/v1/acl/whitelist/192.168.1.0/24

# List all ACLs
curl -s http://localhost:9443/api/v1/acl | jq
```

### Rate Limit Management

```bash
# Add rate limit
curl -X POST http://localhost:9443/api/v1/ratelimits \
  -H "Content-Type: application/json" \
  -d '{
    "id": "api-limit",
    "path": "/api/*",
    "requests_per_minute": 100,
    "burst": 10
  }'

# Remove rate limit
curl -X DELETE http://localhost:9443/api/v1/ratelimits/api-limit

# List rate limits
curl -s http://localhost:9443/api/v1/ratelimits | jq
```

### Webhook Management

```bash
# Add webhook
curl -X POST http://localhost:9443/api/v1/alerting/webhooks \
  -H "Content-Type: application/json" \
  -d '{
    "name": "slack-security",
    "url": "https://hooks.slack.com/services/T00/B00/XXX",
    "events": ["block"],
    "min_score": 50
  }'

# Test webhook
curl -X POST http://localhost:9443/api/v1/alerting/webhooks/slack-security/test

# Remove webhook
curl -X DELETE http://localhost:9443/api/v1/alerting/webhooks/slack-security
```

### Export Events

```bash
# Export as JSON
curl -s "http://localhost:9443/api/v1/events/export?format=json&since=24h" \
  -o events.json

# Export as CSV
curl -s "http://localhost:9443/api/v1/events/export?format=csv&action=block" \
  -o events.csv
```

---

## Go

### Client Initialization

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type GuardianWAFClient struct {
    BaseURL string
    APIKey  string
    Client  *http.Client
}

func NewClient(baseURL, apiKey string) *GuardianWAFClient {
    return &GuardianWAFClient{
        BaseURL: baseURL,
        APIKey:  apiKey,
        Client: &http.Client{
            Timeout: 10 * time.Second,
        },
    }
}

func (c *GuardianWAFClient) request(method, path string, body interface{}) (*http.Response, error) {
    var bodyReader *bytes.Reader
    if body != nil {
        jsonBody, err := json.Marshal(body)
        if err != nil {
            return nil, err
        }
        bodyReader = bytes.NewReader(jsonBody)
    } else {
        bodyReader = bytes.NewReader([]byte{})
    }

    req, err := http.NewRequest(method, c.BaseURL+path, bodyReader)
    if err != nil {
        return nil, err
    }

    req.Header.Set("X-API-Key", c.APIKey)
    req.Header.Set("Content-Type", "application/json")

    return c.Client.Do(req)
}
```

### Statistics

```go
func (c *GuardianWAFClient) GetStats() (*Stats, error) {
    resp, err := c.request("GET", "/stats", nil)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
    }

    var stats Stats
    if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
        return nil, err
    }
    return &stats, nil
}

type Stats struct {
    RequestsTotal      int64   `json:"requests_total"`
    RequestsBlocked    int64   `json:"requests_blocked"`
    RequestsChallenged int64   `json:"requests_challenged"`
    AvgScore           float64 `json:"avg_score"`
    TopIPs             []string `json:"top_ips"`
}

// Usage
func main() {
    client := NewClient("http://localhost:9443/api/v1", "secret123")
    
    stats, err := client.GetStats()
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Blocked: %d, Challenged: %d\n", 
        stats.RequestsBlocked, stats.RequestsChallenged)
}
```

### IP ACL Management

```go
func (c *GuardianWAFClient) AddToWhitelist(ip, comment string) error {
    body := map[string]string{
        "ip":      ip,
        "comment": comment,
    }
    
    resp, err := c.request("POST", "/acl/whitelist", body)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusCreated {
        return fmt.Errorf("failed to add: %d", resp.StatusCode)
    }
    return nil
}

func (c *GuardianWAFClient) RemoveFromWhitelist(ip string) error {
    resp, err := c.request("DELETE", "/acl/whitelist/"+ip, nil)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    return nil
}

func (c *GuardianWAFClient) AddToBlacklist(ip, comment string) error {
    body := map[string]string{
        "ip":      ip,
        "comment": comment,
    }
    
    resp, err := c.request("POST", "/acl/blacklist", body)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    return nil
}
```

### Event Streaming

```go
func (c *GuardianWAFClient) StreamEvents(ctx context.Context) (<-chan Event, error) {
    events := make(chan Event)
    
    go func() {
        defer close(events)
        
        req, err := http.NewRequest("GET", c.BaseURL+"/events/stream", nil)
        if err != nil {
            return
        }
        req.Header.Set("X-API-Key", c.APIKey)
        
        resp, err := c.Client.Do(req)
        if err != nil {
            return
        }
        defer resp.Body.Close()
        
        decoder := json.NewDecoder(resp.Body)
        for {
            select {
            case <-ctx.Done():
                return
            default:
                var event Event
                if err := decoder.Decode(&event); err != nil {
                    return
                }
                events <- event
            }
        }
    }()
    
    return events, nil
}

type Event struct {
    ID        string    `json:"id"`
    Timestamp time.Time `json:"timestamp"`
    ClientIP  string    `json:"client_ip"`
    Method    string    `json:"method"`
    Path      string    `json:"path"`
    Action    string    `json:"action"`
    Score     int       `json:"score"`
}

// Usage
func main() {
    client := NewClient("http://localhost:9443/api/v1", "secret123")
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    events, _ := client.StreamEvents(ctx)
    for event := range events {
        fmt.Printf("[%s] %s %s -> %s\n", 
            event.Timestamp, event.Method, event.Path, event.Action)
    }
}
```

---

## Python

### Setup

```bash
pip install requests
```

### Basic Client

```python
import requests
from typing import Optional, Dict, Any

class GuardianWAFClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        })
    
    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}{path}"
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response
    
    def get_stats(self) -> Dict[str, Any]:
        """Get WAF statistics"""
        resp = self._request('GET', '/stats')
        return resp.json()
    
    def get_events(self, limit: int = 100, action: Optional[str] = None) -> list:
        """Get recent events"""
        params = {'limit': limit}
        if action:
            params['action'] = action
        resp = self._request('GET', '/events', params=params)
        return resp.json()
    
    def add_to_whitelist(self, ip: str, comment: str = "") -> bool:
        """Add IP to whitelist"""
        resp = self._request('POST', '/acl/whitelist', 
                           json={'ip': ip, 'comment': comment})
        return resp.status_code == 201
    
    def add_to_blacklist(self, ip: str, comment: str = "") -> bool:
        """Add IP to blacklist"""
        resp = self._request('POST', '/acl/blacklist',
                           json={'ip': ip, 'comment': comment})
        return resp.status_code == 201
    
    def remove_from_whitelist(self, ip: str) -> bool:
        """Remove IP from whitelist"""
        resp = self._request('DELETE', f'/acl/whitelist/{ip}')
        return resp.status_code == 204
    
    def add_rate_limit(self, id: str, path: str, rpm: int, burst: int = 10) -> bool:
        """Add rate limit rule"""
        resp = self._request('POST', '/ratelimits',
                           json={
                               'id': id,
                               'path': path,
                               'requests_per_minute': rpm,
                               'burst': burst
                           })
        return resp.status_code == 201
    
    def export_events(self, format: str = 'json', since: str = '24h') -> str:
        """Export events to file"""
        resp = self._request('GET', '/events/export',
                           params={'format': format, 'since': since})
        return resp.text

# Usage
client = GuardianWAFClient('http://localhost:9443/api/v1', 'secret123')

# Get stats
stats = client.get_stats()
print(f"Total requests: {stats['requests_total']}")
print(f"Blocked: {stats['requests_blocked']}")

# Get blocked events
events = client.get_events(action='block', limit=10)
for event in events:
    print(f"{event['client_ip']} - {event['path']} - Score: {event['score']}")

# Add to whitelist
client.add_to_whitelist('192.168.1.0/24', 'Office network')

# Add rate limit
client.add_rate_limit('api-limit', '/api/*', 100, 10)
```

### Async Client

```python
import aiohttp
import asyncio

class GuardianWAFAsyncClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        }
    
    async def get_stats(self) -> dict:
        async with aiohttp.ClientSession(headers=self.headers) as session:
            async with session.get(f"{self.base_url}/stats") as resp:
                return await resp.json()
    
    async def add_to_blacklist(self, ip: str) -> bool:
        async with aiohttp.ClientSession(headers=self.headers) as session:
            async with session.post(f"{self.base_url}/acl/blacklist",
                                   json={'ip': ip}) as resp:
                return resp.status == 201

# Usage
async def main():
    client = GuardianWAFAsyncClient('http://localhost:9443/api/v1', 'secret123')
    stats = await client.get_stats()
    print(stats)

asyncio.run(main())
```

---

## JavaScript/Node.js

### Setup

```bash
npm install axios
```

### Client

```javascript
const axios = require('axios');

class GuardianWAFClient {
    constructor(baseURL, apiKey) {
        this.client = axios.create({
            baseURL: baseURL,
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json'
            },
            timeout: 10000
        });
    }

    async getStats() {
        const { data } = await this.client.get('/stats');
        return data;
    }

    async getEvents(options = {}) {
        const { limit = 100, action, minScore } = options;
        const params = { limit };
        if (action) params.action = action;
        if (minScore) params.min_score = minScore;
        
        const { data } = await this.client.get('/events', { params });
        return data;
    }

    async addToWhitelist(ip, comment = '') {
        await this.client.post('/acl/whitelist', { ip, comment });
        return true;
    }

    async addToBlacklist(ip, comment = '') {
        await this.client.post('/acl/blacklist', { ip, comment });
        return true;
    }

    async removeFromWhitelist(ip) {
        await this.client.delete(`/acl/whitelist/${ip}`);
        return true;
    }

    async addRateLimit(id, path, requestsPerMinute, burst = 10) {
        await this.client.post('/ratelimits', {
            id,
            path,
            requests_per_minute: requestsPerMinute,
            burst
        });
        return true;
    }

    async addWebhook(name, url, events = ['block'], minScore = 50) {
        await this.client.post('/alerting/webhooks', {
            name,
            url,
            events,
            min_score: minScore
        });
        return true;
    }

    async exportEvents(format = 'json', since = '24h') {
        const { data } = await this.client.get('/events/export', {
            params: { format, since },
            responseType: format === 'csv' ? 'text' : 'json'
        });
        return data;
    }
}

// Usage
const client = new GuardianWAFClient(
    'http://localhost:9443/api/v1',
    'secret123'
);

async function main() {
    try {
        // Get stats
        const stats = await client.getStats();
        console.log('Stats:', stats);

        // Get blocked events
        const events = await client.getEvents({ action: 'block', limit: 5 });
        console.log('Blocked events:', events);

        // Add to whitelist
        await client.addToWhitelist('192.168.1.0/24', 'Office network');
        console.log('Added to whitelist');

    } catch (error) {
        console.error('Error:', error.message);
    }
}

main();
```

---

## MCP Server Examples

### Using with Claude Code

```bash
# In Claude Code, add to your settings
{
  "mcpServers": {
    "guardianwaf": {
      "command": "guardianwaf",
      "args": ["mcp"],
      "env": {
        "GWAF_MCP_API_KEY": "your-api-key"
      }
    }
  }
}
```

### Tool Examples

```json
// guardianwaf_get_stats
{}

// guardianwaf_get_top_ips
{ "count": 10 }

// guardianwaf_add_blacklist
{ "ip": "192.0.2.1", "comment": "Attacker" }

// guardianwaf_test_request
{
  "method": "GET",
  "url": "https://example.com/api/users?id=1 OR 1=1"
}

// guardianwaf_set_mode
{ "mode": "enforce" }
```

### Custom MCP Client (Go)

```go
package main

import (
    "encoding/json"
    "fmt"
    "os/exec"
)

type MCPClient struct {
    cmd *exec.Cmd
}

func NewMCPClient() *MCPClient {
    return &MCPClient{
        cmd: exec.Command("guardianwaf", "mcp"),
    }
}

func (c *MCPClient) Call(tool string, params map[string]interface{}) (map[string]interface{}, error) {
    // Implement MCP protocol
    // See MCP specification for details
    return nil, nil
}
```

---

## Rate Limiting

All APIs have built-in rate limiting. Default limits:

| Endpoint | Rate Limit |
|----------|------------|
| `/stats` | 100/min |
| `/events` | 60/min |
| `/acl/*` | 30/min |
| `/ratelimits` | 30/min |

If rate limited, you'll receive:
```json
{
  "error": "rate limit exceeded",
  "retry_after": 60
}
```

---

## Error Handling

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 204 | No Content (deleted) |
| 400 | Bad Request |
| 401 | Unauthorized (invalid API key) |
| 404 | Not Found |
| 429 | Rate Limited |
| 500 | Internal Server Error |

### Error Response Format

```json
{
  "error": "error message",
  "code": "ERROR_CODE",
  "details": {}
}
```

---

## WebSocket Events (SSE)

Real-time event streaming via Server-Sent Events:

```javascript
const eventSource = new EventSource(
    'http://localhost:9443/api/v1/events/stream?api_key=secret123'
);

eventSource.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('New event:', data);
};

eventSource.onerror = (error) => {
    console.error('SSE error:', error);
};
```

---

*For complete API reference, see [API Reference](api-reference.md)*
