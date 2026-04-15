# Playwright E2E Tests

Browser-based end-to-end tests for the GuardianWAF dashboard using Playwright.

## Prerequisites

- Node.js 20+
- Playwright browsers installed: `npx playwright install`
- A running GuardianWAF server on port 9443

## Setup

```bash
# Install dependencies
npm install -D @playwright/test

# Install browsers
npx playwright install chromium firefox webkit

# Set environment variables
export E2E_BASE_URL=http://localhost:9443
export E2E_API_KEY=your-api-key
```

## Running Tests

```bash
# Run all tests
npx playwright test

# Run with UI (headed mode)
npx playwright test --headed

# Run specific test file
npx playwright test 01-login.spec.ts

# Run in debug mode
npx playwright test --debug

# Generate report
npx playwright show-report
```

Or use Make targets from the repository root:
```bash
make e2e                          # Run E2E tests against localhost:9443
make e2e-headed                   # Run with browser visible
E2E_BASE_URL=https://... make e2e  # Custom server URL
make e2e-list                     # List all available tests
```

## Test Files

| File | Description |
|------|-------------|
| `01-login.spec.ts` | Login page, authentication flow, error handling |
| `02-health.spec.ts` | Public health/metrics endpoints |
| `03-stats.spec.ts` | Stats and events API endpoints |
| `04-config.spec.ts` | Config and IP ACL API (authenticated) |
| `05-dashboard.spec.ts` | Dashboard UI page navigation |
| `06-waf-blocking.spec.ts` | WAF blocking: SQLi/XSS blocked, benign passes, event log |
| `07-events.spec.ts` | Events API: filtering, pagination, date range, logs UI |
| `08-ai-config.spec.ts` | AI provider config, analysis trigger, stats endpoint |
| `09-routing.spec.ts` | Routing API, topology graph, upstream/route CRUD |
| `10-rules.spec.ts` | Rules API: filtering by type/action, enable/disable |
| `11-ip-acl.spec.ts` | IP ACL: blacklist/whitelist management, bans |
| `12-alerting.spec.ts` | Alerting rules: CRUD, history, conditions |
| `13-tenants.spec.ts` | Multi-tenant: tenant management, config, stats |
| `14-docker.spec.ts` | Docker integration: containers, services, events |
| `15-analytics.spec.ts` | Analytics dashboard: traffic, attacks, top targets |
| `16-ssl.spec.ts` | SSL/TLS: certificates, upload/delete, stats |
| `17-session.spec.ts` | Session management: auth, CSRF, cookie security |
| `18-websocket.spec.ts` | WebSocket upgrade, SSE streaming, auth |
| `19-ratelimit.spec.ts` | Rate limiting: config, 429 responses, bans |
| `20-bot.spec.ts` | Bot detection: known bots, JA3 fingerprinting |
| `21-cluster.spec.ts` | Cluster mode: node status, health, sync |
| `22-mcp.spec.ts` | MCP server: JSON-RPC tools, get_stats, events |
| `23-healthz.spec.ts` | Kubernetes probes: /healthz, /readyz, /livez, /metrics |
| `24-api-validation.spec.ts` | API error handling: 400, 401, 403, 404, 413, CORS |

## CI Integration

In CI, set these environment variables:
```bash
E2E_BASE_URL=https://your-test-server:9443
E2E_API_KEY=test-api-key
```

Tests run in parallel across Chromium, Firefox, and WebKit.

## Notes

- Tests are designed to run against a standalone GuardianWAF server
- Authentication uses session cookies obtained via login
- API key tests use the `X-API-Key` header directly
- Some tests require the WAF to be running with real traffic to validate filtering
