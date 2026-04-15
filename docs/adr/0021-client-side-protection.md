# ADR 0021: Client-Side Protection (RASP-lite)

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF protects traffic at the network/HTTP layer but has no visibility into what happens in the user's browser after a response is delivered. This leaves a significant blind spot:

- **Magecart / formjacking attacks** — malicious scripts injected into the page silently exfiltrate form data (credit cards, passwords) to attacker-controlled servers
- **DOM-based XSS** — JavaScript executing in the browser context can access cookies, local storage, and DOM content even when server-side XSS defenses are in place
- **Supply chain attacks** — a compromised third-party CDN script (analytics, chat widget) can steal data from every user session
- **Iframe clickjacking** — despite `X-Frame-Options`, dynamic iframe injection via JS bypasses static header protections

Current client-side protection (Layer 590) only injects a Content-Security-Policy header and a placeholder script stub. There is no real-time monitoring or reporting from the browser.

## Decision

Implement a lightweight client-side agent ("RASP-lite") injected by Layer 590 that:

1. **Monitors DOM mutations** — detects unauthorized script injection and form field tampering
2. **Enforces form field integrity** — computes checksums of sensitive form fields on page load and alerts if they are modified by unauthorized scripts
3. **Collects CSP violation reports** — enriches the WAF event stream with browser-side violation data
4. **Detects skimmer patterns** — identifies known Magecart exfiltration signatures (XHR/fetch to non-allowlisted domains from payment pages)
5. **Reports events** to the WAF via a dedicated beacon endpoint

### Injection Mechanism

Layer 590 rewrites HTML responses (when `Content-Type: text/html`):

```html
<!-- Injected before </head> -->
<script src="/gwaf/agent.js" integrity="sha256-..." crossorigin="anonymous"></script>
<meta name="gwaf-config" content="<base64-encoded-agent-config>">
```

The `integrity` attribute uses SRI to prevent the agent itself from being tampered with by a compromised CDN. The agent config contains:
- Protected form selectors (`input[type=password]`, `input[name*=card]`)
- Allowed exfiltration domains (XHR/fetch allow-list)
- Beacon endpoint URL
- Session token (signed, for beacon authentication)

### Agent Architecture

```
Browser (gwaf-agent.js ~8KB gzipped)
┌──────────────────────────────────────────────────────────────────┐
│                                                                    │
│  ┌──────────────────┐  ┌─────────────────┐  ┌────────────────┐  │
│  │  MutationObserver │  │  Form Integrity  │  │ Network Monitor│  │
│  │  (DOM changes)   │  │  (field hashes)  │  │ (XHR/fetch)   │  │
│  └────────┬─────────┘  └────────┬─────────┘  └───────┬────────┘  │
│           │                     │                     │            │
│           └─────────────────────┴─────────────────────┘            │
│                                         │                          │
│                               ┌─────────▼──────────┐              │
│                               │  Event Batcher      │             │
│                               │  (100ms debounce)   │             │
│                               └─────────┬───────────┘             │
│                                         │                          │
│                            POST /gwaf/beacon                       │
└──────────────────────────────────────────────────────────────────┘
                                          │
                             ┌────────────▼──────────────┐
                             │  GuardianWAF Beacon Handler│
                             │  (Layer 590 / event bus)  │
                             └───────────────────────────┘
```

### DOM Monitoring

A `MutationObserver` watches for:

| Mutation | Detection | Action |
|----------|-----------|--------|
| New `<script>` tag added to DOM | Check against CSP allow-list | Report if not allowed |
| New `<iframe>` added | Check `src` against allow-list | Report if not allowed |
| Form `action` attribute changed | Always suspicious | Report + freeze form |
| Input event handler added via `addEventListener` | On `password`/`card` fields | Report (potential keylogger) |
| `document.cookie` write from non-first-party script | Cookie stealing | Report + optionally revoke |

### Form Field Integrity

On `DOMContentLoaded`, the agent records SHA-256 hashes of sensitive field values and attached event listeners. If a hash changes without a legitimate user interaction (detected via trusted event flag), a beacon is fired:

```json
{
  "type": "form_tampering",
  "field": "input[name=card_number]",
  "page": "/checkout",
  "detected_at": 1234567890
}
```

### Network Monitor

`XMLHttpRequest` and `fetch` are monkey-patched to intercept outbound requests. Requests to domains not in the `allowed_origins` list from pages matching `payment_path_patterns` trigger a high-severity beacon:

```json
{
  "type": "exfiltration_attempt",
  "target_url": "https://evil.ru/collect",
  "from_page": "/checkout",
  "data_size_bytes": 256
}
```

The beacon is sent **before** the exfiltrating request is allowed to complete (using synchronous XHR as a last resort, or `navigator.sendBeacon`).

### Beacon Endpoint & Rate Limiting

`POST /gwaf/beacon` — handled by GuardianWAF, not proxied to backend:
- Authenticated via session token (HMAC-SHA256, 1-hour validity)
- Rate limited to 10 beacons/minute per session (prevents beacon flooding)
- Events are ingested into the event bus and visible in the dashboard

### Configuration

```yaml
client_side:
  enabled: true
  agent_path: /gwaf/agent.js
  beacon_path: /gwaf/beacon

  protect:
    form_selectors:
      - "input[type=password]"
      - "input[name*=card]"
      - "input[name*=cvv]"
      - "input[name*=ssn]"
    payment_paths:
      - "/checkout"
      - "/payment"
    allowed_exfil_domains:
      - "analytics.example.com"
      - "cdn.stripe.com"

  csp:
    report_uri: /gwaf/csp-report
    report_only: false

  inject:
    enabled: true
    content_types: ["text/html"]
    exclude_paths: ["/api/*", "/gwaf/*"]

  score_on_beacon:
    exfiltration_attempt: 90
    form_tampering: 70
    unauthorized_script: 40
    csp_violation: 20
```

## Consequences

### Positive
- Magecart and formjacking detection that is impossible at the network layer
- CSP violation reports provide ground truth for tightening policies
- Real-time browser events feed the same WAF event stream, giving a unified view

### Negative
- HTML response rewriting adds CPU overhead (string search + inject for every HTML response)
- `fetch`/`XHR` monkey-patching is fragile; some frameworks detect and refuse to work with patched globals
- SPA frameworks (React, Vue) that hydrate on the client may fire false-positive DOM mutation events
- Agent must be kept small (<10KB gzipped) to avoid impacting page performance
- Zero-dependency constraint means the agent must be hand-written vanilla JS with no bundler dependencies

## Implementation Locations

**Note**: `internal/layers/clientside/` exists with `layer.go`, `config.go`, `report_handler.go` (implemented). Order 590 is defined in `layer.go` and registered in the main pipeline. The files below (`injector.go`, `beacon.go`, `csp_report.go`, `agent/`) are planned but do not exist yet.

| File | Purpose |
|------|---------|
| `internal/layers/clientside/injector.go` | HTML response rewriting (planned) |
| `internal/layers/clientside/beacon.go` | Beacon endpoint handler (planned) |
| `internal/layers/clientside/csp_report.go` | CSP violation report handler (planned) |
| `internal/layers/clientside/agent/agent.js` | Browser agent (vanilla JS, no dependencies) (planned) |
| `internal/layers/clientside/agent/build.go` | `//go:generate` embed script (planned) |

## References

- [Magecart Group Overview — RiskIQ](https://www.riskiq.com/research/magecart/)
- [Subresource Integrity (SRI)](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)
- [MutationObserver API](https://developer.mozilla.org/en-US/docs/Web/API/MutationObserver)
- [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/)
- [ADR 0005: React Dashboard](./0005-react-dashboard.md)
