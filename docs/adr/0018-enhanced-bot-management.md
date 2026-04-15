# ADR 0018: Enhanced Bot Management

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF's current bot detection (Order 500) relies on:
- JA3/JA4 TLS fingerprint matching against known-bad lists
- User-Agent string heuristics
- Behavioral rate signals from the Rate Limit layer

This is sufficient for unsophisticated bots but fails against:
- **Headless browsers** (Playwright, Puppeteer, Selenium) — produce valid TLS fingerprints and plausible User-Agents
- **Residential proxies** — legitimate IPs, legitimate TLS, legitimate browsers
- **Slow-drip credential stuffing** — stays under rate thresholds by design
- **CAPTCHA farms** — human solvers defeat JS challenges

CloudFlare Bot Management, DataDome, and PerimeterX defend against these threats through browser fingerprinting, behavioral biometrics, and CAPTCHA integration. GuardianWAF needs equivalent capability.

## Decision

Extend the existing bot detection layer with four complementary techniques:

1. **Browser fingerprinting** — canvas, WebGL, font enumeration via injected JS
2. **Behavioral biometrics** — mouse movement, keystroke, scroll pattern analysis
3. **Good bot allowlisting** — verified crawler recognition (Googlebot, Bingbot, etc.)
4. **CAPTCHA integration** — hCaptcha and CloudFlare Turnstile as challenge escalation

### Architecture Overview

```
┌────────────────────────────────────────────────────────────────┐
│              Enhanced Bot Detection (Order 500)                  │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐    │
│  │  TLS / JA4  │  │  Good Bot    │  │  Fingerprint       │    │
│  │  Heuristics │  │  Allowlist   │  │  Token Validator   │    │
│  │  (existing) │  │  (rDNS verify)│  │  (from JS agent)  │    │
│  └──────┬──────┘  └──────┬───────┘  └────────┬───────────┘    │
│         │                │                    │                  │
│         └────────────────┴────────────────────┘                 │
│                          │                                       │
│                  ┌───────▼────────┐                             │
│                  │ Score Combiner │                             │
│                  └───────┬────────┘                             │
│                          │                                       │
│          ┌───────────────┼───────────────┐                      │
│          ▼               ▼               ▼                       │
│       Pass (0-30)   Challenge(31-70)  Block (71+)               │
│                          │                                       │
│                   ┌──────▼───────┐                              │
│                   │ CAPTCHA Gate │                              │
│                   │ hCaptcha /   │                              │
│                   │ Turnstile    │                              │
│                   └──────────────┘                              │
└────────────────────────────────────────────────────────────────┘
```

### Component 1: Browser Fingerprinting

The client-side JS agent (injected by Layer 590) collects:

```javascript
{
  // Canvas fingerprint (hashed)
  "canvas": "a3f8c2...",
  // WebGL vendor/renderer
  "webgl": { "vendor": "Intel", "renderer": "Intel Iris Xe" },
  // Font enumeration (30-font probe)
  "fonts": ["Arial", "Helvetica", "Times New Roman", ...],
  // Screen/window dimensions
  "screen": { "w": 1920, "h": 1080, "dpr": 2.0 },
  // Navigator properties
  "nav": {
    "languages": ["en-US", "en"],
    "platform": "Win32",
    "hw_concurrency": 8,
    "memory": 8
  },
  // WebRTC local IP (leak detection)
  "webrtc": "192.168.1.x",
  // Automation markers
  "headless": false,
  "webdriver": false,
  "phantom": false
}
```

The fingerprint is POSTed to `/gwaf/fp` as a signed JWT, verified by the bot detection layer on the next request. The signature uses an HMAC key rotated hourly.

### Component 2: Behavioral Biometrics

Mouse, keyboard, and touch events are sampled at 50ms intervals and summarized client-side before upload to minimize payload size:

```json
{
  "mouse": {
    "moves": 42,
    "avg_velocity": 312.5,
    "velocity_variance": 88.2,
    "direction_changes": 17
  },
  "keyboard": {
    "keystrokes": 23,
    "avg_dwell_ms": 120,
    "avg_flight_ms": 85,
    "rhythm_variance": 0.32
  },
  "scroll": {
    "events": 5,
    "avg_delta": 120,
    "smooth": true
  },
  "session_age_ms": 4500
}
```

An Isolation Forest model (shared infrastructure with ADR 0016) classifies sessions as human/bot. Raw biometric data is never stored; only the summary and classification verdict are retained.

### Component 3: Good Bot Allowlisting

Legitimate crawlers declare themselves via User-Agent and originate from known IP ranges. Verification:

1. Match User-Agent against known crawler patterns (Googlebot, Bingbot, Applebot, etc.)
2. **rDNS verify**: resolve `RemoteAddr` → hostname, then forward-resolve hostname back → must match `RemoteAddr`
3. Check IP against published ASN ranges (Google: AS15169, Microsoft: AS8075, Apple: AS714)
4. If all three pass → set `ctx.BotVerified = true`, skip further bot scoring

rDNS lookups are cached for 5 minutes with a bounded LRU (1000 entries) to avoid per-request DNS overhead.

### Component 4: CAPTCHA Integration

When the bot score is in the challenge range (31–70) and a browser session is detected:

```
1. Redirect to /gwaf/challenge?token=<signed-state>
2. Render CAPTCHA (hCaptcha or Turnstile widget)
3. On solve: POST solution to /gwaf/challenge/verify
4. GuardianWAF verifies with provider API (hcaptcha.com / challenges.cloudflare.com)
5. Issue a signed cookie (gwaf_challenge_pass) valid for 24h
6. Redirect back to original URL
```

The challenge cookie is verified by the bot detection layer on subsequent requests, bypassing the CAPTCHA gate. Cookie is bound to IP + User-Agent to limit transferability.

### Configuration

```yaml
bot_detection:
  # Existing
  ja3_blocklist: /etc/guardianwaf/ja3.txt
  ja4_blocklist: /etc/guardianwaf/ja4.txt

  # New: browser fingerprinting
  fingerprint:
    enabled: true
    endpoint: /gwaf/fp
    hmac_rotation_interval: 1h
    require_after_score: 25       # Require FP token if bot pre-score >= 25

  # New: behavioral biometrics
  biometrics:
    enabled: true
    model_path: /var/lib/guardianwaf/models/biometric.onnx
    min_session_age_ms: 1000      # Ignore sessions younger than 1s

  # New: good bot allowlist
  good_bots:
    enabled: true
    verify_rdns: true
    cache_ttl: 5m
    allowlist:
      - name: Googlebot
        ua_pattern: "Googlebot"
        asns: [15169]
      - name: Bingbot
        ua_pattern: "bingbot"
        asns: [8075]

  # New: CAPTCHA
  captcha:
    provider: hcaptcha            # hcaptcha | turnstile
    site_key: "${HCAPTCHA_SITE_KEY}"
    secret_key: "${HCAPTCHA_SECRET}"
    cookie_ttl: 24h
    trigger_score: 31             # Challenge if bot score >= 31
```

## Consequences

### Positive
- Headless browser detection without breaking real users
- Good bot allowlisting eliminates false positives for SEO crawlers
- CAPTCHA integration is provider-agnostic; switching vendors is a config change
- Biometric and fingerprint data is processed on-device and summarized — reduces privacy surface

### Negative
- JS agent injection requires the response layer to rewrite HTML — incompatible with `Content-Encoding: br` responses without intermediate decompression
- rDNS verification adds ~5ms latency on cache miss (DNS RTT)
- CAPTCHA redirect breaks non-browser clients (mobile apps, APIs) — must be disabled for API-only routes
- Behavioral biometrics require a minimum session duration; short-lived bot sessions may slip through

## Implementation Locations

**Note**: `internal/layers/botdetect/` exists with base bot detection (layer, JA3/JA4, UA, behavior).
The enhanced features below are planned: `fingerprint/fingerprinter.go`, `biometric/detector.go`,
`web/` (goodbot), `challenge/` (CAPTCHA), and `clientside/agent.js`.

| File | Purpose |
|------|---------|
| `internal/layers/botdetect/fingerprint/fingerprinter.go` | FP token issuance and verification (planned) |
| `internal/layers/botdetect/biometric/detector.go` | Biometric summary parsing and scoring (planned) |
| `internal/layers/botdetect/web/` | rDNS verification and ASN checking (planned) |
| `internal/layers/botdetect/challenge/` | CAPTCHA challenge flow (planned: hcaptcha.go exists) |
| `internal/layers/clientside/agent/agent.js` | JS biometric/fingerprint collector (planned) |
| `internal/config/config.go` | `BotDetectionConfig` extensions |

## References

- [hCaptcha API](https://docs.hcaptcha.com/)
- [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/)
- [Googlebot Verification](https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot)
- [JA4 Fingerprinting](https://github.com/FoxIO-LLC/ja4)
- [ADR 0016: ML Anomaly Detection](./0016-ml-anomaly-detection.md)
