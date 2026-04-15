# ADR 0030: Account Takeover Protection

**Date:** 2026-04-15
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

Account Takeover (ATO) attacks target authentication endpoints with the goal of gaining unauthorized access to user accounts. They go beyond simple brute force and require dedicated detection because:

- **Credential stuffing** distributes attempts across many IPs (defeating per-IP rate limits) using breached username/password pairs
- **Password spray** uses one common password across many accounts (defeating per-account brute force limits)
- **Impossible travel** detects session hijacking after the fact — a legitimate user in Istanbul cannot be in Tokyo 10 minutes later

The generic rate limit layer (ADR 0029) protects login endpoints by volume, but cannot distinguish between these ATO patterns, which may individually stay under rate thresholds. A dedicated ATO layer tracks cross-dimensional patterns that are invisible to single-dimension rate limiting.

## Decision

Implement an ATO protection layer (`internal/layers/ato/`, Order 250) that independently tracks four attack patterns, each configurable and independently disableable:

### Pattern 1: Brute Force

Detects rapid authentication attempts against a single account or from a single IP:

- Per-IP counter: attempts from one IP within `window` → block IP for `block_duration`
- Per-email counter: attempts against one email/username within `window` → block account for `block_duration`

Counters are stored in `AttemptTracker` (in-memory sliding window with GC). The email is extracted from the request body using a configurable regex (default: JSON field `email`, `username`, or `login`).

### Pattern 2: Credential Stuffing

Detects a single email/username being attempted from many different IPs simultaneously:

```
distributed_threshold = 5   # Same email seen from 5+ different IPs within window
```

The `AttemptTracker` maintains `map[email]set[IP]`. When the distinct-IP count for an email exceeds the threshold, the email is flagged and subsequent attempts return a score increment (not a hard block by default — operators tune this based on false positive tolerance).

### Pattern 3: Password Spray

Detects a single password being used against many different accounts:

```
threshold = 20   # Same password hash seen against 20+ different accounts within window
```

The password is extracted from the request body (field name configurable) and stored as a SHA-256 hash — the raw password is never stored. When the same password hash is seen across `threshold` different usernames, a spray attack is flagged.

**Privacy note:** Even hashed passwords are sensitive. The password hash map has a configurable TTL and is never logged or exported to SIEM.

### Pattern 4: Impossible Travel

Detects location jumps that are physically impossible given elapsed time:

```go
type GeoLocation struct {
    Latitude  float64
    Longitude float64
    Country   string
    City      string
}

func isPossible(prev, curr GeoLocation, elapsed time.Duration) bool {
    distanceKm := haversine(prev, curr)
    maxReachableKm := elapsed.Hours() * 900   // ~900 km/h ≈ commercial flight speed
    return distanceKm <= maxReachableKm
}
```

The GeoIP database (see `internal/geoip/`) maps the client IP to a geographic coordinate. The last successful (or attempted) login location per user session is stored in `lastLogin map[sessionID]*GeoLocation`. If the distance exceeds what is physically reachable in `elapsed`, a high-severity finding is generated.

### Login Path Detection

The ATO layer only activates on paths that match `login_paths` (configurable glob list). Paths that don't match are passed through with zero overhead. Pattern matching uses pre-compiled `*regexp.Regexp` objects.

### Architecture

```
Request → Path matches login_paths?
               │ No  → pass
               │ Yes ↓
          ┌────────────────────────────────────────┐
          │           ATO Layer (Order 250)          │
          │                                          │
          │  ┌─────────────┐  ┌───────────────────┐ │
          │  │  Brute Force │  │ Credential Stuff. │ │
          │  │  per-IP/acct │  │ email × IP set    │ │
          │  └──────┬───────┘  └────────┬──────────┘ │
          │         │                   │             │
          │  ┌──────▼───────┐  ┌────────▼──────────┐ │
          │  │ Password Spray│  │ Impossible Travel │ │
          │  │ pwd_hash×acct │  │ haversine + time  │ │
          │  └──────┬───────┘  └────────┬──────────┘ │
          │         └─────────┬──────────┘            │
          │                   ▼                        │
          │           ScoreAccumulator                 │
          └────────────────────────────────────────────┘
```

### Configuration

```yaml
ato:
  enabled: true
  login_paths:
    - "/api/login"
    - "/api/auth/token"
    - "/*/signin"

  brute_force:
    enabled: true
    window: 15m
    max_attempts_per_ip: 50
    max_attempts_per_email: 10
    block_duration: 1h

  credential_stuffing:
    enabled: true
    distributed_threshold: 5
    window: 10m
    block_duration: 24h

  password_spray:
    enabled: true
    threshold: 20
    window: 30m
    block_duration: 6h

  impossible_travel:
    enabled: true
    max_distance_km: 2000
    max_time_hours: 4
    block_duration: 24h
    geodb_path: /var/lib/guardianwaf/GeoLite2-City.mmdb
```

### Score Contribution

| Detection | Score Added | Rationale |
|-----------|-------------|-----------|
| Brute force (IP) | 60 | High confidence, single-IP signal |
| Brute force (email) | 50 | Distributed may share email |
| Credential stuffing | 70 | Multi-IP coordination is strong signal |
| Password spray | 65 | Many accounts targeted |
| Impossible travel | 80 | Near-certain session hijack |

## Consequences

### Positive
- Four independent detectors provide layered coverage — an attacker that evades one (e.g., rotates IPs to avoid brute force) may still be caught by credential stuffing or password spray
- Password spray uses hashed passwords; raw credentials are never stored in memory
- Impossible travel catches session hijacking that no rate limit can detect

### Negative
- All counters are in-process; a cluster of GuardianWAF nodes does not share ATO state by default (distributed credential stuffing across nodes is undetected unless Raft replication is used)
- Impossible travel requires GeoIP database accuracy; GeoIP errors generate false positives for legitimate users on VPNs or mobile networks
- Email extraction from request body assumes a known JSON field name; GraphQL mutations or non-standard field names require custom configuration
- Password spray detection stores a rolling hash map that grows with unique password count; very high-volume sprays may consume significant memory before TTL eviction

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/layers/ato/ato.go` | Layer, four detection patterns, score accumulation |
| `internal/layers/ato/tracker.go` | `AttemptTracker` — sliding window counters, GC |
| `internal/layers/ato/geo.go` | `LocationDB` wrapper, haversine distance |
| `internal/config/config.go` | `ATOConfig` struct |

## References

- [OWASP Credential Stuffing Prevention](https://owasp.org/www-community/attacks/Credential_stuffing)
- [Haversine Formula](https://en.wikipedia.org/wiki/Haversine_formula)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3) (future: breached password check)
- [ADR 0029: Rate Limiting](./0029-rate-limiting-token-bucket.md)
- [ADR 0018: Enhanced Bot Management](./0018-enhanced-bot-management.md)
