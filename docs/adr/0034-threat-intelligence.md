# ADR 0034: Threat Intelligence Layer

**Date:** 2026-04-15
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

IP reputation and domain reputation are high-signal, low-latency threat indicators. An IP known to be a Tor exit node, a cloud VPS used for scanning, or a botnet C&C is a strong prior for malicious intent — even before any payload is inspected.

GuardianWAF's IP ACL layer (ADR 0028) handles operator-defined static blocklists. The Threat Intel layer complements this with **dynamic, externally maintained feed data**:

- IP reputation feeds (abuse.ch, Spamhaus DROP, Emerging Threats)
- Domain reputation (malware hosting, phishing, C&C domains)
- Automated updates from HTTP/file sources without restart

The distinction from IP ACL is important: threat intel is probabilistic (an IP on a threat feed may be a false positive), so it contributes a score rather than always blocking. The IP ACL layer provides deterministic allow/deny.

## Decision

Implement a threat intelligence layer (`internal/layers/threatintel/`, Order 125) that:

1. Loads threat feeds from files or HTTP URLs on a configurable refresh schedule
2. Looks up each request's client IP and `Host` header against the loaded data
3. Adds a score contribution for matches (configurable per feed)
4. Caches lookup results in an LRU cache to avoid repeated lookups for the same IP

### Feed Types

| Type | Format | Example Source |
|------|--------|---------------|
| IP list | Newline-separated IPs or CIDRs | abuse.ch, Spamhaus DROP |
| Domain list | Newline-separated domains | malware domain lists |
| JSON feed | `{"ip": "...", "tags": [...], "score": N}` | Commercial threat intel APIs |

Feeds are configured with a `path` (local file) or `url` (HTTP/HTTPS endpoint) and a `refresh_interval`. The `FeedManager` goroutine fetches and parses feeds in the background; the active dataset is swapped atomically using an `atomic.Pointer` to a pre-built data structure.

### IP Lookup

Loaded IPs are split into two buckets:
- **Exact IPs** — stored in a `map[string]*ThreatInfo` for O(1) lookup
- **CIDR ranges** — stored in the same `cidrEntry` slice structure used by the IP ACL radix tree (shared code via `net.IPNet`)

Lookup order: exact IP → CIDR scan. In practice, most feeds use exact IPs; CIDR feeds are smaller and the linear scan over pre-parsed `net.IPNet` structs is fast enough (tested at 1,000 CIDR ranges: ~2µs).

### LRU Cache

To avoid re-parsing and re-looking-up the same IPs on every request (a legitimate CDN edge node may serve thousands of requests from the same IP range), results are cached in an LRU:

```
key:   IP string
value: *ThreatInfo (or nil for "not found")
TTL:   CacheTTL (default: 60m)
Size:  CacheSize (default: 100,000 entries)
```

Cache misses trigger a lookup against the loaded feed data. Cache entries are invalidated on feed refresh (the LRU is cleared and rebuilt lazily).

### Domain Reputation

When `DomainRepConfig.Enabled` is true, the `Host` header is checked against the domain blocklist. If `CheckRedirects` is true, the request body is scanned for URLs and their hostnames are also checked (this is relevant for phishing detection — a form submission that POSTs to a known phishing domain triggers an alert).

### Score vs. Block

Threat intel matches contribute to `ScoreAccumulator` rather than issuing `ActionBlock` directly. This is intentional:

- An IP on a Tor exit node list may be a security researcher or privacy-conscious user
- The threat intel score combined with other layer findings (anomalous payload, high request rate) makes the overall score more robust

`block_malicious: true` overrides this and issues `ActionBlock` immediately for IPs with the `malicious` tag in their threat info. This is appropriate for feeds with high precision (e.g., known botnet C&C IPs).

### Configuration

```yaml
threat_intel:
  enabled: true
  cache_size: 100000
  cache_ttl: 60m

  ip_reputation:
    enabled: true
    block_malicious: false    # Score only by default
    score_threshold: 30       # Score added on match

  domain_reputation:
    enabled: true
    block_malicious: false
    check_redirects: false

  feeds:
    - name: spamhaus_drop
      url: "https://www.spamhaus.org/drop/drop.txt"
      format: cidr_list
      refresh_interval: 12h
      tags: [spam, reputation]
      score: 30

    - name: abuse_ch_feodo
      url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
      format: ip_list
      refresh_interval: 1h
      tags: [malicious, botnet, c2]
      score: 80
      block: true             # This feed has high precision

    - name: custom_internal
      path: /etc/guardianwaf/custom-blocklist.txt
      format: ip_list
      refresh_interval: 5m
      tags: [custom]
      score: 50
```

### Feed Refresh Safety

HTTP feeds are fetched with a 30-second timeout. On fetch failure, the last successful dataset is retained (no downgrade to empty). Feed data is validated before activation: an empty feed (network error returning 0 bytes) is rejected. A metric `gwaf_threatintel_feed_errors_total{feed_name}` tracks failures.

## Consequences

### Positive
- Dynamic feeds update without WAF restart or configuration reload
- LRU cache makes repeated lookups for active IPs essentially free
- Score-based matching (not block-based) is safer for high false-positive feeds
- Domain reputation adds a second signal dimension beyond IP

### Negative
- HTTP feed fetching requires outbound network access from the WAF — in highly locked-down environments this may be restricted
- Feed quality varies widely; a low-quality feed with high false positives can degrade WAF accuracy
- Cache invalidation on feed refresh causes a burst of cache misses immediately after a large feed update — for a 100K-entry feed, this may add 1–2µs latency per request for a few seconds
- Domain reputation checking the request body (`check_redirects`) requires body buffering for all POST requests, not just those that fail other checks

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/layers/threatintel/feed.go` | Feed fetching, parsing, background refresh |
| `internal/layers/threatintel/cache.go` | LRU cache implementation |
| `internal/layers/threatintel/threatintel.go` | Layer, IP/domain lookup, score contribution |
| `internal/config/config.go` | `ThreatIntelConfig` struct |

## References

- [Spamhaus DROP List](https://www.spamhaus.org/drop/)
- [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/)
- [STIX/TAXII Threat Sharing Standard](https://oasis-open.github.io/cti-documentation/)
- [ADR 0011: IP Reputation Sharing](./0011-ip-reputation-sharing.md)
- [ADR 0028: IP ACL with Radix Tree](./0028-ip-acl-radix-tree.md)
