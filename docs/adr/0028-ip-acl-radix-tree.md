# ADR 0028: IP Access Control List with Radix Tree

**Date:** 2026-04-15
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

IP-based access control is the most fundamental WAF defence: allow known-good IPs, block known-bad IPs and CIDRs. The implementation must handle:

- **Scale** — production deployments may have thousands of CIDR ranges in blocklists (threat intel feeds, geo-blocks)
- **Latency** — the IP ACL is Order 100, the very first layer; its cost is paid on every single request
- **Dynamic updates** — auto-ban IPs discovered by downstream layers (rate limit, bot detection) must be added at runtime without blocking the hot path
- **IPv4 and IPv6** — both address families must be supported with identical semantics

A naive linear scan of CIDR ranges is O(n) per lookup. With 10,000 ranges, that is 10,000 comparisons per request at sub-millisecond latency budgets.

## Decision

Use a **binary radix tree** (Patricia trie) keyed on IP address bits. Each tree supports O(log n) worst-case lookup with typical performance of O(32) for IPv4 (at most 32 bit comparisons) and O(128) for IPv6.

Two separate trees are maintained: `whitelist` and `blacklist`. The processing order is:

1. **Auto-ban check** — lock-free atomic read of `ExpiresAt`; if present and unexpired → `ActionBlock`
2. **Whitelist check** — if IP matches any whitelist CIDR → `ActionPass` (short-circuit)
3. **Blacklist check** — if IP matches any blacklist CIDR → `ActionBlock`
4. Default → `ActionPass`

### Radix Tree Design

```go
type node struct {
    bit      int    // Which bit of the IP to branch on
    left     *node  // 0-branch
    right    *node  // 1-branch
    cidr     *net.IPNet
    value    bool
}
```

Insertion converts the CIDR to a fixed 16-byte representation (IPv4-mapped IPv6 for uniform handling), then walks the tree bit by bit. Lookup follows the same bit path, returning `true` at the most specific matching prefix.

The tree is immutable after construction. Runtime additions (auto-ban, API-driven whitelist/blacklist changes) rebuild the relevant sub-tree under a write lock while the old tree continues serving reads.

### Auto-Ban

Downstream layers (rate limit, bot detection, ATO) call back into the IP ACL layer via `OnAutoBan`:

```go
layer.AddAutoBan(ip, reason, ttl)
```

Auto-ban entries are stored in a `map[string]*autoBanEntry` protected by `sync.RWMutex`. The expiry is stored as `atomic.Value` (type `time.Time`) so the hot-path read (`ExpiresAt.Load()`) is lock-free:

```go
entry := l.autoBan[ip]    // map read under RLock
if entry != nil {
    exp := entry.ExpiresAt.Load().(time.Time)
    if time.Now().Before(exp) { ... }   // Atomic, no lock needed
}
```

A background goroutine purges expired auto-ban entries every `max_ttl` to prevent unbounded map growth. The map is capped at `max_auto_ban_entries` (default: 100,000); oldest entries are evicted when the cap is reached.

### Runtime Add/Remove

The dashboard and MCP tools can add/remove CIDR ranges at runtime:

```
POST /api/v1/ipacl/blacklist  { "cidr": "203.0.113.0/24" }
DELETE /api/v1/ipacl/blacklist/203.0.113.0%2F24
```

These operations rebuild the affected radix tree under a write lock. The hot path holds a `RLock` only for the duration of the lookup (a few nanoseconds), so tree rebuilds do not cause observable latency spikes.

### Configuration

```yaml
ip_acl:
  enabled: true
  whitelist:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "127.0.0.1/32"
  blacklist:
    - "203.0.113.0/24"    # Known-bad range example

  auto_ban:
    enabled: true
    default_ttl: 1h
    max_ttl: 24h
    max_entries: 100000
```

### Performance Profile

| Operation | Complexity | Measured |
|-----------|-----------|---------|
| Lookup (IPv4) | O(32) bit comparisons | ~80ns |
| Lookup (IPv6) | O(128) bit comparisons | ~200ns |
| Insert (rebuild) | O(n log n) | ~1ms for 10k CIDRs |
| Auto-ban check | O(1) map + atomic | ~20ns |

## Consequences

### Positive
- O(log n) CIDR lookup is fast enough to be negligible even with large blocklists
- Lock-free auto-ban expiry reads eliminate contention on the hot path
- IPv4 and IPv6 use the same tree code (IPv4 is stored as IPv4-in-IPv6)
- Auto-ban with TTL enables temporary blocks without manual cleanup

### Negative
- The radix tree is rebuilt on every structural change — for a 10,000-entry blocklist, a single API-driven add takes ~1ms under write lock; concurrent requests are queued during this window
- Auto-ban map is in-process only; entries are lost on restart (use ADR 0023 cluster replication for persistence)
- `max_auto_ban_entries` eviction uses oldest-first; an attacker rotating IPs rapidly could displace legitimate auto-bans

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/layers/ipacl/radix.go` | Radix tree (Patricia trie) implementation |
| `internal/layers/ipacl/ipacl.go` | Layer, auto-ban, whitelist/blacklist logic |
| `internal/config/config.go` | `IPACLConfig` struct |

## References

- [Patricia Trie — Knuth TAOCP Vol. 3](https://en.wikipedia.org/wiki/Radix_tree)
- [net.IPNet — Go stdlib](https://pkg.go.dev/net#IPNet)
- [ADR 0023: High Availability / Raft](./0023-high-availability-raft.md)
- [ADR 0011: IP Reputation Sharing](./0011-ip-reputation-sharing.md)
