# ADR 0043: API Key Hashing Upgrade

**Date:** 2026-04-17
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF authenticates dashboard users, API consumers, and MCP clients via API keys. The original implementation used single-pass SHA256 with a random salt:

```
v1$<salt>$<sha256(salt+key)>
```

This is adequate for low-value internal tokens but falls short of industry best practices:

- Single-pass SHA256 is vulnerable to GPU-accelerated brute force
- NIST SP 800-63B recommends iterated hashing for stored credentials
- OWASP recommends key derivation functions (PBKDF2, bcrypt, Argon2) for password-like secrets

However, importing bcrypt or Argon2 would violate the zero-dependency constraint (ADR 0001). We need a stronger scheme using only Go stdlib.

## Decision

Upgrade API key hashing to iterated HMAC-SHA256 (100,000 rounds) with backward-compatible verification:

1. **New format** (`v2`): `v2$<salt>$<hmac-sha256-100k(salt, key)>`
   - Salt: 32 bytes, hex-encoded (64 chars)
   - Hash: HMAC-SHA256 iterated 100,000 times (PBKDF2-like construction using only `crypto/hmac`)
   - Cost: ~100ms on modern hardware (acceptable for login/authentication, not per-request)

2. **Backward compatibility** — `verifyAPIKeyHash` supports three formats:
   - `v2$...` — New iterated HMAC-SHA256 (preferred)
   - `v1$...` — Old salted SHA256 (auto-upgrades to v2 on next successful login)
   - Raw hex — Legacy (original) format, no salt

3. **Auto-upgrade path** — When a v1 or legacy key is verified successfully, the hash is transparently upgraded to v2 format. No user action required.

### Why HMAC-SHA256 instead of bcrypt/Argon2

- bcrypt requires `golang.org/x/crypto` — an external dependency
- Argon2 requires a CGO wrapper or pure-Go implementation — both are external
- Iterated HMAC-SHA256 with 100k rounds provides ~100ms verification time, which is sufficient for API key authentication (not a high-frequency operation)
- Go stdlib `crypto/hmac` is reviewed and audited by the Go security team

### Key verification flow

```
Input: stored hash string, plaintext API key
1. Parse version prefix (v2, v1, or raw)
2. For v2: extract salt, compute 100k HMAC rounds, constant-time compare
3. For v1: extract salt, compute single SHA256, constant-time compare, flag for upgrade
4. For raw: compute SHA256, constant-time compare, flag for upgrade
5. If flagged for upgrade: re-hash with v2 and store
```

## Consequences

**Positive:**
- ~100,000x harder to brute-force compared to single-pass SHA256
- Zero external dependencies — pure stdlib `crypto/hmac`
- Backward compatible — existing keys continue to work
- Auto-upgrade — old hashes migrate to v2 on next successful authentication

**Negative:**
- ~100ms verification time (vs ~0.1ms for single SHA256) — acceptable for login/auth, not per-request token validation
- Not as strong as Argon2id (memory-hard) — but API keys are high-entropy (32+ bytes), so memory hardness is less critical
- Custom KDF construction — not a standard like PBKDF2 (but uses the same HMAC-SHA256 building blocks)

## References

- ADR 0001: Zero External Dependencies
- `internal/tenant/manager.go` — v2 hash generation
- `internal/dashboard/auth.go` — v1/v2/legacy verification with auto-upgrade
