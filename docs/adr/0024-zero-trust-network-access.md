# ADR 0024: Zero Trust Network Access (ZTNA)

**Date:** 2026-04-15
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

Traditional perimeter security assumes that traffic originating from inside the network is trustworthy. Modern threat models invalidate this assumption: lateral movement after an initial compromise, compromised credentials, malicious insiders, and supply-chain attacks all originate from "inside" the perimeter.

GuardianWAF already enforces per-request WAF checks, but these operate at the HTTP layer and are unaware of:
- **Client identity** — who is making the request (human, service, device)
- **Device posture** — is the client device managed, up-to-date, attested?
- **Least-privilege access** — should this client identity be allowed to reach this path?

A Zero Trust model addresses these gaps by replacing implicit trust with explicit, continuous verification of identity and device state.

## Decision

Implement a Zero Trust middleware (`internal/layers/zerotrust/`) that enforces:

1. **Mutual TLS (mTLS)** — clients present a certificate; the WAF verifies it against a configured CA
2. **Device attestation** — an attestation token proves the device is managed and healthy
3. **Graduated trust levels** — requests are assigned a trust score (None → Low → Medium → High → Maximum) based on authentication factors presented
4. **Path-based access control** — resource access is gated on minimum required trust level
5. **Session management** — verified identities receive a session token (`X-ZeroTrust-Session`) to avoid re-authentication on every request

### Trust Level Model

| Level | Value | Requirements |
|-------|-------|-------------|
| `none` | 0 | No credentials presented |
| `low` | 1 | Valid client certificate (CN recognized) but device unknown |
| `medium` | 2 | Valid certificate + device fingerprint in registry |
| `high` | 3 | Valid certificate + attested device (attestation token valid) |
| `maximum` | 4 | All of high + recent strong authentication (within `reauth_window`) |

Trust level is computed per-request and cached in the session for `session_ttl` duration. Any change in device posture (new attestation failure, certificate revocation) invalidates the session.

### Authentication Factors

**Factor 1: mTLS Client Certificate**

The WAF's TLS terminator is configured with `ClientAuth: tls.RequireAndVerifyClientCert`. The `x509.Certificate` extracted from the TLS handshake provides:
- Subject CN → mapped to `ClientIdentity.UserID`
- Subject O → mapped to `ClientIdentity.TenantID`
- Certificate serial → used as device identifier seed
- NotAfter → checked against current time (explicit, not relying solely on TLS stack)

Certificates are verified against a CA bundle configured per-tenant (`zerotrust.ca_cert`). CRL/OCSP checking is optional (`revocation_check: ocsp`).

**Factor 2: Device Attestation**

The client POSTs an attestation token to `/gwaf/zt/attest` before accessing resources. The token is a signed JWT containing:

```json
{
  "device_id": "dev_abc123",
  "fingerprint": "sha256:...",
  "attested_at": 1234567890,
  "tpm_quote": "<base64>",        // Optional: TPM 2.0 quote
  "platform": "windows",
  "os_version": "10.0.26200",
  "disk_encrypted": true,
  "antivirus_active": true
}
```

The WAF verifies the JWT signature (RS256 or ES256) against a configured attestation authority public key. The `fingerprint` is stored in the device registry; subsequent requests include `X-Device-Fingerprint` which is matched against the registry.

**Factor 3: Session Token**

After successful mTLS + attestation, the WAF issues an `X-ZeroTrust-Session` HMAC-signed token containing:
- `identity_id` (hashed)
- `device_id`
- `trust_level`
- `issued_at`, `expires_at`

The token is validated on every subsequent request. Invalidation occurs on:
- Expiry (`session_ttl`, default 1 hour)
- Certificate revocation detected
- Device fingerprint mismatch
- Manual revocation via dashboard

### Access Control Policy

Path-level policies define the minimum trust level required:

```yaml
zerotrust:
  policies:
    - path: "/admin/*"
      min_trust: maximum
    - path: "/api/internal/*"
      min_trust: high
    - path: "/api/*"
      min_trust: medium
    - path: "/public/*"
      min_trust: none           # Public — no ZTNA required
  default_min_trust: low
```

Policy resolution uses longest-prefix matching. A request that does not meet the minimum trust level receives HTTP 403 with a `X-ZeroTrust-Required` header indicating what additional authentication is needed.

### Architecture

```
HTTP Request
     │
     ▼
[TLS Terminator]
  ← Extract client cert (mTLS) → TrustLevel: low
     │
     ▼
[Zero Trust Middleware]
     │
     ├─ X-ZeroTrust-Session present?
     │     Yes → Validate session token
     │              Valid → Apply cached trust level
     │              Invalid → Fall through to auth
     │
     ├─ X-Device-Fingerprint present?
     │     Yes → Look up in device registry
     │              Found → TrustLevel: medium
     │
     ├─ POST /gwaf/zt/attest?
     │     Yes → Verify attestation JWT
     │              Valid → TrustLevel: high
     │
     ├─ Check path policy (min_trust required)
     │     Insufficient trust → 403
     │     Sufficient trust → pass
     │
     └─ Issue/refresh X-ZeroTrust-Session
```

### Configuration

```yaml
zerotrust:
  enabled: true
  require_mtls: true
  ca_cert: /etc/guardianwaf/zt-ca.pem
  revocation_check: ocsp          # none | crl | ocsp

  device:
    attestation_pubkey: /etc/guardianwaf/attestation.pub
    registry_path: /var/lib/guardianwaf/devices.json
    max_attest_age: 24h

  session:
    ttl: 1h
    hmac_key: "${ZT_SESSION_KEY}"  # 32-byte hex

  reauth_window: 8h               # Window for "maximum" trust level

  allow_bypass_paths:
    - /healthz
    - /gwaf/zt/attest
    - /gwaf/agent.js

  policies:
    - path: "/admin/*"
      min_trust: maximum
    - path: "/api/*"
      min_trust: medium
  default_min_trust: low
```

## Consequences

### Positive
- Lateral movement by compromised credentials is contained — stolen credentials alone do not grant access without a matching device certificate
- Graduated trust levels allow progressive rollout (start with `low`, tighten over time)
- Path-based policies are expressed in configuration without code changes
- Integrates with existing TLS infrastructure (`internal/tls/`)

### Negative
- mTLS requires client certificate distribution — significant operational overhead for human user access (more suited to service-to-service)
- Device attestation requires a managed device program; unmanaged BYOD devices cannot reach `high` trust without enrollment
- Session token in a header requires HTTPS; intercepted tokens grant session-level access until expiry
- The ZTNA middleware runs before the WAF pipeline layers — a bug in identity parsing could affect all requests, not just protected paths

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/layers/zerotrust/service.go` | Trust level computation, device registry, session management |
| `internal/layers/zerotrust/middleware.go` | HTTP middleware — applies policy, issues session tokens |
| `internal/config/config.go` | `ZeroTrustConfig` struct |

## References

- [NIST SP 800-207 Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication](https://datatracker.ietf.org/doc/html/rfc8705)
- [TPM 2.0 Remote Attestation](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [ADR 0006: Multi-Tenant Isolation](./0006-multi-tenant-isolation.md)
- [ADR 0013: Multi-Region Support](./0013-multi-region-support.md)
