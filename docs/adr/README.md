# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for GuardianWAF.
Each ADR documents a significant design decision: the context that drove it,
the decision made, and the consequences.

**Format:** Each ADR has sections: Context → Decision → Consequences → Implementation Locations → References.
**Status values:** `Proposed` (planned), `Implemented` (in codebase), `Accepted` (principle/constraint).

---

## Index

### Foundational Decisions

| ADR | Title | Status |
|-----|-------|--------|
| [0001](./0001-zero-external-dependencies.md) | Zero External Go Dependencies | Accepted |
| [0002](./0002-custom-yaml-parser.md) | Custom YAML Parser | Accepted |
| [0003](./0003-tokenizer-based-detection.md) | Tokenizer-Based Detection | Accepted |
| [0004](./0004-pipeline-architecture.md) | Pipeline Architecture | Accepted |
| [0005](./0005-react-dashboard.md) | React Dashboard | Accepted |
| [0006](./0006-multi-tenant-isolation.md) | Multi-Tenant Isolation | Accepted |

### AI & Machine Learning

| ADR | Title | Status |
|-----|-------|--------|
| [0007](./0007-ml-anomaly-detection.md) | ML Anomaly Detection (early) | Proposed |
| [0008](./0008-ai-batch-analysis.md) | AI Batch Threat Analysis | Implemented |
| [0016](./0016-ml-anomaly-detection.md) | Real-Time ML Anomaly Detection (ONNX) | Proposed |

### Observability & Integration

| ADR | Title | Status |
|-----|-------|--------|
| [0009](./0009-opentelemetry-integration.md) | OpenTelemetry Integration | Proposed |
| [0025](./0025-siem-integration.md) | SIEM Integration (CEF/LEEF/Splunk/Elastic) | Implemented |

### Security Features & Rules

| ADR | Title | Status |
|-----|-------|--------|
| [0010](./0010-dynamic-rules-api.md) | Dynamic Rules API | Proposed |
| [0011](./0011-ip-reputation-sharing.md) | IP Reputation Sharing | Proposed |
| [0012](./0012-graphql-protection.md) | Enhanced GraphQL Protection | Implemented |
| [0014](./0014-wasm-sandbox.md) | WebAssembly Sandbox for Rule Evaluation | Proposed |
| [0027](./0027-virtual-patching-nvd.md) | Virtual Patching with NVD Integration | Implemented |
| [0032](./0032-owasp-crs-integration.md) | OWASP CRS Integration (native Go) | Implemented |

### Scalability & Distribution

| ADR | Title | Status |
|-----|-------|--------|
| [0013](./0013-multi-region-support.md) | Multi-Region Support | Proposed |
| [0015](./0015-distributed-event-store.md) | Distributed Event Store | Proposed |
| [0023](./0023-high-availability-raft.md) | High Availability with Raft Consensus | Proposed |

### WAF Pipeline Layers (by order)

| ADR | Order | Layer | Status |
|-----|-------|-------|--------|
| [0024](./0024-zero-trust-network-access.md) | 70 | Zero Trust (mTLS) | Proposed — not registered in pipeline |
| (internal/cluster/) | 75 | Cluster | Proposed — not registered in pipeline |
| [0035](./0035-websocket-proxy.md) | 76 | WebSocket | Proposed — not registered in pipeline |
| [0019](./0019-grpc-protocol-support.md) | 78 | gRPC | Proposed — not registered in pipeline |
| [0036](./0036-canary-deployments.md) | 95 | Canary Deployment | Proposed — not registered in pipeline |
| [0028](./0028-ip-acl-radix-tree.md) | 100 | IP ACL (Radix Tree) | Implemented |
| [0034](./0034-threat-intelligence.md) | 125 | Threat Intelligence | Implemented |
| [0037](./0037-request-replay.md) | 145 | Request Recording & Replay | Proposed — not registered in pipeline |
| [0031](./0031-cors-layer.md) | 150 | CORS Validation | Implemented |
| [0029](./0029-rate-limiting-token-bucket.md) | 200 | Rate Limiting (Token Bucket) | Implemented |
| [0030](./0030-ato-protection.md) | 250 | ATO Protection | Implemented |
| (internal/layers/apisecurity/) | 275 | API Security | Implemented |
| (internal/layers/apivalidation/) | 280 | API Validation | Implemented |
| [0017](./0017-api-discovery-schema-validation.md) | TBD | API Discovery & Schema Validation | Proposed |
| [0033](./0033-request-sanitizer.md) | 300 | Request Sanitizer | Implemented |
| [0032](./0032-owasp-crs-integration.md) | 350 | OWASP CRS | Implemented |
| [0003](./0003-tokenizer-based-detection.md) | 400 | Detection Engine | Accepted |
| [0027](./0027-virtual-patching-nvd.md) | 450 | Virtual Patching | Implemented |
| [0020](./0020-advanced-dlp.md) | 475 | Advanced DLP | Proposed |
| [0016](./0016-ml-anomaly-detection.md) | 475 | ML Anomaly Detection | Proposed |
| [0018](./0018-enhanced-bot-management.md) | 500 | Enhanced Bot Management | Proposed |
| [0021](./0021-client-side-protection.md) | 590 | Client-Side Protection (RASP-lite) | Proposed |
| [0038](./0038-response-layer.md) | 600 | Response Layer | Implemented |

### Protocol Support

| ADR | Title | Status |
|-----|-------|--------|
| [0012](./0012-graphql-protection.md) | GraphQL Protection | Implemented |
| [0035](./0035-websocket-proxy.md) | WebSocket Proxy | Proposed |
| [0019](./0019-grpc-protocol-support.md) | gRPC Protocol Support | Proposed |

### Enterprise & Compliance

| ADR | Title | Status |
|-----|-------|--------|
| [0020](./0020-advanced-dlp.md) | Advanced DLP Pattern Engine | Proposed |
| [0022](./0022-compliance-reporting.md) | Compliance & Reporting Framework | Proposed |
| [0024](./0024-zero-trust-network-access.md) | Zero Trust Network Access (mTLS) | Proposed — not registered in pipeline |

### Developer Experience

| ADR | Title | Status |
|-----|-------|--------|
| [0026](./0026-response-caching-layer.md) | — | Response Caching | Proposed — not registered in pipeline |
| [0036](./0036-canary-deployments.md) | 95 | Canary Deployments | Proposed — not registered in pipeline |
| [0037](./0037-request-replay.md) | 145 | Request Recording & Replay | Proposed — not registered in pipeline |

---

## Writing a New ADR

Use this template:

```markdown
# ADR NNNN: Title

**Date:** YYYY-MM-DD
**Status:** Proposed | Implemented | Accepted
**Deciders:** GuardianWAF Team

---

## Context

[Why this decision was needed]

## Decision

[What was decided, with architecture diagrams and config examples]

## Consequences

### Positive
- ...

### Negative
- ...

## Implementation Locations

| File | Purpose |
|------|---------|
| `path/to/file.go` | Description |

## References

- [Link](url)
```

Number sequentially. File naming: `NNNN-kebab-case-title.md`.
