# GuardianWAF Documentation

Complete documentation index for GuardianWAF — the zero-dependency, embeddable Web Application Firewall.

---

## Getting Started

| Document | Description |
|----------|-------------|
| [README](../README.md) | Project overview, quick start, feature list |
| [Getting Started](getting-started.md) | Installation, three deployment modes, first run |
| [Configuration](configuration.md) | Full YAML schema, environment variables, CLI flags |
| [Deployment Modes](deployment-modes.md) | Reverse proxy, sidecar, inline — same engine, different topologies |
| [Architecture](ARCHITECTURE.md) | System architecture with Mermaid diagrams, subsystem overview |

## Operations

| Document | Description |
|----------|-------------|
| [Production Deployment](production-deployment.md) | Production best practices, reverse proxy integration, TLS |
| [Clustering & HA](clustering.md) | Multi-node cluster setup, gossip peer discovery, Raft replication, leader redirect, observability |
| [Metrics & Monitoring](metrics.md) | Prometheus metrics reference, scraping config, tracing setup |
| [Health Probes](health-probes.md) | `/livez`, `/readyz`, `/healthz` — liveness and readiness endpoints |
| [Runtime Reload](runtime-reload.md) | Which config fields are hot-reloadable and which require restart |
| [State Persistence](state-persistence.md) | Persistence model, what survives restarts, fail-fast stores |
| [Config Profiles](config-profiles.md) | Validated starter profiles under `examples/profiles/` |

## Detection & Protection

| Document | Description |
|----------|-------------|
| [Detection Engine](detection-engine.md) | Tokenizer-based scoring, attack pattern databases, how scoring works |
| [Tuning Guide](tuning-guide.md) | Reducing false positives, adjusting thresholds, profile tuning |
| [API Reference](api.md) | REST API endpoints for stats, events, config, cluster management |
| [API Examples](api-examples.md) | Concrete curl examples for common API operations |
| [AI Analysis](ai-analysis.md) | AI-powered batch threat analysis and log interpretation |

## Reliability

| Document | Description |
|----------|-------------|
| [Security Best Practices](security-best-practices.md) | Hardening GuardianWAF deployments |
| [Threat Model](threat-model.md) | Production threat model, attack surfaces, mitigations |
| [Incident Response](incident-response.md) | Incident classification, investigation, containment |
| [Runbook](runbook.md) | Step-by-step troubleshooting runbook |
| [Troubleshooting FAQ](troubleshooting-faq.md) | Common issues and solutions |
| [SLOs](slo.md) | Service-level objectives and measurement |
| [Performance Budget](performance-budget.md) | Release performance budgets and benchmark evidence |

## Integrations

| Resource | Description |
|----------|-------------|
| [Grafana Dashboards](../contrib/grafana/README.md) | Pre-built dashboards: WAF overview + cluster monitoring |
| [Grafana: WAF Dashboard](../contrib/grafana/dashboard.json) | Request volume, blocked/challenged rates, latency, detector scores |
| [Grafana: Cluster Dashboard](../contrib/grafana/cluster-dashboard.json) | Member count, Raft term, replication lag, store stats |
| [Prometheus Alert Rules](../contrib/prometheus/README.md) | Pre-configured alerting rules for WAF and cluster health |
| [Kubernetes Deployment](../contrib/k8s/README.md) | K8s manifests, Helm chart, StatefulSet for cluster mode |

## Development

| Document | Description |
|----------|-------------|
| [Contributing](../CONTRIBUTING.md) | How to contribute, code style, PR process |
| [Security Policy](../SECURITY.md) | Vulnerability reporting, supported versions |
| [Architecture Decision Records](adr/README.md) | 43 design decisions covering every major subsystem |

## Architecture Decision Records

### Core Architecture

| ADR | Title |
|-----|-------|
| [0001](adr/0001-zero-external-dependencies.md) | Zero External Go Dependencies |
| [0002](adr/0002-custom-yaml-parser.md) | Custom YAML Parser |
| [0004](adr/0004-pipeline-architecture.md) | Pipeline Architecture |
| [0040](adr/0040-feature-flags.md) | Config-Driven Feature Flags |

### Detection & Protection

| ADR | Title |
|-----|-------|
| [0003](adr/0003-tokenizer-based-detection.md) | Tokenizer-Based Detection |
| [0007](adr/0007-ml-anomaly-detection.md) | ML-Based Anomaly Detection Layer |
| [0016](adr/0016-ml-anomaly-detection.md) | Real-Time ML Anomaly Detection |
| [0017](adr/0017-api-discovery-schema-validation.md) | API Discovery & Schema Validation |
| [0020](adr/0020-advanced-dlp.md) | Advanced Data Loss Prevention (DLP) |
| [0022](adr/0022-compliance-reporting.md) | Compliance & Reporting Framework |
| [0032](adr/0032-owasp-crs-integration.md) | OWASP Core Rule Set Integration |
| [0033](adr/0033-request-sanitizer.md) | Request Sanitizer |
| [0034](adr/0034-threat-intelligence.md) | Threat Intelligence Layer |

### Access Control & Rate Limiting

| ADR | Title |
|-----|-------|
| [0028](adr/0028-ip-acl-radix-tree.md) | IP ACL with Radix Tree |
| [0029](adr/0029-rate-limiting-token-bucket.md) | Rate Limiting with Token Bucket |
| [0030](adr/0030-ato-protection.md) | Account Takeover Protection |
| [0031](adr/0031-cors-layer.md) | CORS Validation Layer |

### Clustering & Distributed

| ADR | Title |
|-----|-------|
| [0023](adr/0023-high-availability-raft.md) | High Availability with Raft Consensus |
| [0011](adr/0011-ip-reputation-sharing.md) | IP Reputation Sharing |
| [0013](adr/0013-multi-region-support.md) | Multi-Region Support |
| [0015](adr/0015-distributed-event-store.md) | Distributed Event Store |
| [0024](adr/0024-zero-trust-network-access.md) | Zero Trust Network Access (ZTNA) |

### Protocol & Proxy

| ADR | Title |
|-----|-------|
| [0019](adr/0019-grpc-protocol-support.md) | gRPC Protocol Support |
| [0035](adr/0035-websocket-proxy.md) | WebSocket Proxy |

### Security & Hardening

| ADR | Title |
|-----|-------|
| [0014](adr/0014-wasm-sandbox.md) | WebAssembly Sandbox for Rule Evaluation |
| [0021](adr/0021-client-side-protection.md) | Client-Side Protection (RASP-lite) |
| [0043](adr/0043-api-key-hardening.md) | API Key Hashing Upgrade |

### Observability

| ADR | Title |
|-----|-------|
| [0009](adr/0009-opentelemetry-integration.md) | OpenTelemetry Integration |
| [0025](adr/0025-siem-integration.md) | SIEM Integration |
| [0039](adr/0039-distributed-tracing.md) | Zero-Dependency Distributed Tracing |
| [0042](adr/0042-correlation-id-propagation.md) | Correlation ID Propagation |

### Management & Operations

| ADR | Title |
|-----|-------|
| [0005](adr/0005-react-dashboard.md) | React Dashboard with Go Embed |
| [0006](adr/0006-multi-tenant-isolation.md) | Multi-Tenant Isolation |
| [0008](adr/0008-ai-batch-analysis.md) | AI Batch Threat Analysis |
| [0010](adr/0010-dynamic-rules-api.md) | Dynamic Rule Updates via API |
| [0027](adr/0027-virtual-patching-nvd.md) | Virtual Patching with NVD Integration |
| [0037](adr/0037-request-replay.md) | Request Recording and Replay |

### Performance & Caching

| ADR | Title |
|-----|-------|
| [0026](adr/0026-response-caching-layer.md) | Response Caching Layer |
| [0038](adr/0038-response-layer.md) | Response Protection Layer |

### Bot Management & Threat Intel

| ADR | Title |
|-----|-------|
| [0018](adr/0018-enhanced-bot-management.md) | Enhanced Bot Management |
| [0012](adr/0012-graphql-protection.md) | Enhanced GraphQL Protection |

### Infrastructure

| ADR | Title |
|-----|-------|
| [0036](adr/0036-canary-deployments.md) | Canary Deployment Layer |
| [0041](adr/0041-log-rotation.md) | Log Rotation and File Writer |
