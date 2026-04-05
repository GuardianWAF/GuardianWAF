## [1.0.0] - 2026-04-05

### Production Release

#### Critical Fixes
- **Cluster Package Mutex Fix**
  - Fixed sync.RWMutex copying undefined behavior
  - Resolved deadlock in handleJoin and startLeaderElection
  - Added StateSyncData struct with Clone() method for safe copying

- **GraphQL Parser Fix**
  - Fixed alias parsing with parentheses (e.g., `__type(name: "User")`)
  - Fixed depth calculation to start from 1 instead of 0

- **WebSocket Pattern Matching**
  - Fixed flaky test with ordered slice pattern matching
  - Ensured deterministic pattern detection order

#### Infrastructure
- **Kubernetes Support**
  - Added production-ready Kubernetes manifests
  - Deployment with 2 replicas, security contexts, health probes
  - ConfigMap for WAF configuration
  - Service and Ingress with dashboard auth
  - Comprehensive deployment documentation

- **Monitoring**
  - Added Grafana production dashboard (25+ panels)
  - Request rate, block rate, P99 latency metrics
  - Detection performance per detector
  - Geographic distribution map
  - AI analysis queue and cost tracking

#### Documentation
- Updated README with production deployment section
- Added PRODUCTION_READINESS_SUMMARY.md

---

## [0.4.0] - 2026-04-04

### Added

#### Phase 1: ML Anomaly, API Discovery, GraphQL Security, Enhanced Bot Management

- **ML Anomaly Detection Layer**
  - Unsupervised ML-based anomaly detection
  - Real-time behavioral analysis
  - Configurable thresholds and auto-blocking
  - Feature extraction from requests

- **API Discovery Engine**
  - Automatic API endpoint discovery
  - Passive traffic analysis
  - OpenAPI spec generation and export
  - Real-time endpoint statistics
  - JSON and OpenAPI export formats

- **GraphQL Security Layer**
  - Query depth limiting (configurable max depth)
  - Complexity analysis and scoring
  - Introspection blocking
  - Endpoint allowlisting

- **Enhanced Bot Detection**
  - hCaptcha/Turnstile integration
  - Biometric behavioral analysis
  - Browser fingerprinting (Canvas, WebGL, Fonts)
  - Headless browser detection
  - JavaScript challenge collector

#### Phase 2: gRPC Support, Multi-tenancy, Advanced DLP

- **gRPC/gRPC-Web Proxy**
  - HTTP/2 transport support
  - gRPC-Web bridging for browsers
  - Protocol Buffer validation
  - Method-level access control (ACL)
  - Message size limits

- **Multi-tenancy with Namespace Isolation**
  - Tenant CRUD operations
  - Domain-based and API key resolution
  - Resource quotas per tenant:
    - Max requests per minute/hour
    - Bandwidth limits
    - Max rules, rate limits, IP ACLs
  - Usage tracking (requests, bytes, blocked)
  - Wildcard domain support (*.example.com)
  - Context-based tenant propagation
  - REST API: `/api/v1/tenants/*`

- **Advanced DLP (Data Loss Prevention)**
  - Pattern detection for:
    - Credit Cards (Visa, MasterCard, Amex, Discover, JCB, Diners)
    - US Social Security Numbers (SSN)
    - IBAN (International Bank Account Numbers)
    - Email addresses
    - Phone numbers
    - API Keys and tokens
    - Private Keys (RSA, EC, DSA)
    - Passport numbers
    - Tax IDs (EIN)
  - Request/response body scanning
  - Automatic PII masking
  - Risk scoring per pattern
  - Custom pattern support

#### Integration

- **v0.4.0 Feature Integrator** (`internal/integrations/v040`)
  - Unified initialization for all v0.4.0 features
  - Layer registration with proper ordering:
    - 450: GraphQL Security
    - 475: ML Anomaly Detection
    - 500: Enhanced Bot Detection
    - 550: Advanced DLP
  - HTTP handler registration
  - Statistics aggregation

### Changed

- Layer order system updated for new Phase 1 & 2 layers
- Dashboard API extended with tenant management endpoints
- Configuration schema extended:
  - `WAF.MLAnomaly`
  - `WAF.APIDiscovery`
  - `WAF.GraphQL`
  - `WAF.GRPC`
  - `WAF.Tenant`
  - `WAF.DLP`
  - `WAF.ZeroTrust`
  - `WAF.SIEM`
  - `WAF.Cache`
  - `WAF.Replay`
  - `WAF.Canary`

#### Phase 3: Zero Trust, SIEM, Advanced Caching, Request Replay, Canary Releases

- **Zero Trust Network Access (ZTNA)**
  - mTLS client certificate verification
  - Device attestation with 5 trust levels
  - Session-based authentication with TTL
  - Certificate revocation checking
  - Zero Trust middleware

- **SIEM Integration**
  - 6 export formats: CEF, LEEF, JSON, Syslog, Splunk, Elasticsearch
  - Batch export with configurable size and flush interval
  - HTTP/TLS transport support

- **Advanced Caching Layer**
  - Memory (LRU) and Redis backends
  - Configurable TTL and size limits
  - Cache key generation
  - Stale-while-revalidate support

- **Request Replay**
  - HTTP request/response recording
  - JSON and binary format support
  - Replay engine with rate limiting
  - Dry-run mode

- **Canary Releases**
  - 5 routing strategies: percentage, header, cookie, geographic, random
  - Dynamic percentage adjustment
  - Automatic rollback on error/latency thresholds

### Security

- DLP pattern detection prevents data exfiltration
- Multi-tenant isolation prevents cross-tenant data access
- gRPC method ACLs for fine-grained access control
- Enhanced bot detection with biometric analysis

### Testing

- **Phase 1 Tests**: 50+ new test cases
- **Phase 2 Tests**: 47+ new test cases
  - Multi-tenancy: 25 tests
  - gRPC proxy: 12 tests
  - DLP patterns: 22 tests
- Overall test coverage maintained >95%

### Phase 3 Tests

- **Zero Trust**: 15 test cases (mTLS, attestation, sessions)
- **SIEM**: 12 test cases (formatters, exporters)
- **Advanced Caching**: 25 test cases (memory, Redis, layer)
- **Request Replay**: 18 test cases (recorder, replayer, filters)
- **Canary Releases**: 19 test cases (strategies, routing, rollback)

## [0.3.0] - 2026-04-04
