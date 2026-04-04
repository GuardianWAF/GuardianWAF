# GuardianWAF v0.4.0 - v1.0.0 Roadmap

Strategic roadmap to position GuardianWAF as a Signal Sciences/CloudFlare alternative.

---

## Phase 1: Foundation (v0.4.0) - Q2 2026
**Goal:** Close critical gaps (ML Detection, API Security)
**Duration:** 8-10 weeks
**Priority:** 🔴 Critical

### 1.1 Real-time ML Anomaly Detection
**Why:** Zero-day protection, differentiate from signature-based WAFs
**Competitor:** Signal Sciences, open-appsec

```yaml
Technical Approach:
  Model: Isolation Forest / One-Class SVM
  Format: ONNX Runtime (Go bindings)
  Latency Budget: < 1ms per request
  Features:
    - Request path entropy
    - Parameter count/anomaly
    - Header patterns
    - Body structure
    - Time-based patterns
    - IP reputation score
  
Implementation:
  - internal/ml/onnx/
    - model.go          # ONNX model wrapper
    - features.go       # Feature extraction
    - anomaly.go        # Anomaly detector layer
    
  - Model training:
    - scripts/train_model.py
    - Dataset: HTTP request corpus
    - Export to ONNX format
```

**Tasks:**
- [ ] Research ONNX Go bindings (onnxruntime-go)
- [ ] Design feature extraction pipeline
- [ ] Implement baseline model (Isolation Forest)
- [ ] Create model training pipeline
- [ ] Add per-request inference (layer 475)
- [ ] Benchmark: < 1ms latency
- [ ] Update dashboard: Anomaly score display
- [ ] Tests: 95% coverage

**Estimated Effort:** 3-4 weeks
**Dependencies:** None

---

### 1.2 API Discovery & Schema Validation
**Why:** Shadow API detection, prevent API abuse
**Competitor:** Signal Sciences API Discovery

```yaml
Technical Approach:
  Discovery:
    - Passive traffic analysis
    - Endpoint clustering (path similarity)
    - Method distribution tracking
    - Parameter extraction
    - Response code analysis
    
  Schema Validation:
    - OpenAPI 3.0 import/export
    - JSON Schema validation
    - Request/response body validation
    - Custom rule generation from schema
    
Storage:
  - api_inventory/     # Discovered endpoints
    - endpoints.json
    - schemas/
      - users.openapi.json
      - orders.openapi.json
```

**Tasks:**
- [ ] Implement traffic analyzer (background goroutine)
- [ ] Design endpoint clustering algorithm
- [ ] Create OpenAPI parser/generator
- [ ] Add schema validation middleware
- [ ] Dashboard: API inventory page
- [ ] MCP tools: api_discovery_get, api_schema_validate
- [ ] Export discovered schema to OpenAPI
- [ ] Tests: 90% coverage

**Estimated Effort:** 3-4 weeks
**Dependencies:** None

---

### 1.3 GraphQL Security
**Why:** Modern APIs use GraphQL, specific vulnerabilities
**Competitor:** AWS WAF, CloudFlare

```yaml
Technical Approach:
  Detection:
    - Query depth analysis
    - Complexity scoring (field cost)
    - Introspection detection
    - Batching abuse detection
    - Alias abuse detection
    - Directive injection detection
    
  Protection:
    - Max depth enforcement
    - Max complexity enforcement
    - Allow-list introspection
    - Query allow-list (persisted queries)
    
Integration:
  Layer: 450 (between API Security and Sanitizer)
```

**Tasks:**
- [ ] GraphQL query parser
- [ ] Depth/complexity calculator
- [ ] Add graphql layer (internal/layers/graphql/)
- [ ] Configuration: depth_limit, complexity_limit
- [ ] Dashboard: GraphQL-specific events
- [ ] Tests: Query samples, edge cases

**Estimated Effort:** 2 weeks
**Dependencies:** None

---

### 1.4 Enhanced Bot Management
**Why:** Improve bot detection beyond JA3/JA4
**Competitor:** CloudFlare Bot Management

```yaml
Technical Approach:
  Biometric Analysis:
    - Mouse movement tracking (JS)
    - Keystroke dynamics
    - Scroll patterns
    - Touch events (mobile)
    
  CAPTCHA Integration:
    - hCaptcha provider
    - CloudFlare Turnstile
    - Invisible challenge
    
  Fingerprinting:
    - Canvas fingerprinting
    - WebGL fingerprinting
    - Font enumeration
    - WebRTC leak detection
    
  Classification:
    - Good bots (Google, Bing)
    - Suspicious automation
    - Known bad bots
```

**Tasks:**
- [ ] Integrate hCaptcha/Turnstile
- [ ] Create JS biometric collector
- [ ] Add fingerprinting endpoints
- [ ] Bot category classification
- [ ] Dashboard: Bot analytics
- [ ] Tests: Bot simulation

**Estimated Effort:** 2-3 weeks
**Dependencies:** None

---

## Phase 2: Enterprise Features (v0.5.0) - Q3 2026
**Goal:** Enterprise readiness (Multi-tenancy, Protocols)
**Duration:** 10-12 weeks
**Priority:** 🟡 High

### 2.1 gRPC Support
**Why:** Microservices communication, modern protocols
**Competitor:** AWS WAF, F5

```yaml
Technical Approach:
  Protocol Support:
    - HTTP/2 with gRPC framing
    - Protocol Buffers parsing
    - gRPC reflection support
    - Method-level routing
    
  Security:
    - Message size limits
    - Method allow-list
    - Metadata inspection
    - Streaming abuse detection
    
Implementation:
  - internal/protocols/grpc/
    - server.go          # gRPC proxy
    - codec.go           # Protobuf handling
    - interceptor.go     # Security checks
```

**Tasks:**
- [ ] gRPC frame parser
- [ ] HTTP/2 stream management
- [ ] Add gRPC proxy mode
- [ ] Method routing
- [ ] Message size enforcement
- [ ] Dashboard: gRPC metrics
- [ ] Tests: gRPC client/server

**Estimated Effort:** 3-4 weeks
**Dependencies:** HTTP/2 improvements

---

### 2.2 Multi-Tenancy
**Why:** MSSP support, SaaS offering
**Competitor:** Imperva, CloudFlare

```yaml
Technical Approach:
  Isolation:
    - Namespace-based isolation
    - Per-tenant config
    - Per-tenant event storage
    - Per-tenant rate limits
    
  Routing:
    - Tenant identification (header/subdomain)
    - Tenant-specific rules
    - Shared vs dedicated resources
    
  Management:
    - Tenant CRUD API
    - Resource quotas
    - Billing metrics
    
Implementation:
  - internal/tenant/
    - manager.go
    - context.go
    - quota.go
```

**Tasks:**
- [ ] Design tenant isolation model
- [ ] Implement tenant context
- [ ] Add tenant management API
- [ ] Resource quotas per tenant
- [ ] Dashboard: Tenant selector
- [ ] MCP tools: tenant management
- [ ] Tests: Tenant isolation

**Estimated Effort:** 4 weeks
**Dependencies:** None

---

### 2.3 Advanced DLP (Data Loss Prevention)
**Why:** PII/PCI compliance, data leak prevention
**Competitor:** Imperva, F5

```yaml
Technical Approach:
  Pattern Matching:
    - Custom regex patterns
    - Predefined patterns (PCI, PII, HIPAA)
    - Luhn algorithm validation (credit cards)
    - Keyword matching
    
  Content Inspection:
    - Request body inspection
    - Response body inspection
    - File upload scanning
    - Structured data detection (JSON/XML)
    
  Actions:
    - Block
    - Mask (partial redaction)
    - Encrypt
    - Log only
    - Alert
    
  Patterns:
    - credit_card: Luhn check
    - ssn_us: "XXX-XX-XXXX"
    - email: RFC 5322
    - phone_international: E.164
    - turkish_tc: 11 digits, checksum
    - custom: User-defined regex
```

**Tasks:**
- [ ] Pattern engine
- [ ] Predefined pattern library
- [ ] Request/response inspection
- [ ] Masking/encryption actions
- [ ] Dashboard: DLP events
- [ ] Compliance reporting
- [ ] Tests: Pattern accuracy

**Estimated Effort:** 3 weeks
**Dependencies:** None

---

### 2.4 Client-Side Protection (RASP-lite)
**Why:** Magecart, formjacking protection
**Competitor:** Sucuri, Imperva

```yaml
Technical Approach:
  JavaScript Injection:
    - Automatic JS agent injection
    - DOM monitoring
    - Form field protection
    - Event listener tampering detection
    
  Detection:
    - Unauthorized script injection
    - Skimming detection
    - Keylogger detection
    - Iframe sandbox violations
    
  Reporting:
    - Client-side events to server
    - CSP violation reporting
```

**Tasks:**
- [ ] JS agent development
- [ ] Response rewriting for injection
- [ ] Client-side event collection
- [ ] Skimming detection rules
- [ ] Dashboard: Client-side events
- [ ] Tests: JS injection scenarios

**Estimated Effort:** 3 weeks
**Dependencies:** Response layer modifications

---

## Phase 3: Scale & Compliance (v1.0.0) - Q4 2026
**Goal:** Enterprise readiness, compliance certifications
**Duration:** 8-10 weeks
**Priority:** 🟢 Medium

### 3.1 HTTP/3 (QUIC) Support
**Why:** Modern protocol, performance
**Competitor:** CloudFlare, F5

```yaml
Technical Approach:
  Protocol:
    - QUIC implementation (quic-go)
    - HTTP/3 framing
    - 0-RTT support
    - Connection migration
    
  Integration:
    - UDP listener
    - ALPN negotiation
    - Fallback to HTTP/2
```

**Tasks:**
- [ ] Integrate quic-go
- [ ] UDP listener
- [ ] HTTP/3 request handling
- [ ] Performance benchmarking
- [ ] Tests: QUIC protocol

**Estimated Effort:** 3 weeks
**Dependencies:** None

---

### 3.2 Compliance & Reporting
**Why:** Enterprise requirement, audit support
**Competitor:** Imperva, F5

```yaml
Technical Approach:
  Compliance:
    - PCI DSS reports
    - GDPR data mapping
    - SOC2 controls
    - ISO 27001 mapping
    
  Reporting:
    - Automated compliance reports
    - Audit trail export
    - Data retention policies
    - Evidence collection
```

**Tasks:**
- [ ] Compliance framework
- [ ] PCI DSS report generator
- [ ] GDPR data inventory
- [ ] Audit trail export
- [ ] Dashboard: Compliance status
- [ ] Scheduled report generation

**Estimated Effort:** 3 weeks
**Dependencies:** Event storage enhancements

---

### 3.3 High Availability
**Why:** Production reliability
**Competitor:** All enterprise WAFs

```yaml
Technical Approach:
  Clustering:
    - Leader election (Raft/consul)
    - State synchronization (Redis/etcd)
    - Shared event storage
    - Config synchronization
    
  Failover:
    - Health checks
    - Automatic failover
    - Session affinity
    
Implementation:
  - internal/cluster/
    - raft.go
    - sync.go
    - leader.go
```

**Tasks:**
- [ ] Raft consensus implementation
- [ ] State sync mechanism
- [ ] Redis/etcd backend
- [ ] Health check improvements
- [ ] Documentation: HA setup
- [ ] Tests: Failover scenarios

**Estimated Effort:** 4 weeks
**Dependencies:** Redis/etcd optional dependency

---

## Implementation Timeline

```
2026 Q2 (v0.4.0)                    2026 Q3 (v0.5.0)                   2026 Q4 (v1.0.0)
├─ Real-time ML    [████████]      ├─ gRPC Support    [████████]      ├─ HTTP/3 QUIC     [████]
├─ API Discovery   [████████]      ├─ Multi-tenancy   [████████]      ├─ Compliance      [████]
├─ GraphQL         [████]          ├─ Advanced DLP    [██████]        └─ High Availability[██████]
└─ Bot Mgmt v2     [██████]        └─ Client-side     [██████]

Total: 24-26 weeks (6 months)
```

---

## Resource Requirements

### Development Team

| Phase | Backend | ML/Security | Frontend | QA/DevOps |
|-------|---------|-------------|----------|-----------|
| v0.4.0 | 2 devs  | 1 dev       | 1 dev    | 1 dev     |
| v0.5.0 | 2 devs  | 1 dev       | 1 dev    | 1 dev     |
| v1.0.0 | 2 devs  | -           | 1 dev    | 1 dev     |

### Infrastructure

```yaml
Testing:
  - Load testing cluster (k6/locust)
  - ML training environment
  - Multi-region test setup
  
CI/CD:
  - GPU runners for ML tests
  - Security scanning (SAST/DAST)
  - Performance benchmarking
```

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| ML model accuracy low | Medium | High | A/B testing, gradual rollout |
| Performance regression | Medium | High | Benchmarking, profiling |
| Dependency conflicts | Low | Medium | Vendor packages isolation |
| Scope creep | High | Medium | Strict sprint planning |

---

## Success Metrics

### Technical Metrics

| Metric | Current | v0.4.0 | v0.5.0 | v1.0.0 |
|--------|---------|--------|--------|--------|
| Detection Accuracy | 85% | 92% | 95% | 97% |
| False Positive Rate | 5% | 3% | 2% | 1% |
| Latency (p99) | <1ms | <2ms | <3ms | <3ms |
| Throughput | 5K RPS | 10K RPS | 20K RPS | 50K RPS |
| Test Coverage | 91% | 93% | 94% | 95% |

### Business Metrics

| Metric | Target |
|--------|--------|
| GitHub Stars | 5,000+ |
| Docker Pulls | 1M+ |
| Enterprise Customers | 10+ |
| Community Contributors | 50+ |

---

## Next Steps

1. **Immediate (This Week):**
   - [ ] Finalize v0.4.0 scope
   - [ ] Create GitHub milestones
   - [ ] Assign initial tasks
   - [ ] Set up ML training environment

2. **Short-term (Next 2 weeks):**
   - [ ] Begin ML research (ONNX Go)
   - [ ] Design API Discovery architecture
   - [ ] Create proof-of-concepts

3. **Ongoing:**
   - [ ] Weekly progress reviews
   - [ ] Monthly competitor analysis
   - [ ] Quarterly roadmap updates

---

*Document Version: 1.0*
*Last Updated: 2026-04-04*
