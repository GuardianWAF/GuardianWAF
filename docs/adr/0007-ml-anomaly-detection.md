# ADR 007: ML-Based Anomaly Detection Layer

## Status: Accepted

## Context

The rule-based WAF engine (tokenizer-based SQLi/XSS/LFI detectors) excels at known attack patterns but has limited ability to detect novel or low-and-slow attacks that don't match specific signatures. An attacker may send payloads that differ slightly from known patterns, stay below detection thresholds, or probe for vulnerabilities over extended periods.

We evaluated two approaches for addressing this gap:

1. **Additional rule-based detectors** — Continuously add new rules for each novel pattern. This is whack-a-mole and doesn't scale.
2. **ML-based anomaly scoring** — Use a trained model to score requests based on deviation from normal traffic patterns. This catches novel attacks without specific rules.

## Decision

Implement an ML-based anomaly detection layer (`internal/ml/anomaly/`) that runs alongside the existing rule-based detectors. The layer uses an ONNX-compatible model to score each request's deviation from learned "normal" traffic profiles.

**Layer position**: Order 475, between API Security and Sanitizer — after authentication/normalization but before expensive detection layers.

**Architecture**:
- Feature extractor (`internal/ml/features/`) computes per-request feature vectors:
  - Request rate per client IP (requests/minute)
  - Error rate per client (4xx/5xx responses)
  - Request size distribution (body, headers)
  - Path diversity (unique paths accessed)
  - Temporal patterns (time of day, day of week)
  - JA3/JA4 fingerprint clustering distance
- ONNX model (`internal/ml/onnx/`) evaluates the feature vector against a trained anomaly detector
- Anomaly score is added to the WAF score accumulator (configurable weight)
- Layer produces findings with `anomaly_detector` name

**Why ONNX**:
- Runtime-agnostic model format (trained in Python/PyTorch, deployed in Go)
- No external runtime dependencies in the WAF binary (ONNX inference is pure Go via `internal/ml/onnx/`)
- Separates model training (offline, in a training environment) from inference (in the WAF)

**Threshold**: Configurable, default 0.7. Score below threshold = normal traffic; above = anomalous.

## Consequences

**Positive**:
- Detects zero-day attacks and low-and-slow brute force without specific rules
- Complements tokenizers: ML catches what rules miss, rules catch what ML can't explain
- ONNX model can be updated independently of WAF code (new model file, no redeploy)
- Per-request scoring is fast (<1ms overhead measured on benchmarks)

**Negative**:
- ONNX model is a binary asset that must be shipped alongside the WAF binary
- Model quality depends on training data quality — a poorly trained model produces false positives
- ML findings are less explainable than tokenizer findings ("anomaly score 0.85" vs "found OR keyword in query")
- Increased complexity: requires ML training pipeline and model versioning
- ONNX inference code adds ~300 lines to the codebase

**Trade-offs considered**:
- **ONNX vs custom Go inference**: Rejected custom Go inference because implementing matrix operations from scratch is error-prone and hard to optimize. ONNX provides a well-tested inference engine.
- **Online vs offline training**: Online learning (continuously updating the model) was rejected due to poisoning risk — an attacker could gradually shift the "normal" profile. Offline training with periodic model updates is safer.
- **Full request scoring vs sampling**: Sampling (scoring 1% of traffic) was considered to reduce overhead, but this misses low-volume attacks. Full scoring with a fast ONNX model is preferred.

## Alternatives Considered

- **Isolation Forest**: Rejected — less mature ONNX support, harder to explain scores
- **One-class SVM**: Rejected — poor scalability for high-throughput WAF traffic
- **Rule-only approach**: Rejected — cannot detect novel attack patterns without constant rule maintenance
- **External ML service**: Rejected — adds network dependency and latency, violates zero-external-dependency constraint

## Implementation Notes

The anomaly layer is currently **functional but not enabled by default** (`Enabled: false` in default config). To enable:

```yaml
waf:
  anomaly_detection:
    enabled: true
    model_path: "models/anomaly.onnx"
    threshold: 0.7
```

Training a production model requires:
1. Collecting representative traffic (benign + attack samples)
2. Feature extraction using `features.Extractor`
3. Training in PyTorch/scikit-learn
4. Exporting to ONNX format
5. Validating precision/recall before deployment
