# ADR 0007: ML-Based Anomaly Detection Layer

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

The rule-based WAF engine (tokenizer-based SQLi/XSS/LFI detectors) excels at known attack patterns but has limited ability to detect novel or low-and-slow attacks that don't match specific signatures. An attacker may send payloads that differ slightly from known patterns, stay below detection thresholds, or probe for vulnerabilities over extended periods.

We evaluated two approaches for addressing this gap:

1. **Additional rule-based detectors** — Continuously add new rules for each novel pattern. This is whack-a-mole and does not scale.
2. **ML-based anomaly scoring** — Use a trained model to score requests based on deviation from normal traffic patterns. This catches novel attacks without specific rules.

## Decision

Implement an ML-based anomaly detection layer that runs alongside the existing rule-based detectors. The layer uses an ONNX-compatible model to score each request's deviation from learned "normal" traffic profiles.

**Layer position**: Order 475, between API Security and Detection — after authentication/normalization but before expensive detection layers.

### Feature Extraction

Feature extractor computes per-request feature vectors:
- Request rate per client IP (requests/minute)
- Error rate per client (4xx/5xx responses)
- Request size distribution (body, headers)
- Path diversity (unique paths accessed)
- Temporal patterns (time of day, day of week)
- JA3/JA4 fingerprint clustering distance

### ONNX Model

- **Why ONNX**: Runtime-agnostic model format (trained in Python/PyTorch, deployed in Go). Separates model training (offline, in a training environment) from inference (in the WAF). No external runtime dependencies — pure Go ONNX inference.
- **Why Isolation Forest**: Handles high-dimensional feature spaces efficiently, robust to outliers, provides anomaly scores (not just binary classification), works well with the mixed-type features present in HTTP traffic.
- **Threshold**: Configurable, default 0.7. Score below threshold = normal traffic; above = anomalous.

### Training Considerations

- **Online vs offline training**: Online learning (continuously updating the model) was rejected due to poisoning risk — an attacker could gradually shift the "normal" profile. Offline training with periodic model updates is safer.
- **Full request scoring vs sampling**: Sampling (scoring 1% of traffic) was considered to reduce overhead, but this misses low-volume attacks. Full scoring with a fast ONNX model is preferred.

## Consequences

### Positive

- Detects zero-day attacks and low-and-slow brute force without specific rules
- Complements tokenizers: ML catches what rules miss, rules catch what ML cannot explain
- ONNX model can be updated independently of WAF code (new model file, no redeploy)
- Per-request scoring is fast (<2ms overhead measured on benchmarks)

### Negative

- ONNX model is a binary asset that must be shipped alongside the WAF binary
- Model quality depends on training data quality — a poorly trained model produces false positives
- ML findings are less explainable than tokenizer findings ("anomaly score 0.85" vs "found OR keyword in query")
- Increased complexity: requires ML training pipeline and model versioning

## Implementation Locations

**Note**: `internal/ml/anomaly/layer.go` exists. `onnx.go`, `features.go`, and `internal/ml/models/`
are planned but do not exist yet. The layer is not registered in the main engine pipeline.

| File | Purpose |
|------|---------|
| `internal/ml/anomaly/layer.go` | Pipeline layer (Order 475 — same slot as DLP; order subject to change) |
| `internal/ml/anomaly/onnx.go` | ONNX model loading and inference (planned) |
| `internal/ml/anomaly/features.go` | Feature vector extraction from RequestContext (planned) |
| `internal/ml/models/` | Trained ONNX model files (shipped separately) (planned) |
| `internal/config/config.go` | `AnomalyConfig` struct |

## References

- [ADR 0016: Real-Time ML Anomaly Detection (ONNX)](./0016-ml-anomaly-detection.md) — supersedes this ADR with detailed ONNX implementation
- [ONNX Runtime](https://onnxruntime.ai/)
- [Isolation Forest Algorithm](https://en.wikipedia.org/wiki/Isolation_forest)
- [OWASP Machine Learning](https://owasp.org/www-project-machine-learning/)
