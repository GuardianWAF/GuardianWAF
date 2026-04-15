# ADR 0016: Real-Time ML Anomaly Detection

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF's current detection stack is entirely signature-based: regex patterns, OWASP CRS rules, and static scoring thresholds. This approach works well for known attack patterns but has a fundamental blind spot — **zero-day attacks and novel payloads** that share no syntactic similarity with known signatures.

Problems with the current approach:
- A crafted payload that avoids known patterns passes all detectors even if behaviorally anomalous
- No per-tenant baseline: normal traffic for one application may look malicious for another
- Scoring relies on human-tuned thresholds, not data-driven boundaries
- No temporal awareness — a slow-moving brute force spread over hours is invisible

Signal Sciences, open-appsec, and modern cloud WAFs all offer ML-based anomaly detection as a differentiator. GuardianWAF needs this to compete.

## Decision

Implement a real-time ML anomaly detection layer using **ONNX Runtime** via Go bindings. The model runs as a pipeline layer (Order 475, between DLP and Bot Detection) and adds an anomaly score to the request's `ScoreAccumulator`.

### Model Selection

| Model | Pros | Cons | Decision |
|-------|------|------|----------|
| Isolation Forest | Unsupervised, no labels needed, fast | Lower accuracy on structured attacks | **Primary** |
| One-Class SVM | Strong boundary learning | Slow training, memory-heavy | Fallback |
| Autoencoder (ONNX) | High accuracy, latent space | Requires GPU training | Future |

**Selected: Isolation Forest exported to ONNX**, running via `onnxruntime-go` bindings.

### Feature Extraction

Each request is converted to a fixed-length numeric feature vector before inference:

```
Feature Vector (32 dimensions):
  Request shape:
    [0]  Path length (normalized)
    [1]  Query string length (normalized)
    [2]  Body length (normalized)
    [3]  Number of query parameters
    [4]  Number of headers
    [5]  Body entropy (Shannon)
    [6]  Path entropy

  Token distribution:
    [7]  Ratio of special chars in path (%,<,>,',",;,(),[],{})
    [8]  Ratio of special chars in query
    [9]  Ratio of special chars in body
    [10] Ratio of numeric chars in body
    [11] Ratio of alphabetic chars in body

  Method & protocol:
    [12] HTTP method (one-hot: GET=0, POST=1, PUT=2, DELETE=3, other=4)
    [13] HTTP version (1.0=0, 1.1=1, 2=2, 3=3)
    [14] Has body flag (0/1)
    [15] Content-Type category (none=0, json=1, form=2, xml=3, multipart=4, other=5)

  Header anomalies:
    [16] User-Agent length (normalized)
    [17] User-Agent entropy
    [18] Accept-Language present (0/1)
    [19] Number of non-standard headers
    [20] Cookie count

  Path structure:
    [21] Path segment count
    [22] Path traversal depth (normalized)
    [23] Has file extension (0/1)
    [24] Extension category (none=0, php=1, asp=2, js=3, other=4)

  Existing scores (cross-layer context):
    [25] Normalized cumulative WAF score from prior layers
    [26] Bot detection pre-score (0/1 flag)
    [27] GeoIP risk score (normalized)

  Time-based (per-IP sliding window):
    [28] Request rate last 10s (normalized)
    [29] Unique path count last 60s (normalized)
    [30] Error rate last 60s (normalized)
    [31] Payload size variance last 10 requests
```

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       Pipeline (Order 475)                        │
│                                                                   │
│  RequestContext                                                   │
│       │                                                           │
│       ▼                                                           │
│  ┌──────────────────┐                                            │
│  │ Feature Extractor │  (32-dim float32 vector, ~500ns)          │
│  └────────┬─────────┘                                            │
│           │                                                       │
│           ▼                                                       │
│  ┌──────────────────┐                                            │
│  │  ONNX Runtime    │  (Isolation Forest, ~200µs inference)      │
│  │  (onnxruntime-go)│                                            │
│  └────────┬─────────┘                                            │
│           │  anomaly_score: 0.0–1.0                              │
│           ▼                                                       │
│  ┌──────────────────┐                                            │
│  │ ScoreAccumulator │  score += anomaly_score * multiplier        │
│  └──────────────────┘                                            │
└─────────────────────────────────────────────────────────────────┘
```

### Per-Tenant Baselining

Each tenant trains its own model from a 7-day traffic sample, captured as background goroutines write feature vectors to a rolling JSONL file. The training pipeline runs offline (Python + scikit-learn → ONNX export), and the resulting `.onnx` file is hot-reloaded per tenant.

### Configuration

```yaml
ml:
  enabled: true
  model_path: /var/lib/guardianwaf/models/anomaly.onnx
  score_multiplier: 0.8          # Scale anomaly score before adding to WAF score
  min_anomaly_threshold: 0.6     # Below this, anomaly is ignored
  fallback_on_error: pass        # pass | block | log
  latency_budget_ms: 2           # Skip inference if prior layers took too long

  per_tenant:
    enabled: true
    model_dir: /var/lib/guardianwaf/models/tenants/
    fallback_to_global: true     # Use global model if tenant model missing

  training:
    auto_collect: true           # Collect feature vectors for training data
    collect_dir: /var/lib/guardianwaf/training/
    sample_rate: 0.01            # Sample 1% of requests
```

### Latency Budget

| Phase | P50 | P99 | Budget |
|-------|-----|-----|--------|
| Feature extraction | 200µs | 800µs | 1ms |
| ONNX inference | 150µs | 600µs | 1ms |
| Score integration | <10µs | <10µs | — |
| **Total overhead** | **~350µs** | **~1.4ms** | **2ms** |

Inference is **skipped** if the request has already been blocked by an earlier layer.

## Consequences

### Positive
- Zero-day and novel payload detection without signature updates
- Per-tenant baseline eliminates false positives from legitimate edge-case traffic
- No dependency on labeled data — Isolation Forest is unsupervised
- ONNX format is vendor-neutral; models can be retrained with any ML framework

### Negative
- ONNX Runtime introduces a native shared library dependency (breaks pure-Go binary)
- Model training requires a Python pipeline and labeled-clean traffic corpus
- Cold start problem: no model available until enough traffic is collected
- Additional ~350µs latency per request (acceptable within 2ms budget)

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/ml/onnx/model.go` | ONNX Runtime wrapper, session management |
| `internal/ml/onnx/features.go` | Feature extraction from `RequestContext` |
| `internal/layers/anomaly/layer.go` | Pipeline layer (Order 475) |
| `internal/layers/anomaly/sliding_window.go` | Per-IP time-based feature computation |
| `scripts/train_model.py` | Offline training script (scikit-learn → ONNX) |
| `internal/config/config.go` | `MLConfig` struct addition |

## References

- [ONNX Runtime Go Bindings](https://github.com/yalue/onnxruntime_go)
- [Isolation Forest — scikit-learn](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
- [open-appsec ML Architecture](https://github.com/openappsec/openappsec)
- [GuardianWAF Scoring System](../ARCHITECTURE.md#scoring-system)
- [ADR 0003: Tokenizer-Based Detection](./0003-tokenizer-based-detection.md)
