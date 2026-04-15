# ADR 0008: AI Batch Threat Analysis

**Date:** 2026-04-15
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

The rule-based WAF engine detects known attack patterns in real-time. However, correlating attack signals across multiple requests — detecting coordinated campaigns, identifying false positives, and producing threat intelligence summaries — requires analysis that is too expensive and slow for per-request processing.

Making an LLM API call for every WAF event would be:
- **Too slow**: LLM inference adds 1–10 seconds per request, unacceptable for a WAF
- **Too expensive**: At $0.01–0.10 per 1K tokens, real-time scoring costs would be prohibitive
- **Too noisy**: Individual events lack the context needed for accurate verdicts

We needed an approach that provides AI-powered threat intelligence without impacting request latency or breaking the budget.

## Decision

Implement **background batch analysis** (`internal/ai/analyzer.go`): events are collected into batches in memory, then sent to the configured LLM provider periodically or when the batch reaches a configurable size.

### Architecture

```
WAF Pipeline → Event Channel → [Background Analyzer Loop] → LLM API → Verdicts
                                       ↑
                                 Batch of N events
                                 (configurable size, default 20)
```

### Key Design Choices

1. **Background goroutine** (not per-request): The analyzer runs in its own goroutine with a dedicated event channel. The WAF pipeline never blocks on AI analysis — events are queued and processed asynchronously.

2. **Batch composition**: Only events with `score >= MinScoreForAI` (default 25) are analyzed. This filters noise (benign traffic) and focuses AI resources on genuinely suspicious activity.

3. **Batch sizing**: Configurable via `BatchSize` (default 20 events) and `BatchInterval` (default 60 seconds). Batches are flushed when either threshold is reached — whichever comes first.

4. **AI provider abstraction**: `Client` implements an OpenAI-compatible API client. Any provider that speaks the OpenAI chat completions format works. Provider selection uses the models.dev catalog.

5. **Cost controls**: Per-store usage tracking with configurable limits:
   - `MaxTokensHour`: Default 50,000 tokens/hour
   - `MaxTokensDay`: Default 500,000 tokens/day
   - `MaxRequestsHour`: Default 30 requests/hour
   Batches are skipped when limits are exceeded.

6. **Verdict application**: When the AI returns `block` verdicts with confidence >= 70%, the analyzer calls `AddAutoBan` on the IP ACL layer (fire-and-forget, non-blocking). This provides automated response to confirmed attackers.

7. **JSON store persistence**: Analysis results are stored in a JSON file (`ai_analysis.jsonl`) for audit and review. The dashboard exposes this history via `/api/v1/ai/history`.

### Trade-offs Considered

- **Streaming vs batch**: Streaming (process events one-by-one as they arrive) was rejected due to API cost — streaming is billed per-token even for tiny batches. Batch processing amortizes the fixed per-request cost.
- **Synchronous vs async**: Synchronous (wait for AI before accepting next batch) was rejected — it creates backpressure when the AI provider is slow. Async with channel buffering decouples the WAF from AI latency.
- **Verdict caching**: Caching verdicts by IP was considered to avoid re-analyzing the same IP across batches. Rejected for now — batch composition changes over time, and caching adds complexity.

### Configuration

```yaml
ai_analysis:
  enabled: true
  batch_size: 20              # Events per batch
  batch_interval: 60s         # Maximum time between batches
  min_score: 25               # Only analyze events with score >= 25
  auto_block: true            # Auto-ban IPs flagged by AI (confidence >= 70%)
  auto_block_ttl: 1h          # Ban duration
  max_tokens_hour: 50000
  max_tokens_day: 500000
  max_requests_hour: 30
```

## Consequences

### Positive

- Zero latency impact on request processing — AI runs entirely in the background
- Cost-effective: one batch of 20 events vs 20 individual API calls (batching reduces per-request overhead)
- Better analysis quality: AI sees the full attack context across multiple events
- Automated response: auto-ban confirmed attackers without human intervention
- Provider-agnostic: any OpenAI-compatible API works (local models, ollama, etc.)

### Negative

- Verdicts are delayed by `BatchInterval` (up to 60 seconds) — no real-time blocking based on AI
- AI verdicts are non-deterministic — same input may produce slightly different outputs
- Cost is unpredictable without careful monitoring — tokens/day can exceed budget
- Requires a working AI provider — if the provider is down, batch analysis silently fails (logged)

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/ai/analyzer.go` | Background batch analyzer, verdict application |
| `internal/ai/client.go` | OpenAI-compatible API client |
| `internal/ai/provider.go` | Provider catalog (models.dev) |
| `internal/ai/remediation/` | Auto-ban verdict handler |
| `internal/config/config.go` | `AIConfig` struct |

## References

- [models.dev Catalog](https://models.dev)
- [OpenAI Chat Completions API](https://platform.openai.com/docs/api-reference/chat)
- [ADR 0016: Real-Time ML Anomaly Detection](./0016-ml-anomaly-detection.md) — complementary real-time ML layer
