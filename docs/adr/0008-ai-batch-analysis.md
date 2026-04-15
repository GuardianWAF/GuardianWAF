# ADR 008: AI Batch Threat Analysis Design

## Status: Accepted

## Context

The rule-based WAF engine detects known attack patterns in real-time. However, correlating attack signals across multiple requests — detecting coordinated campaigns, identifying false positives, and producing threat intelligence summaries — requires analysis that is too expensive and slow for per-request processing.

Making an LLM API call for every WAF event would be:
- **Too slow**: LLM inference adds 1-10 seconds per request, unacceptable for a WAF
- **Too expensive**: At $0.01-0.10 per 1K tokens, real-time scoring costs would be prohibitive
- **Too noisy**: Individual events lack the context needed for accurate verdicts

We needed an approach that provides AI-powered threat intelligence without impacting request latency or breaking the budget.

## Decision

Implement **background batch analysis** (`internal/ai/analyzer.go`): events are collected into batches in memory, then sent to the configured LLM provider periodically or when the batch reaches a configurable size.

**Architecture**:

```
WAF Pipeline → Event Channel → [Background Analyzer Loop] → LLM API → Verdicts
                                       ↑
                                 Batch of N events
                                 (configurable size, default 20)
```

**Key design choices**:

1. **Background goroutine** (not per-request): The analyzer runs in its own goroutine with a dedicated event channel. The WAF pipeline never blocks on AI analysis — events are queued and processed asynchronously.

2. **Batch composition**: Only events with `score >= MinScoreForAI` (default 25) are analyzed. This filters noise (benign traffic) and focuses AI resources on genuinely suspicious activity.

3. **Batch sizing**: Configurable via `BatchSize` (default 20 events) and `BatchInterval` (default 60 seconds). Batches are flushed when either threshold is reached — whichever comes first.

4. **AI provider abstraction**: `Client` implements an OpenAI-compatible API client. Any provider that speaks the OpenAI chat completions format works. Provider selection uses the models.dev catalog (`/v1/models` from `https://models.dev`).

5. **Cost controls**: Per-store usage tracking with configurable limits:
   - `MaxTokensHour`: Default 50,000 tokens/hour
   - `MaxTokensDay`: Default 500,000 tokens/day
   - `MaxRequestsHour`: Default 30 requests/hour
   Batches are skipped when limits are exceeded.

6. **Verdict application**: When the AI returns `block` verdicts with confidence >= 70%, the analyzer calls `AddAutoBan` on the IP ACL layer (fire-and-forget, non-blocking). This provides automated response to confirmed attackers.

7. **JSON store persistence**: Analysis results are stored in a JSON file (`ai_analysis.jsonl`) for audit and review. The dashboard exposes this history via `/api/v1/ai/history`.

**Prompt design** (system prompt in `analyzer.go`):
- The system prompt instructs the AI to respond ONLY with valid JSON in a structured format
- Input: batch of event summaries (timestamp, IP, method, path, query, score, findings)
- Output: `verdicts[]`, `summary`, `threats_detected[]`
- `extractJSON()` helper extracts the JSON object from markdown-wrapped responses

**Manual analysis**: The `ManualAnalyze(events)` method allows on-demand analysis of a specific event batch (e.g., from the dashboard), useful for investigating specific incidents.

## Consequences

**Positive**:
- Zero latency impact on request processing — AI runs entirely in the background
- Cost-effective: one batch of 20 events vs 20 individual API calls (batching reduces per-request overhead)
- Better analysis quality: AI sees the full attack context across multiple events
- Automated response: auto-ban confirmed attackers without human intervention
- Provider-agnostic: any OpenAI-compatible API works (local models, ollama, etc.)

**Negative**:
- Verdicts are delayed by `BatchInterval` (up to 60 seconds) — no real-time blocking based on AI
- AI verdicts are non-deterministic — same input may produce slightly different outputs
- Cost is unpredictable without careful monitoring — tokens/day can exceed budget
- Requires a working AI provider — if the provider is down, batch analysis silently fails (logged)

**Trade-offs considered**:
- **Streaming vs batch**: Streaming (process events one-by-one as they arrive) was rejected due to API cost — streaming is billed per-token even for tiny batches. Batch processing amortizes the fixed per-request cost.
- **Synchronous vs async**: Synchronous (wait for AI before accepting next batch) was rejected — it creates backpressure when the AI provider is slow. Async with channel buffering decouples the WAF from AI latency.
- **Verdict caching**: Caching verdicts by IP was considered to avoid re-analyzing the same IP across batches. Rejected for now — batch composition changes over time, and caching adds complexity. Re-evaluate if cost becomes problematic.

## Configuration

```yaml
ai_analysis:
  enabled: true
  batch_size: 20              # Events per batch
  batch_interval: 60s         # Maximum time between batches
  min_score: 25               # Only analyze events with score >= 25
  auto_block: true            # Auto-ban IPs flagged by AI (confidence >= 70%)
  auto_block_ttl: 1h         # Ban duration
  max_tokens_hour: 50000
  max_tokens_day: 500000
  max_requests_hour: 30
```

## Security Considerations

- AI verdicts with confidence < 70% are logged but not actioned (no auto-ban)
- Provider BaseURL is validated against SSRF (private/reserved IPs rejected)
- API keys are stored in the config file; the dashboard shows only masked keys
- AI responses are parsed conservatively — malformed JSON is logged but doesn't crash the analyzer
- The analyzer loop has panic recovery — if it crashes, it restarts automatically
