# AI-Powered Threat Analysis

GuardianWAF includes an AI-powered threat analysis system that uses large language models to evaluate suspicious traffic patterns, identify coordinated attacks, and auto-block malicious IPs.

## How It Works

```
Events (score ≥ 25) ──► EventBus ──► AI Analyzer (batch 20 events)
                                           │
                                      AI API Call (OpenAI format)
                                           │
                                      Parse Verdicts
                                           │
                                ┌──────────┼──────────┐
                                ▼          ▼          ▼
                             BLOCK      MONITOR      SAFE
                           (auto-ban)    (log)     (ignore)
```

The AI analyzer is a **background batch processor** — it does NOT analyze every request inline (too slow and expensive). Instead:

1. Collects suspicious events (score ≥ threshold) from the event bus
2. When batch is full (default: 20) or interval elapsed (default: 60s) → sends to AI
3. AI returns verdicts per IP: block, monitor, or safe
4. Block verdicts auto-ban the IP via the IP ACL layer
5. All results stored for dashboard display

## Quick Start

### 1. Enable AI Analysis

```yaml
# guardianwaf.yaml
waf:
  ai_analysis:
    enabled: true
    store_path: data/ai
    batch_size: 20
    batch_interval: 60s
    min_score: 25
    max_tokens_per_hour: 50000
    max_tokens_per_day: 500000
    max_requests_per_hour: 30
    auto_block: true
    auto_block_ttl: 1h
```

### 2. Configure Provider via Dashboard

1. Open `http://localhost:9443/ai`
2. Select a provider from the dropdown (400+ providers from models.dev)
3. Select a model
4. Enter your API key
5. Click "Save Provider"
6. Click "Test Connection" to verify

### 3. That's It!

The analyzer automatically starts collecting suspicious events and sending them to the AI for analysis. Check the dashboard for results.

## Provider Configuration

### Via Dashboard UI (`/ai`)

The AI Analysis page provides:
- **Provider selector** — Browse 400+ providers from [models.dev](https://models.dev)
- **Model selector** — Filter by context window, cost, capabilities
- **API key input** — Securely stored on disk
- **Connection test** — Verify API key works
- **Manual analyze** — Trigger analysis on demand

### Via API

```bash
# Get available providers
curl -H "X-API-Key: $KEY" http://localhost:9443/api/v1/ai/providers

# Set provider config
curl -X PUT -H "X-API-Key: $KEY" http://localhost:9443/api/v1/ai/config \
  -d '{
    "provider_id": "openai",
    "provider_name": "OpenAI",
    "model_id": "gpt-4o-mini",
    "model_name": "GPT-4o Mini",
    "api_key": "sk-...",
    "base_url": "https://api.openai.com/v1"
  }'

# Test connection
curl -X POST -H "X-API-Key: $KEY" http://localhost:9443/api/v1/ai/test

# Trigger manual analysis
curl -X POST -H "X-API-Key: $KEY" http://localhost:9443/api/v1/ai/analyze

# View history
curl -H "X-API-Key: $KEY" http://localhost:9443/api/v1/ai/history

# View usage stats
curl -H "X-API-Key: $KEY" http://localhost:9443/api/v1/ai/stats
```

## Supported Providers

Any provider with an **OpenAI-compatible chat completions API** works:

| Provider | Base URL | Recommended Model |
|----------|----------|------------------|
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |
| Anthropic (via proxy) | varies | `claude-3-haiku` |
| Google AI | `https://generativelanguage.googleapis.com/v1beta/openai` | `gemini-2.0-flash` |
| Groq | `https://api.groq.com/openai/v1` | `llama-3.3-70b` |
| Together AI | `https://api.together.xyz/v1` | `meta-llama/Llama-3.3-70B` |
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat` |
| Mistral | `https://api.mistral.ai/v1` | `mistral-small-latest` |
| Local (Ollama) | `http://localhost:11434/v1` | `llama3.2` |

The full list of 400+ providers is fetched from [models.dev/api.json](https://models.dev/api.json).

## Cost Control

AI API calls cost money. GuardianWAF has hard limits to prevent runaway costs:

```yaml
waf:
  ai_analysis:
    max_tokens_per_hour: 50000    # ~$0.05/hour with cheap models
    max_tokens_per_day: 500000    # ~$0.50/day max
    max_requests_per_hour: 30     # Max 30 API calls per hour
    min_score: 25                 # Only analyze events with score ≥ 25
    batch_size: 20                # 20 events per batch (fewer API calls)
    batch_interval: 60s           # Max 1 batch per minute
```

When any limit is reached, analysis is **skipped** (not queued), and a warning is logged. Counters reset automatically every hour/day.

### Cost Estimation

| Model | Input Cost | Output Cost | ~Cost per Analysis |
|-------|-----------|-------------|-------------------|
| gpt-4o-mini | $0.15/M | $0.60/M | ~$0.001 |
| llama-3.3-70b (Groq) | $0.59/M | $0.79/M | ~$0.002 |
| deepseek-chat | $0.14/M | $0.28/M | ~$0.0005 |
| gemini-2.0-flash | $0.10/M | $0.40/M | ~$0.0008 |

With default limits: **max ~$0.50/day**.

## Auto-Blocking

When enabled, the AI can automatically ban IPs:

```yaml
waf:
  ai_analysis:
    auto_block: true      # Enable AI auto-blocking
    auto_block_ttl: 1h    # Block duration
```

Requirements for auto-block:
- AI verdict must be `"block"` (not "monitor" or "safe")
- Confidence must be ≥ 70%
- IP ACL layer must be enabled

The AI is instructed to be conservative — it only recommends blocking when it identifies clear attack patterns with high confidence.

## Analysis Prompt

GuardianWAF sends a structured prompt to the AI:

```
System: You are a WAF security analyst. Analyze these HTTP request events and identify:
1. Attack patterns and their severity
2. IPs that should be blocked (confirmed attackers)
3. IPs that are safe (false positives)
4. Coordinated attack patterns across IPs

User: Analyze these 20 WAF events:
[{ts, ip, method, path, score, action, findings}, ...]
```

The AI responds with structured JSON:
```json
{
  "verdicts": [
    {"ip": "1.2.3.4", "action": "block", "reason": "SQL injection campaign", "confidence": 0.95},
    {"ip": "5.6.7.8", "action": "safe", "reason": "Health check bot", "confidence": 0.9}
  ],
  "summary": "Detected coordinated SQLi campaign from 3 IPs",
  "threats_detected": ["sql_injection_campaign", "credential_stuffing"]
}
```

## Dashboard UI

The AI Analysis page (`/ai`) shows:

- **Stats cards** — Requests/hour, tokens/hour, total cost, AI blocks
- **Provider config** — Current provider, model, masked API key, test button
- **Analyze Now** — Manual trigger button, instant results
- **Analysis History** — Expandable list of past analyses with verdicts, threats, costs

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/ai/providers` | List available AI providers from models.dev |
| GET | `/api/v1/ai/config` | Get current provider configuration |
| PUT | `/api/v1/ai/config` | Set provider, model, API key |
| GET | `/api/v1/ai/history` | Recent analysis results |
| GET | `/api/v1/ai/stats` | Token usage, cost, request counts |
| POST | `/api/v1/ai/analyze` | Trigger manual analysis |
| POST | `/api/v1/ai/test` | Test API key connectivity |

## Configuration Reference

```yaml
waf:
  ai_analysis:
    # Enable/disable AI analysis
    enabled: false

    # Directory for storing AI config and history
    store_path: data/ai

    # URL to fetch provider/model catalog (default: models.dev)
    catalog_url: ""

    # Number of events per batch
    batch_size: 20

    # Maximum interval between batches
    batch_interval: 60s

    # Minimum event score to include in analysis
    min_score: 25

    # Cost control limits
    max_tokens_per_hour: 50000
    max_tokens_per_day: 500000
    max_requests_per_hour: 30

    # Auto-block IPs based on AI verdict
    auto_block: false
    auto_block_ttl: 1h
```

## Troubleshooting

### "No provider configured"
- Go to `/ai` in the dashboard and configure a provider with an API key.

### "Usage limit reached"
- Check `GET /api/v1/ai/stats` to see current usage.
- Increase limits in config or wait for hourly/daily reset.

### AI responses are inaccurate
- Use a more capable model (e.g., GPT-4o instead of GPT-4o-mini).
- Increase `batch_size` for more context per analysis.
- Lower `min_score` to include more borderline events.

### High costs
- Use cheaper models (DeepSeek, Groq).
- Increase `min_score` to only analyze high-confidence events.
- Reduce `max_requests_per_hour`.
- Set `batch_interval` to `5m` for less frequent analysis.
