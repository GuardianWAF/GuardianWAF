# ADR 0003: Tokenizer-Based Detection

**Date:** 2026-04-15
**Status:** Accepted
**Deciders:** GuardianWAF Team

---

## Context

WAF detection engines face a fundamental tradeoff between accuracy and evasion resistance. The two main approaches are:

**Regex-based detection** — pattern matching using regular expressions (e.g., `UNION\s+SELECT`, `' OR '1'='1`). Simple and fast but trivially evaded via:
- Whitespace variation: `UNION\tSELECT`, `UNION\nSELECT`, `%09UNION%09SELECT` (HTTP header injection)
- Case variation: `UnIoN`, `%55NION` (URL-encoded ASCII rotation)
- Comment injection: `UN/**/ION`, `UN/*foo*/ION`
- Null byte injection: `UNION%00SELECT`

**Token-based (lexical) detection** — first tokenize input into a sequence of meaningful tokens (keywords, operators, strings, identifiers), then analyze token sequences for attack patterns. This is structurally resistant to whitespace encoding, comment mixing, and case variation because the tokenizer normalizes these before pattern matching.

The challenge for tokenizers is handling multi-layer encoding: input may be URL-encoded, then HTML-encoded, then SQL-comment-wrapped. A naive tokenizer sees `%` and pauses. A robust tokenizer chains multiple normalization passes (see ADR 0033: Request Sanitizer) before analysis.

## Decision

Each attack detector (SQLi, XSS, LFI, CMDi, XXE, SSRF) implements its own **state-machine tokenizer** that:

1. Reads input character by character
2. Classifies each character as part of a token (keyword, operator, string, comment, etc.)
3. Emits typed tokens with position information
4. Passes the token stream to a pattern analyzer that scores attack signatures

No regex is used on the hot tokenization path.

### Token Categories

All detectors share a common `Token` type but define their own token type constants:

```go
// SQLi tokens (internal/layers/detection/sqli/tokenizer.go)
type TokenType int

const (
    TokenStringLiteral  TokenType = iota // 'value', "value"
    TokenNumericLiteral                  // 123, 0x1A, 0b1010
    TokenKeyword                         // SELECT, UNION, OR, AND, etc.
    TokenOperator                        // =, <>, !=, >=, <=, LIKE, IN, BETWEEN, IS
    TokenFunction                        // COUNT, SLEEP, CHAR, CONCAT, etc.
    TokenComment                         // --, #, /* */
    TokenParenOpen                       // (
    TokenParenClose                      // )
    TokenSemicolon                       // ;
    TokenComma                           // ,
    TokenWildcard                        // *
    TokenWhitespace                      // space, tab, newline
    TokenOther                           // anything else
)
```

### Tokenizer State Machine

The tokenizer operates as a deterministic finite automaton (DFA). For SQL, the key states are:

```
                     ┌──────────────┐
                     │    Start     │
                     └──────┬───────┘
                            │ read char
           ┌────────────────┼────────────────┐
           ▼                ▼                ▼
    ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
    │   String    │  │  Keyword/   │  │   Comment   │
    │  ' or "    │  │  Identifier  │  │  -- or /*   │
    └─────────────┘  └─────────────┘  └─────────────┘
           │                               │
           │ closing quote                  │ */
           ▼                               ▼
         [Token]                      [Token]
```

The tokenizer handles:
- **Nested quotes**: `q'it''s here'` (SQL Server escaping)
- **Hex literals**: `0x1A2B3C`
- **Bit literals**: `0b1010`
- **Scientific notation**: `1e10`
- **Comment removal**: `/* ... */` tokens are classified separately so they can be stripped before scoring

### Evasion Resistance

| Evasion Technique | Regex Impact | Tokenizer Impact |
|-------------------|--------------|------------------|
| `%09` (tab, URL-encoded) | Pattern `UNION SELECT` won't match `\t` | Sanitizer decodes before tokenizer (see ADR 0033) |
| `UN/**/ION` (inline comment) | Pattern `UNION` won't match `UN/**/ION` | Comment token stripped → `UN ION` → two identifiers |
| `%55NION` (URL-encoded ASCII rotation) | Pattern `UNION` won't match `%55NION` | Sanitizer decodes first; no match → 0 score |
| `'>"><svg/onload=alert(1)>` (multi-layer XSS) | Single pattern unlikely to match | Stacked decoders in sanitizer layer normalize each layer |

### Scoring Model

Each detector's analyzer assigns a score based on:

1. **Keyword presence** — `UNION`, `SELECT`, `SLEEP`, `EXEC` (SQLi); `<script>`, `alert`, `onerror` (XSS)
2. **Operator context** — `OR 1=1`, `' AND 'a'='a`
3. **Structural anomalies** — unclosed quotes, consecutive semicolons, excessive string length
4. **Token density** — ratio of suspicious tokens to total tokens

Scores are per-detector and independent. The pipeline accumulates them via `ScoreAccumulator`.

## Consequences

### Positive

- **Encoding-agnostic** — URL decoding, HTML entity decoding, and SQL comment stripping are applied by the Sanitizer (ADR 0033) before the tokenizer sees input; evasion attempts via encoding are neutralized upstream
- **Explainable findings** — each `Finding` includes the matched token, its type, and byte position in the original input; operators can see exactly what triggered the alert
- **Weighted scoring** — a `UNION SELECT` in a string literal scores lower than `UNION SELECT` as keywords in a query context
- **Fuzz-tested** — comprehensive corpus of attack samples and legitimate traffic used to tune sensitivity; each detector package contains `fuzz_test.go`
- **Per-detector isolation** — each detector (sqli, xss, lfi, cmdi, xxe, ssrf) is in its own package with its own tokenizer and patterns; adding a new detector does not affect existing ones

### Negative

- **Higher CPU cost than regex** — character-by-character state machine scanning is more expensive than a compiled regex (`regexp.Regexp.FindAllString` uses a finite automaton internally, but with different optimization characteristics)
- **More code per detector** — each detector requires ~400-800 lines for the tokenizer + analyzer + patterns
- **Normalization dependency** — the tokenizer assumes input is already normalized; without the Sanitizer layer running first, encoded evasion would not be caught
- **New attack techniques require tokenizer updates** — if attackers develop an encoding scheme not handled by the Sanitizer, the detector will miss it until the Sanitizer is updated

### Comparison: Regex vs Tokenizer vs libinjection

| Approach | Evasion Resistance | CPU Cost | Explainability | External Dependency |
|----------|-------------------|----------|----------------|---------------------|
| Regex | Low (trivial to evade) | Low | Finding shows matched substring | None |
| Tokenizer (GuardianWAF) | High (with Sanitizer) | Medium | Finding shows matched token + type | None (ADR 001) |
| libinjection (C) | High | Low | Finding shows SQLi type only | Yes (C library, rejected by ADR 001) |

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/layers/detection/sqli/tokenizer.go` | SQL tokenizer (string literals, keywords, operators, comments) |
| `internal/layers/detection/sqli/patterns.go` | SQLi pattern definitions and scoring rules |
| `internal/layers/detection/sqli/sqli.go` | Detector implementation, score thresholds |
| `internal/layers/detection/xss/parser.go` | HTML/JS parser for XSS detection |
| `internal/layers/detection/lfi/lfi.go` | LFI detector with sensitive path checking |
| `internal/layers/detection/cmdi/cmdi.go` | Command injection detector with shell metacharacter patterns |
| `internal/layers/detection/xxe/xxe.go` | XML external entity detector |
| `internal/layers/detection/ssrf/ssrf.go` | SSRF URL detector with private IP checking |
| `internal/layers/detection/detector.go` | Base detector interface and shared utilities |

## References

- [libinjection](https://github.com/client9/libinjection) — rejected per ADR 001 (C dependency)
- [SQLi Evasion: "SQL Injection Without Normalization"](https://web.archive.org/web/2023/https://oxford.computer)
- [OWASP SQLi Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [ADR 0033: Request Sanitizer](./0033-request-sanitizer.md)
