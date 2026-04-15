# Detection Engine

GuardianWAF uses a tokenizer-based scoring engine to detect attacks. Instead of matching raw regex patterns, it lexically analyzes HTTP requests, produces token streams, and scores each token against attack pattern databases.

---

## How Scoring Works

Every request flows through a 20+ layer pipeline (simplified view):

```
Request → IP ACL → Rate Limit → Sanitizer → Detection → Bot Detect → Response
           100       200          300          400          500         600
```

The full pipeline includes additional layers between these stages: Cluster (75), WebSocket Security (76), gRPC Security (78), Canary (95), Threat Intel (125), Replay (145), CORS (150), Custom Rules (150), ATO Protection (250), API Security (275), API Validation (280), CRS (350), Virtual Patch (450), DLP (475), Client-Side (590), and Response (600).

The detection layer (order 400) runs all enabled detectors. Each detector produces **findings** with individual scores. The cumulative score determines the action:

| Score Range | Action | Behavior |
|---|---|---|
| `0 – 24` | **Pass** | Request allowed, no log entry |
| `25 – 49` | **Log** | Request allowed, logged as suspicious |
| `50+` | **Block** | Request blocked with 403 (in enforce mode) |

These thresholds are configurable:

```yaml
waf:
  detection:
    threshold:
      block: 50
      log: 25
```

---

## Scoring Example

**Request:**
```
GET /search?q=' OR 1=1 -- HTTP/1.1
```

**Tokenization of query parameter `q`:**

```
Token 1: StringLiteral  '      (unterminated quote — injection marker)
Token 2: Operator       OR     (boolean operator keyword)
Token 3: NumericLiteral 1
Token 4: Operator       =
Token 5: NumericLiteral 1
Token 6: Comment        --     (SQL line comment)
```

**Findings:**

| # | Pattern | Score | Severity | Confidence |
|---|---|---|---|---|
| 1 | Boolean injection with tautology (`' OR 1=1`) | 85 | High | 0.90 |
| 2 | Comment after string literal (`' ... --`) | 35 | Medium | 0.60 |
| 3 | Isolated SQL keyword: `OR` | 10 | Low | 0.20 |

**Total score: 130** (well above block threshold of 50)

**Action: BLOCK**

---

## Detectors

GuardianWAF ships with 6 attack detectors. Each runs independently and contributes findings to the total score.

### 1. SQL Injection (sqli)

The flagship detector. Uses a custom **tokenizer** (not regex) to decompose input into typed SQL tokens:

| Token Type | Examples |
|---|---|
| `StringLiteral` | `'value'`, `"value"`, unterminated `'` |
| `NumericLiteral` | `123`, `0x1A`, `0b1010`, `3.14` |
| `Keyword` | `SELECT`, `UNION`, `DROP`, `INSERT` |
| `Operator` | `OR`, `AND`, `=`, `!=`, `<>`, `LIKE`, `IN` |
| `Function` | `SLEEP`, `BENCHMARK`, `CHAR`, `CONCAT`, `LOAD_FILE` |
| `Comment` | `--`, `#`, `/* */` |
| `Semicolon` | `;` |
| `ParenOpen/Close` | `(`, `)` |
| `Wildcard` | `*` |

After tokenization, pattern analysis checks for:

| Pattern | Score | Description |
|---|---|---|
| UNION SELECT | 90 | Classic union-based injection |
| Tautology (`' OR 1=1`) | 55–85 | Boolean-based injection |
| Stacked query (`;DROP`) | 95 | Semicolon + dangerous keyword |
| Time-based blind (`SLEEP()`) | 90 | SLEEP, BENCHMARK, WAITFOR DELAY |
| File access (`LOAD_FILE()`) | 100 | File read/write functions |
| INTO OUTFILE/DUMPFILE | 100 | File write via SQL |
| EXEC/EXECUTE + argument | 80 | Dynamic SQL execution |
| CHAR()/CONCAT() obfuscation | 50 | String construction evasion |
| Hex literal in comparison | 40 | Hex-encoded bypass |
| Comment after string literal | 35 | Comment-based evasion |
| Subquery `(SELECT ...)` | 25 | Nested query injection |
| Multiple dangerous keywords | 30 | Bonus for 3+ SQL keywords |
| Isolated dangerous keyword | 10 | Single keyword (low confidence) |

**Scanned locations:** URL path, query parameters, request body, cookies, Referer header, User-Agent (at 50% weight).

### 2. Cross-Site Scripting (xss)

Parses input for HTML/JavaScript injection patterns:

- Script tags (`<script>`, `<script src=`)
- Event handlers (`onerror=`, `onload=`, `onmouseover=`)
- JavaScript URIs (`javascript:`, `vbscript:`)
- Data URIs with script content
- DOM access patterns (`document.cookie`, `document["write"]`)
- Encoded evasion (`&#x`, `\u00`, `%3C`)

### 3. Local File Inclusion (lfi)

Detects path traversal and sensitive file access:

- Directory traversal sequences (`../`, `..%2f`, `..%5c`)
- Null byte injection (`%00`)
- Sensitive file paths (`/etc/passwd`, `/etc/shadow`, `web.config`, `.env`)
- Windows-specific paths (`C:\Windows\`, `\\server\share`)

### 4. Command Injection (cmdi)

Detects OS command injection:

- Shell metacharacters (`;`, `|`, `&&`, `||`, `` ` ``)
- Command substitution (`$(...)`, `` `...` ``)
- Common dangerous commands (`cat`, `ls`, `wget`, `curl`, `nc`, `whoami`)
- Shell-specific syntax (`/bin/sh`, `/bin/bash`, `cmd.exe`, `powershell`)

### 5. XML External Entity (xxe)

Detects XXE injection in XML payloads:

- DOCTYPE declarations with ENTITY definitions
- SYSTEM and PUBLIC entity references
- External DTD includes
- Parameter entities (`%entity;`)

### 6. Server-Side Request Forgery (ssrf)

Detects SSRF attempts in URL parameters:

- Internal IP addresses (`127.0.0.1`, `10.x.x.x`, `192.168.x.x`, `169.254.169.254`)
- IPv6 loopback (`::1`, `0:0:0:0:0:0:0:1`)
- Cloud metadata endpoints (`169.254.169.254/latest/meta-data`)
- DNS rebinding patterns
- Protocol smuggling (`gopher://`, `file://`, `dict://`)

---

## Tokenizer Approach

The SQL injection detector uses a **state-machine tokenizer** rather than regex:

1. **Input normalization.** The sanitizer layer URL-decodes and normalizes encoding before detection.
2. **Lexical analysis.** The tokenizer reads character by character, classifying each sequence into one of 13 token types.
3. **Smart quote handling.** Unterminated quotes and quotes containing SQL keywords are treated as injection markers rather than string delimiters.
4. **Pattern matching.** The resulting token stream is analyzed for known attack patterns (UNION SELECT, boolean injection, stacked queries, etc.).
5. **Score aggregation.** Each pattern match produces a finding with an individual score. Scores accumulate.

This approach resists common evasion techniques:

- **Encoding tricks:** Input is normalized before tokenization.
- **Comment injection:** Comments are recognized as tokens, not ignored.
- **Case manipulation:** Keywords are compared case-insensitively.
- **Whitespace variation:** Whitespace tokens are filtered before analysis.

---

## Tuning Multipliers

Each detector has a `multiplier` that scales all its finding scores:

```yaml
waf:
  detection:
    detectors:
      sqli:
        enabled: true
        multiplier: 1.5   # 50% more sensitive
      xss:
        enabled: true
        multiplier: 0.5   # 50% less sensitive
```

Multiplier math: `final_score = base_score * multiplier`

A UNION SELECT finding with base score 90 and multiplier 1.5 produces final score 135.

---

## Exclusions

Skip specific detectors for paths that legitimately contain patterns that look like attacks:

```yaml
waf:
  detection:
    exclusions:
      - path: /api/webhook
        detectors: [sqli, xss]
        reason: "Webhook payloads contain arbitrary user content"

      - path: /api/markdown
        detectors: [xss]
        reason: "Markdown editor allows HTML-like input"

      - path: /admin/sql
        detectors: [sqli]
        reason: "Admin SQL query interface"
```

Exclusions match by path prefix. A request to `/api/webhook/github` matches the `/api/webhook` exclusion.

---

## Detection Locations

Each detector scans multiple parts of the request:

| Location | Scanned By |
|---|---|
| URL path | All detectors |
| Query parameters | All detectors |
| Request body | All detectors |
| Cookie values | SQLi, XSS |
| Referer header | SQLi, XSS |
| User-Agent | SQLi (at 50% weight) |
| Content-Type | XXE |

---

## Score Interpretation

| Total Score | Meaning |
|---|---|
| 0 | Clean request |
| 10–24 | Isolated keyword matches (likely benign) |
| 25–49 | Suspicious patterns (logged for review) |
| 50–89 | Probable attack (blocked) |
| 90+ | Definite attack (high-confidence patterns) |
| 100+ | Critical attack (file access, stacked queries) |
