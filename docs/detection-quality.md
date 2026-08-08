# Detection Quality Program

This document defines the measurable detection-quality baseline for GuardianWAF. It complements the detector unit tests by running shared attack and benign corpora through the full detection layer and reporting false-negative and block-threshold false-positive rates.

## Corpus Sources

Attack corpus:

| Detector | File | Current baseline |
|---|---|---:|
| CMDi | `testdata/attacks/cmdi.txt` | 46/49 detected, 93.9% |
| GraphQL | `testdata/attacks/graphql.txt` | 20/20 detected, 100.0% |
| LFI | `testdata/attacks/lfi.txt` | 52/55 detected, 94.5% |
| NoSQLi | `testdata/attacks/nosqli.txt` | 26/26 detected, 100.0% |
| Open Redirect | `testdata/attacks/openredirect.txt` | 27/28 detected, 96.4% |
| SQLi | `testdata/attacks/sqli.txt` | 95/105 detected, 90.5% |
| SSRF | `testdata/attacks/ssrf.txt` | 39/39 detected, 100.0% |
| SSTi | `testdata/attacks/ssti.txt` | 22/23 detected, 95.7% |
| XSS | `testdata/attacks/xss.txt` | 71/72 detected, 98.6% |
| XXE | `testdata/attacks/xxe.txt` | 27/27 detected, 100.0% |

> **HTTP Request Smuggling** detection operates at the HTTP framing layer (Content-Length / Transfer-Encoding header inspection), not on query or body content. It is therefore not exercised by the content-based corpus gate. Coverage is maintained through unit tests (`internal/layers/detection/smuggling/smuggling_test.go`, 15 cases) and the fuzz target (`FuzzSmugglingDetector`).

Benign corpus:

| Source | Samples | Block FP rate |
|---|---:|---:|
| generic | 56 | 3/56 = 5.4% |
| cmdi-benign | 25 | 0/25 = 0.0% |
| lfi-benign | 25 | 2/25 = 8.0% |
| nosqli-benign | 25 | 0/25 = 0.0% |
| ssrf-benign | 25 | 2/25 = 8.0% |
| ssti-benign | 25 | 0/25 = 0.0% |
| application_logs | 30 | 2/30 = 6.7% |
| **Combined** | **211** | **9/211 = 4.3%** |

| File | Current baseline |
|---|---:|
| `testdata/benign/queries.txt` | 3/56 at or above block threshold, 5.4%; weighted FP avg 0.89 |
| `testdata/benign/cmdi.txt` | 0/25 at or above block threshold, 0.0%; weighted FP avg 0.00 |
| `testdata/benign/lfi.txt` | 2/25 at or above block threshold, 8.0%; weighted FP avg 0.80 |
| `testdata/benign/nosqli.txt` | 0/25 at or above block threshold, 0.0%; weighted FP avg 0.16 |
| `testdata/benign/ssrf.txt` | 2/25 at or above block threshold, 8.0%; weighted FP avg 0.56 |
| `testdata/benign/ssti.txt` | 0/25 at or above block threshold, 0.0%; weighted FP avg 0.00 |
| `testdata/benign/application_logs.txt` | 2/30 at or above block threshold, 6.7%; weighted FP avg 1.03 |
| Combined benign corpus | 9/211 at or above block threshold, 4.3%; weighted FP avg 0.56 |

The benign corpus intentionally includes text that resembles attacks: Windows paths, local development URLs, FTP URLs, SQL-like prose, HTML-like prose, shell-like snippets, mathematical expressions, MongoDB/JSON filter builders, template placeholder examples, and realistic application/audit log lines. The current block-threshold and severity-weighted false positives are tracked instead of hidden so tuning work can reduce them without weakening attack coverage.

## v0.5.0 Detection Capabilities

### HTTP Request Smuggling (`smuggling-detector`)

Inspects HTTP framing headers for desync attacks that bypass WAF inspection by making the frontend and backend disagree on request boundaries.

| Vector | Pattern | Severity |
|---|---|---:|
| CL.TE conflict | Both `Content-Length` and `Transfer-Encoding: chunked` present | Critical |
| CL.CL conflict | Duplicate `Content-Length` headers with different values | Critical |
| TE.TE obfuscation | `Transfer-Encoding` not exactly `chunked` (case/space/value tricks) | Critical |
| Duplicate TE | Multiple `Transfer-Encoding` headers | Critical |
| HTTP/1.0 + TE | Transfer-Encoding on HTTP/1.0 (non-standard framing) | High |
| Header injection | CR/LF/null bytes in CL or TE header values | Critical |

Config: `waf.detection.detectors.smuggling` (enabled, multiplier). Tests: 15 unit cases + `FuzzSmugglingDetector`.

### Open Redirect (`openredirect-detector`)

Inspects redirect-type parameters and headers for untrusted external URLs that enable phishing via open-redirect vulnerabilities.

**18 redirect parameter names:** `redirect`, `redirect_uri`, `redirect_url`, `return`, `return_url`, `returnurl`, `returnTo`, `return_to`, `next`, `callback`, `callback_url`, `target`, `goto`, `dest`, `destination`, `continue`, `redir`, `r`.

**6 redirect headers:** `Location`, `Refresh`, `X-Redirect`, `X-Forwarded-Host`, `Referer`, `Origin`.

| Vector | Example | Severity |
|---|---|---:|
| External URL | `?redirect=https://evil.com` | High |
| Protocol-relative | `?redirect=//evil.com` | High |
| Scheme injection | `?redirect=javascript:alert(1)` | Critical |
| Data exfil | `?redirect=data:text/html,...` | Critical |
| Backslash confusion | `?redirect=\\\\evil.com` | High |
| CRLF injection | `?redirect=%0d%0aLocation:...` | Critical |

Same-origin bypass: URLs whose host is the request host or a subdomain of it are allowed (e.g., `?redirect=/dashboard` or `?redirect=https://app.example.com/path` when the request is to `example.com`).

Config: `waf.detection.detectors.openredirect` (enabled, multiplier). Tests: 15 unit cases + `FuzzOpenRedirectDetector`.

### GraphQL Depth/Complexity (`graphql-detector`)

Protects GraphQL endpoints from DoS via deeply nested queries, excessive aliasing, fragment cycles, and introspection.

| Metric | Default limit | Config key |
|---|---:|---|
| Max depth | 10 | `waf.graphql.max_depth` |
| Max complexity | 1000 | `waf.graphql.max_complexity` |
| Block introspection | true | `waf.graphql.block_introspection` |
| Allowed endpoints | `["/graphql"]` | `waf.graphql.allow_endpoints` |

**Attack vectors detected:** depth nesting, complexity (field count × depth), introspection (`__schema`, `__type`, `__typename`), aliasing abuse (>10 same-field aliases), fragment cycles, and batch-query bombs (multiple `query` keys in a single JSON request).

**Transport formats supported:** raw `application/graphql`, JSON-wrapped (`{"query":"..."}`), and query parameter (`?query={...}`).

The parser strips string literals and comments before counting braces — a `}` inside a string like `description: "has a } char"` does not affect depth.

Config: `waf.graphql.*`. Tests: 18 unit cases + `FuzzGraphQLDetector`.

## Regression Gate

Run the corpus gate with:

```bash
go test ./internal/layers/detection -run TestDetectionLayer_CorpusQualityBaseline -count=1 -v
```

The gate currently requires:

- at least 20 attack samples per detector corpus,
- at least 90% positive detection rate for each attack corpus,
- at least 40 generic benign samples,
- at least 20 CMDi-specific benign samples,
- at least 20 LFI-specific benign samples,
- at least 20 NoSQLi-specific benign samples,
- at least 20 SSRF-specific benign samples,
- at least 20 SSTI-specific benign samples,
- at least 20 application-log benign samples,
- no more than 6% of combined benign samples reaching the default block threshold,
- combined severity-weighted benign false-positive average no higher than 1.00.

The test logs per-detector detection rates, context-specific benign false-positive rates, severity-weighted false-positive averages, and the detector/severity/description behind benign samples that reach the block threshold. Detection changes should include this output in review notes when they alter scoring, normalization, or detector patterns.

## Known Bypass Coverage

Current parser and detector boundary fuzzing runs through `scripts/fuzz-smoke.sh`, which covers sanitizer normalization, SQLi, XSS, CMDi, LFI, SSRF, NoSQLi, SSTI, IP ACL, rate limiting, bot fingerprinting, and JWT validation.

The corpus gate also locks recent SSRF bypass fixes:

- single-number octal loopback IPs such as `017700000001`,
- dangerous non-HTTP URL schemes such as `gopher://`, `dict://`, `ftp://`, and `ldap://`.

## Remaining Work

- Expand benign traffic with more realistic form, search-box, API query-string, documentation-page, and application-log samples.
- Continue splitting benign samples by context so URL-fetch parameters, search terms, request bodies, and documentation text can have separate expected outcomes.
- Expand the detector-specific benign corpora with real production traffic once anonymized logs are available.
