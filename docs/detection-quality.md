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
| SQLi | `testdata/attacks/sqli.txt` | 100/105 detected, 95.2% |
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
| ssrf-benign | 25 | 1/25 = 4.0% |
| ssti-benign | 25 | 0/25 = 0.0% |
| application_logs | 30 | 2/30 = 6.7% |
| **Combined** | **211** | **8/211 = 3.8%** |

| File | Current baseline |
|---|---:|
| `testdata/benign/queries.txt` | 3/56 at or above block threshold, 5.4%; weighted FP avg 0.89 |
| `testdata/benign/cmdi.txt` | 0/25 at or above block threshold, 0.0%; weighted FP avg 0.00 |
| `testdata/benign/lfi.txt` | 2/25 at or above block threshold, 8.0%; weighted FP avg 0.80 |
| `testdata/benign/nosqli.txt` | 0/25 at or above block threshold, 0.0%; weighted FP avg 0.16 |
| `testdata/benign/ssrf.txt` | 1/25 at or above block threshold, 4.0%; weighted FP avg 0.28 |
| `testdata/benign/ssti.txt` | 0/25 at or above block threshold, 0.0%; weighted FP avg 0.00 |
| `testdata/benign/application_logs.txt` | 2/30 at or above block threshold, 6.7%; weighted FP avg 1.03 |
| Combined benign corpus | 8/211 at or above block threshold, 3.8%; weighted FP avg 0.53 |

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

**Redirect header inspected:** `Location`.

`Referer` is deliberately excluded. It is an inbound header naming where the
visitor came from, not a target the application redirects to, so scoring it as a
redirect target flagged every ordinary click-through from an external site — a
referrer of `https://www.google.com/` scored 60 against a block threshold of 50.
Earlier revisions of this document also listed `Refresh`, `X-Redirect`,
`X-Forwarded-Host` and `Origin`; the detector has never inspected those.

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

## End-to-End Quality Gate

The corpora above score the detection layer alone, and the benign samples
are chosen to look like attacks. The end-to-end gate in `tests/quality`
measures what a production request experiences instead. It builds every
layer the default config enables, exactly as `serve` does, and sends each
sample in realistic positions with browser headers from a distinct client.

```bash
go test ./tests/quality -count=1 -v
```

Benign traffic lives in `testdata/quality/benign/`. Each file declares its
placements in a `# placement:` header:

- `query`: `?q=`
- `form`: urlencoded body
- `multipart`: a multipart/form-data field next to a PNG upload
- `cookie_raw`: a real-world cookie (`name=value`) as browsers send it
- `header`: the value of an application header (`X-Search-Term`)
- `header_raw`: a real-world request header (`Name: value`) as clients send it
- `json`: the whole body
- `path`
- `redirect`: `?next=`

| Corpus | Requests | Blocked |
|---|---:|---:|
| search queries (EN/TR/DE/ES/FR), also as a header | 548 | 0 |
| comments, reviews, support tickets | 386 | 0 |
| names, companies, addresses, emails, phones, also as a header | 308 | 0 |
| JSON API bodies | 78 | 0 |
| passwords, tokens, identifiers, also as a header | 165 | 0 |
| cookies: analytics, consent, signed sessions, preferences | 45 | 0 |
| custom headers: API keys, tenants, cloud SDK, webhook signatures, tracing | 102 | 0 |
| URL paths and slugs | 51 | 0 |
| URLs as parameters | 20 | 0 |
| same-site redirect targets | 17 | 0 |
| **General benign** | **1724** | **0 (0.00%)** — budget 1% |
| developer posts quoting code (`technical_*`) | 138 | 0 (0.00%) — budget 5% |

Attacks reuse `testdata/attacks/`, placed where each class is delivered:

- SQLi, XSS, CMDi, SSTI, NoSQLi: query, form, multipart, a URL-encoded cookie
  and an application header.
- LFI: `file=` and query.
- SSRF: `url=` and query.
- Open redirect: `next=`.
- XXE: XML body.
- GraphQL: `/graphql`.

Every class must be blocked at least 85% of the time. Current result:
1626/1648 (98.7%), with SQLi at 97.1%, CMDi at 98.0%, and LFI and XSS at 100%.

Building this gate exposed defects that the layer-only corpus could not see.
They are now fixed and pinned by tests:

- **Form bodies.** Urlencoded form bodies were inspected with `+` left
  undecoded, so `' OR 1=1 --` in a login form scored 0.
- **JSON bodies.** Fields were inspected as raw JSON text. `{"user":"admin' --"}`
  scored 0, while `{"md":"# Title"}` scored 60. Text detectors now scan the
  decoded fields of JSON and form bodies (`RequestContext.BodyViews`).
- **Double counting.** One rule matching an input's raw and normalized views
  was counted twice, pushing 30-point "possible" findings such as "O'Connor" to
  60.
- **Same-site redirects.** A normalization artifact (`https:/host`) flagged
  every absolute same-site `next=` target as external.
- **Missed SQLi.** `' OR 1 --`, `' HAVING 1=1 --`, `'||1=1 --` and
  `') OR ('1'='1` scored below the block threshold.
- **CMDi whole-value payloads.** `;id`, `| id` and `127.0.0.1;id` were
  downgraded as ambiguous. Table rows such as `| id | name |` still are.
- **SQL keywords in prose.** Every distinct keyword scored 10 and three or more
  added 30, so "create, update or delete a post, select a theme" scored 100.
  Isolated keywords now score at most twice, and the bonus needs two real
  clauses (`DELETE FROM`, `UPDATE t SET`, `DROP TABLE`, ...). Attack detection
  is unchanged.
- **Multipart bodies.** Multipart fields were scanned as raw body text, so the
  boundary `--` and the quoted `name="..."` gave every upload form a 35-point
  SQLi baseline; 35 of 833 benign samples blocked. Fields, raw upload filenames
  and textual uploads are now extracted like JSON and form fields.
- **Binary uploads.** The default `block_null_bytes` check ran over the raw
  body, and text detectors scanned binary bytes, so every image, PDF or
  archive upload was blocked. The NUL check now covers multipart fields and
  textual bodies only, and a body that is binary under a binary media type
  skips text inspection (text sent as `application/octet-stream` is still
  inspected).
- **Cookies.** Cookie values were judged only as transmitted, so
  `pref=%27+OR+1%3D1+--`, which PHP, Express and Rails hand the application as
  `' OR 1=1 --`, scored 0 (SQLi in cookies: 2/105 blocked). Detectors now also
  scan the URL-decoded and normalized forms (`RequestContext.CookieViews`).
- **Custom headers.** Only Referer and User-Agent were scanned (plus four
  headers by SSRF), so an injection in any header the backend reads as data,
  such as `X-Api-Key: ' OR '1'='1' --` or `X-Original-URL: /../../etc/passwd`,
  scored 0. Application-defined headers are now scanned like query values
  (`RequestContext.CustomHeaderViews`). Protocol, credential, client-IP,
  tracing and `Sec-*` headers are skipped.
- **Windows paths in prose.** "the path is C:\Users\me\AppData" scored 55. A
  drive path a space into prose now only logs (25); one that is the value or
  follows `=`, `/` or a quote still scores 55, and sensitive targets such as
  `win.ini` and `system32` score through their own rules.
- **Quoted prose with dashes.** "Don't say 'no' and leave -- please" scored 90
  and "Mark's 'draft' and 'final' versions -- both attached" 125: the quote
  closing a quoted word read as a breakout quote, and a string before AND plus
  a comment after a string added up past the threshold. The breakout and
  boolean rules now require an SQL operand after AND/OR (a literal, constant,
  function, comparison or sub-expression, not a bare English word), and the
  60-point "literal then comment" rule needs a bare quote (`admin'--`).
  Prose that is token-for-token identical to an attack (`it's 'a' and "b" --`
  vs `x' and 'x' --`) still blocks.
- **Home-directory secrets.** `file=/root/.ssh/id_rsa`, `/root/.bash_history`
  and `~/.aws/credentials` scored 0 because only `/etc`, `/proc`, `/var/log` and
  Windows paths were listed. SSH keys, cloud, Docker, Kubernetes and git
  credentials, `.netrc`, `.pgpass` and shell/DB history now score 70-85 when
  the path is the value, and 25 (log only) when a developer post mentions it
  in a sentence.
- **JavaScript string breakout.** `';alert(1)//` scored 0. Input reflected
  into `var q = '...'` needs no tag. A quote, a run of expression separators
  (`;` `+` `-` `)` `||` ...) and a script sink used as code (`alert(`,
  ``alert`1` ``, `top[...]`, `location=`) now score 70. Only a quote with no
  partner earlier in the input counts, so developer posts that quote code
  (`const s = "a"; window.addEventListener(...)`) close their own literal and
  stay clean.
- **"exec" as a word.** `exec office chair` scored 80.

## Known Bypass Coverage

Current parser and detector boundary fuzzing runs through `scripts/fuzz-smoke.sh`, which covers sanitizer normalization, SQLi, XSS, CMDi, LFI, SSRF, NoSQLi, SSTI, IP ACL, rate limiting, bot fingerprinting, and JWT validation.

The corpus gate also locks recent SSRF bypass fixes:

- single-number octal loopback IPs such as `017700000001`,
- dangerous non-HTTP URL schemes such as `gopher://`, `dict://`, `ftp://`, and `ldap://`.

## Remaining Work

- Grow the end-to-end corpora with anonymized production traffic.
- Expand the detector-specific benign corpora with real production traffic once anonymized logs are available.
