# GoTestWAF results

An independent attack simulation, run against a stock `guardianwaf serve`. These
numbers are lower than our own corpora ([detection quality](detection-quality.md))
because GoTestWAF covers attack classes and encodings that GuardianWAF does not
inspect today. They are published as measured, not tuned for.

## Setup

| | |
|---|---|
| Date | 2026-11-01 |
| Tool | [GoTestWAF](https://github.com/wallarm/gotestwaf) v0.5.11, bundled test cases |
| Target | `guardianwaf serve` built from `main` at the v0.7.0 preparation point |
| Mode | `enforce`, default thresholds (block 50, log 25), all default layers |
| Changed from defaults | `rate_limit` and `ip_acl.auto_ban` disabled (so one blocked probe does not ban the client and inflate results), dashboard disabled |
| Backend | a stub that returns `200` to every method |
| Classification | block = `403`, pass = `200` |

Rerun: start a backend that answers `200` to everything, start `guardianwaf serve`
with the changes above, then run
`gotestwaf --url http://127.0.0.1:PORT/ --blockStatusCodes 403 --passStatusCodes 200 --sendDelay 0 --randomDelay 1 --skipWAFIdentification`
from a directory containing GoTestWAF's `config.yaml` and `testcases/`.

## Result

| | Blocked / sent | Rate |
|---|---|---|
| True-positive (attacks blocked) | 288 / 672 | **42.9%** |
| True-positive, excluding flat base64 payloads | 288 / 437 | **65.9%** |
| True-negative (benign passed) | 137 / 141 | **97.2%** |
| GoTestWAF overall score | | 63.5% |

3 raw-request cases came back `400` and are counted as unresolved.

### Where the misses are

- **Flat base64 payloads: 0 of 235 blocked.** The whole parameter value is base64.
  GuardianWAF does not decode base64 before detection. This accounts for 235 of
  the 384 bypasses.
- **No detector for these classes** (0% blocked, URL-encoded and plain forms):
  CRLF injection (0/7), LDAP injection (0/12), mail-header injection (0/12).
- **Weak coverage:** NoSQL injection 4/25, server-side includes 3/12,
  command injection via URL parameter 3/9, shell injection 8/16, path traversal
  5/10, SOAP 2/5, User-Agent payloads 4/9.
- **Placeholders (all encodings, base64 included):** blocked share is lowest for
  the URL path (30%) and URL parameters (39%) and higher for headers (64%) and
  XML (67%).
- **Reasonable, excluding base64:** XSS 76/112 (owasp) and 94/104 (community),
  SQL injection 32/36, plain remote code execution 13/13 (`rce`, `rce-urlpath`,
  `community-rce`). RCE in URL parameters is weak (3/9, listed above).

### False positives (4 of 141)

`JavaScript: Basics of JavaScript Language` (URL-encoded, in a URL parameter, an
HTML form and a multipart form) and one multipart body containing `>url=/pi?mode=<;>`.

## What this means

Treat GuardianWAF as a first line that catches common injection, XSS, traversal
and RCE in plain and URL-encoded form. It does not replace application-level
input validation for LDAP, mail headers, CRLF, NoSQL operators or encoded
payloads. Closing these gaps is tracked in
[production readiness](production-readiness.md); each detector added must keep
the in-repo false-positive gates green.
