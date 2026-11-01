# GoTestWAF results

An attack simulation run against a stock `guardianwaf serve`, and what it
changed.

**Read the second result with care.** The first run found the gaps and the
detectors were then fixed until the suite passed, so the 100% below is not an
independent measurement. It shows that the gaps GoTestWAF can see are closed,
not how GuardianWAF scores on payloads nobody has tried yet. Re-measure on a
newer GoTestWAF version or another suite before quoting it.

## Setup

| | |
|---|---|
| Tool | [GoTestWAF](https://github.com/wallarm/gotestwaf) v0.5.11, bundled test cases |
| Target | `guardianwaf serve`, `enforce` mode, default thresholds (block 50, log 25), all default layers |
| Changed from defaults | `rate_limit` and `ip_acl.auto_ban` off (so one blocked probe does not ban the client and inflate results), dashboard off |
| Backend | a stub that returns `200` to every method |
| Classification | block = `403`, pass = `200` |

Rerun: start a backend that answers `200` to everything, start `guardianwaf serve`
with the changes above, then run
`gotestwaf --url http://127.0.0.1:PORT/ --blockStatusCodes 403 --passStatusCodes 200 --sendDelay 0 --randomDelay 1 --skipWAFIdentification`
from a directory containing GoTestWAF's `config.yaml` and `testcases/`.
(`--randomDelay 0` panics GoTestWAF 0.5.11; use 1.)

## Results

| | First run, 2026-11-01 | After the fixes, 2026-11-01 |
|---|---|---|
| Attacks blocked | 288 / 672, **42.9%** | 672 / 672, **100%** |
| Benign requests passed | 137 / 141, **97.2%** | 141 / 141, **100%** |
| GoTestWAF score | 63.5% | 100% |

Three raw-request cases are answered `400` by the WAF and counted by GoTestWAF
as unresolved in both runs.

### What the first run showed

- **Flat base64 payloads: 0 of 235 blocked.** The whole value is base64 and the
  WAF did not decode it. Values that decode to text are now scanned as that
  text.
- **Missing detectors:** CRLF injection (0/7), LDAP injection (0/12) and
  mail-header and SMTP/IMAP injection (0/12) now have detectors; Server Side
  Includes are caught by the template detector.
- **Weak coverage:** NoSQL injection (4/25), URL-parameter RCE (3/9), shell
  injection (8/16), path traversal (5/10), SOAP, `User-Agent` payloads and XML
  injection. Each missed payload became a rule; see
  [detection quality](detection-quality.md#coverage-added-after-the-gotestwaf-run).
- **Splitting by a raw `&`.** GoTestWAF percent-encodes everything except `&`,
  so a payload containing an HTML entity or a VBScript `"&"` arrives as
  several parameters. A query string or form body is now also read across its
  parameters when an `&` starts an entity.
- **False positives (4 of 141):** the title `JavaScript: Basics of JavaScript
  Language` (read as a `javascript:` URL) and the quoted query string
  `>url=/pi?mode=<;>` (read as a file redirection). Both are fixed.

## What this means

The fixes are general rules, each tested against look-alike benign text, and the
in-repo end-to-end gate (0 false blocks on 2225 benign requests) held throughout.
But the rules were chosen because this suite missed them. Treat the first run as
the honest baseline, the second as proof the known gaps are closed, and keep
sending GuardianWAF payloads it has not seen.
