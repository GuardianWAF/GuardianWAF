# Detection Quality Program

This document defines the measurable detection-quality baseline for GuardianWAF. It complements the detector unit tests by running shared attack and benign corpora through the full detection layer and reporting false-negative and block-threshold false-positive rates.

## Corpus Sources

Attack corpus:

| Detector | File | Current baseline |
|---|---|---:|
| CMDi | `testdata/attacks/cmdi.txt` | 45/49 detected, 91.8% |
| LFI | `testdata/attacks/lfi.txt` | 50/55 detected, 90.9% |
| NoSQLi | `testdata/attacks/nosqli.txt` | 26/26 detected, 100.0% |
| SQLi | `testdata/attacks/sqli.txt` | 95/105 detected, 90.5% |
| SSRF | `testdata/attacks/ssrf.txt` | 39/39 detected, 100.0% |
| SSTI | `testdata/attacks/ssti.txt` | 22/23 detected, 95.7% |
| XSS | `testdata/attacks/xss.txt` | 71/72 detected, 98.6% |
| XXE | `testdata/attacks/xxe.txt` | 27/27 detected, 100.0% |

Benign corpus:

| File | Current baseline |
|---|---:|
| `testdata/benign/queries.txt` | 2/56 at or above block threshold, 3.6%; weighted FP avg 0.77 |
| `testdata/benign/cmdi.txt` | 0/25 at or above block threshold, 0.0%; weighted FP avg 0.00 |
| `testdata/benign/lfi.txt` | 0/25 at or above block threshold, 0.0%; weighted FP avg 0.24 |
| `testdata/benign/nosqli.txt` | 0/25 at or above block threshold, 0.0%; weighted FP avg 0.16 |
| `testdata/benign/ssrf.txt` | 1/25 at or above block threshold, 4.0%; weighted FP avg 0.28 |
| `testdata/benign/ssti.txt` | 0/25 at or above block threshold, 0.0%; weighted FP avg 0.00 |
| `testdata/benign/application_logs.txt` | 1/30 at or above block threshold, 3.3%; weighted FP avg 0.80 |
| Combined benign corpus | 4/211 at or above block threshold, 1.9%; weighted FP avg 0.40 |

The benign corpus intentionally includes text that resembles attacks: Windows paths, local development URLs, FTP URLs, SQL-like prose, HTML-like prose, shell-like snippets, mathematical expressions, MongoDB/JSON filter builders, template placeholder examples, and realistic application/audit log lines. The current block-threshold and severity-weighted false positives are tracked instead of hidden so tuning work can reduce them without weakening attack coverage.

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
