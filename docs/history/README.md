# Historical audit & planning snapshots

These are **point-in-time documents**, kept for provenance. They describe the
repository as it was on their stated date and are *not* maintained. Do not treat
any of them as a description of current behaviour — for that, see
[`ARCHITECTURE.md`](../../ARCHITECTURE.md), [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md)
and [`docs/production-readiness.md`](../production-readiness.md).

| Document | As of | What it was |
|---|---|---|
| [`AUDIT.md`](AUDIT.md) | 2026-06-04 | System audit that drove the dead-package removal (Round 8). Still cited from code comments for its finding IDs (e.g. `M1`). |
| [`COMPREHENSIVE-AUDIT.md`](COMPREHENSIVE-AUDIT.md) | 2026-07-15 | Full-project audit of v0.4.0. |
| [`ACTION-PLAN.md`](ACTION-PLAN.md) | 2026-07-15 | P0–P3 remediation plan derived from `COMPREHENSIVE-AUDIT.md`. |
| [`refactor.md`](refactor.md) | 2026-06-26 | Refactoring backlog from the same period. |
| [`PRODUCTION-READINESS-ASSESSMENT.md`](PRODUCTION-READINESS-ASSESSMENT.md) | 2026-07-24 | Readiness assessment for the 0.4.0 release. |
| [`PRODUCTION-READINESS-2026-08-07.md`](PRODUCTION-READINESS-2026-08-07.md) | 2026-08-07 | Readiness report (Turkish) for commit `5eedf89`. |
| [`production-readiness-roadmap.md`](production-readiness-roadmap.md) | 2026-10 | Long-form readiness roadmap (some doc-guard tests still read it). |
| [`production-readiness-report.md`](production-readiness-report.md) | 2026-10 | Readiness report for v0.6.0. |
| [`project-review-2026-10-26.md`](project-review-2026-10-26.md) | 2026-10-26 | Project review (Turkish) that found library-mode parity gaps F216–F218. |
| [`production-readiness-2026-10-26.md`](production-readiness-2026-10-26.md) | 2026-10-26 | Fix record (Turkish) for that review. |
| [`ROADMAP.md`](ROADMAP.md) | 2026 | Earlier feature roadmap, including since-removed features. |
| [`v0.5.0-roadmap.md`](v0.5.0-roadmap.md), [`v0.6.0-roadmap.md`](v0.6.0-roadmap.md) | 2026 | Per-release plans. |

## Why these moved

They previously sat in the repository root, where seven dated snapshots
(~340 KB of prose) sat alongside the six files a reader actually needs. Code
comments that cite a finding ID now point at `docs/history/AUDIT.md`.
