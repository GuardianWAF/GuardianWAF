# GuardianWAF Service-Level Objectives

## Scope and ownership

These objectives apply to each production GuardianWAF cluster. The `guardianwaf-oncall` team owns measurement, alerts, and first response; the GuardianWAF service owner approves error-budget policy changes. Prometheus must attach a stable `cluster` label and scrape the service as `job="guardianwaf"`.

## Objectives

| SLO | Target / window | SLI | Error budget |
|---|---|---|---|
| Availability | 99.9% over rolling 30 days | Average `up{job="guardianwaf"}` across intended instances, aggregated by `cluster` | 0.1% (about 43m 49s per 30 days) |
| WAF processing latency | 99% of observations ≤100ms over rolling 30 days | `guardianwaf_request_duration_seconds_bucket{le="0.1"}` / `guardianwaf_request_duration_seconds_count` | 1% of observations may exceed 100ms |
| Backup freshness | RPO ≤3600s | `time() - guardianwaf_backup_last_success_timestamp_seconds` | No planned breach; alert at target age |
| Restore | RTO ≤300s per drill/incident | Recorded duration from approved restore start through state replay plus healthy `/livez` and `/readyz` | No planned breach; investigate every miss |

Security event durability, management audit durability, and alert delivery are **zero-tolerance operational invariants**. Any observed drop/persistence/delivery failure pages on-call; they are not averaged into an error budget because a low percentage can still erase critical security evidence.

The availability SLI measures GuardianWAF process/scrape availability, not end-to-end client success. The exporter does not currently expose bounded HTTP response-status counters, so this document deliberately does not claim an HTTP success-rate SLO. Target-environment probes should supplement, not silently replace, this SLI.

## Burn-rate policy

Prometheus rules in [`contrib/prometheus/guardianwaf-rules.yaml`](../contrib/prometheus/guardianwaf-rules.yaml) use two multi-window policies:

- **Fast burn / page:** 14.4× budget consumption over both 5-minute and 1-hour signals, held for 2 minutes.
- **Slow burn / warning ticket:** 6× budget consumption over both 30-minute and 6-hour signals, held for 15 minutes.

These thresholds detect incidents before the rolling 30-day budget is exhausted while requiring both a short and long window to reduce noise. Do not loosen targets or silence alerts during an incident; record an explicit, time-bounded risk acceptance if the service owner chooses to continue a release with depleted budget.

## Release and operating policy

- Stable release requires validated rule syntax, working scrape/rule evaluation in the target environment, and routed test notifications to the real on-call destination.
- Review the rolling 30-day error budget before release. A depleted availability or latency budget blocks routine production rollout unless an incident commander approves an emergency change.
- Run the backup/restore smoke after DR code changes and a target-environment restore drill at least quarterly.
- Review targets after 30 days of production data; changes require service-owner approval and a versioned update to this document and the rules file.
