# GuardianWAF Prometheus Rules

`guardianwaf-rules.yaml` contains recording and alerting rules for the stable metrics contract in [`docs/metrics.md`](../../docs/metrics.md). It is a standard Prometheus rule file and can be mounted under `rule_files`, loaded through a Prometheus Operator `PrometheusRule`, or imported by compatible managed Prometheus services.

## Ownership and routing

Every alert carries:

- `service: guardianwaf`
- `team: guardianwaf-oncall`
- `severity: critical|warning`
- `slo: <signal>`
- a `runbook_url` annotation pointing to an actionable section in [`docs/runbook.md`](../../docs/runbook.md)

Route `severity=critical` to the primary GuardianWAF on-call pager. Route `severity=warning` to the GuardianWAF operations ticket/notification queue. Environment overlays may replace the `team` label or repository URL, but must preserve an accountable owner and working runbook link.

## SLOs

The recording rules implement the service-level indicators defined in [`docs/slo.md`](../../docs/slo.md):

- 99.9% scrape/instance availability over 30 days.
- 99% of WAF processing observations at or below 100ms over 30 days.

Fast-burn and slow-burn alerts use multi-window thresholds against the corresponding 30-day error budget. Event/audit durability, backup freshness, and alert delivery are operational invariants with immediate alerts rather than percentage budgets.

The availability SLI uses Prometheus `up{job="guardianwaf"}`. Ensure the scrape job is named `guardianwaf` and attach a stable `cluster` external label. Backup rules expect `backup-state.sh --metrics-file ...` output to be collected by node-exporter's textfile collector and stored in the same Prometheus.

## Install and validate

Native Prometheus:

```yaml
rule_files:
  - /etc/prometheus/rules/guardianwaf-rules.yaml
```

Validate before deployment:

```bash
docker run --rm \
  --entrypoint /bin/promtool \
  -v "$PWD/contrib/prometheus:/rules:ro" \
  prom/prometheus:v3.5.0 \
  check rules /rules/guardianwaf-rules.yaml
```

Prometheus Operator users can place the file's `groups` under `spec.groups` in a `PrometheusRule`; keep the rule file as the canonical source and validate the rendered object in CI.
