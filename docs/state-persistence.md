# State Persistence

GuardianWAF has a mixed persistence model. Request processing should continue when optional state is unavailable, but explicitly configured durable stores should fail fast during startup so operators do not believe data is being retained when it is not.

## Event Storage

Security events are controlled by the top-level `events` block:

```yaml
events:
  storage: file
  max_events: 100000
  file_path: /var/log/guardianwaf/events.jsonl
```

Supported storage modes:

| Mode | Runtime behavior | Durable | Queryable |
| --- | --- | --- | --- |
| `memory` | Fixed-size in-memory ring buffer. Old events are overwritten when `max_events` is reached. | No | Yes |
| `file` | Persistent memory store backed by JSONL. Startup replays the JSONL file into a fixed-size memory ring and appends new events to the same file. | Yes | Yes, for the last `max_events` replayed/in-memory events |

When `events.storage: file` is configured, `cmd serve` and `cmd sidecar` create the parent directory for `events.file_path` with mode `0700` and fail startup if the file cannot be opened. The store writes the file with mode `0600`.

The JSONL file is append-oriented. For operational retention, rotate or archive it externally, or place it on a volume with an explicit retention policy. On restart, GuardianWAF keeps only the most recent `max_events` records in queryable memory even if the file contains more historical data.

## Default Stateful Paths

| Subsystem | Config field | Default path | Notes |
| --- | --- | --- | --- |
| Security events | `events.file_path` | `/var/log/guardianwaf/events.jsonl` | Used only when `events.storage: file`. |
| ACME certificates | `tls.acme.cache_dir` | `/var/lib/guardianwaf/acme` | Stores ACME account and certificate material. Back up this directory before node replacement. |
| Tenant definitions | `tenant.store_path` | `data/tenants` when tenant store is enabled without an explicit path | Stores tenant metadata and hashed keys. Treat as sensitive. |
| AI analysis | `waf.ai_analysis.store_path` | `data/ai` | Stores provider config/history used by AI analysis features. |
| API discovery exports | `waf.api_discovery.export_path` | `data/api-discovery` | Stores generated API discovery artifacts when auto-export is enabled. |
| Replay captures | `waf.replay.storage_path` | `data/replay` | Stores captured traffic according to replay retention settings. Treat captures as sensitive. |
| Analytics | `waf.analytics.storage_path` | `data/analytics` | Stores analytics time-series snapshots when analytics persistence is active. |
| AI remediation rules | `waf.remediation.storage_path` | `data/remediation` | Stores generated remediation rules. |
| Compliance audit trail | `compliance.audit_trail.persist_path` | No default path unless configured | JSONL hash-chain persistence for compliance audit records. |
| Compliance report archive | `compliance.retention.archive_path` | No default path unless configured | Optional archive target for compliance retention. |
| Access/application logs | `logging.output` | `stdout` | File output is rotated by GuardianWAF when configured as a file path. |

## Container and Kubernetes Guidance

For production containers, mount persistent volumes for every enabled durable path. At minimum, file-backed events and ACME should use volumes:

```yaml
events:
  storage: file
  file_path: /var/log/guardianwaf/events.jsonl

tls:
  acme:
    cache_dir: /var/lib/guardianwaf/acme
```

Recommended volume ownership and permissions:

| Path class | Directory mode | File mode | Sensitivity |
| --- | --- | --- | --- |
| Event JSONL | `0700` | `0600` | High, contains security event metadata. |
| ACME cache | `0700` | `0600` | Critical, contains private keys. |
| Tenant store | `0700` | `0600` | Critical, contains tenant metadata and key hashes. |
| Replay captures | `0700` | `0600` | Critical, may contain request/response data. |
| Analytics/API discovery | `0700` | `0600` | Medium to high, can expose traffic shape and endpoint inventory. |

Avoid sharing these volumes with sidecars that do not need direct access. If using Kubernetes, set `securityContext.fsGroup` or an init container so the GuardianWAF runtime user can create and write the mounted directories without broadening permissions to world-readable paths.

The Helm chart mounts one state volume at `/var/lib/guardianwaf` and `/var/log/guardianwaf` when persistence is enabled. The default `ReadWriteOnce` access mode is appropriate for a single replica. For multiple replicas with shared file-backed state, use a storage class that supports `ReadWriteMany` or provide a topology-specific storage design where each pod has its own durable path.

## Backup and Restore

Back up these paths before upgrading, replacing nodes, or migrating clusters:

- `tls.acme.cache_dir`, to avoid unnecessary certificate reissuance and rate limits.
- `events.file_path`, if security event history is required after migration.
- `tenant.store_path`, when tenant management is enabled.
- `waf.replay.storage_path`, only when replay captures are intentionally retained.
- `waf.remediation.storage_path`, if generated remediation rules are part of operations.
- `compliance.audit_trail.persist_path` and report/archive directories, when compliance features are enabled.

Restore order should be:

1. Stop GuardianWAF.
2. Restore directories with the same ownership and restrictive permissions.
3. Start GuardianWAF and confirm `/livez` returns success.
4. Confirm `/readyz` returns success once upstreams are healthy.
5. Check dashboard event history or event API queries if `events.storage: file` is enabled.

Do not restore stale replay captures or AI/remediation outputs into a different tenant or environment unless they have been reviewed for sensitive data and environment-specific assumptions.
