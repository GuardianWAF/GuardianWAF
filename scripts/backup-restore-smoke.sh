#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work_root="$repo_root/.temp_files/backup-restore-smoke"
rto_seconds=${GUARDIANWAF_RESTORE_RTO_SECONDS:-300}

fail() {
  printf 'backup-restore-smoke: %s\n' "$*" >&2
  exit 1
}

[[ $rto_seconds =~ ^[1-9][0-9]*$ ]] || fail "GUARDIANWAF_RESTORE_RTO_SECONDS must be a positive integer"
rm -rf -- "$work_root"
mkdir -p -- "$work_root/source/state/audit" "$work_root/source/config" "$work_root/source/events" "$work_root/restore"
cleanup() {
  rm -rf -- "$work_root"
}
trap cleanup EXIT

binary="$work_root/guardianwaf"
(
  cd "$repo_root"
  go build -o "$binary" ./cmd/guardianwaf
)
cp -- "$repo_root/guardianwaf.yaml" "$work_root/source/config/guardianwaf.yaml"
printf '{"timestamp":"2026-07-20T12:00:00Z","method":"POST","path":"/api/v1/rules","auth_type":"global_key","principal":"admin","remote_addr":"192.0.2.1","status":201,"mutation":"add_rule"}\n' >"$work_root/source/state/audit/dashboard.jsonl"
printf '{"id":"tenant-a","name":"Tenant A"}\n' >"$work_root/source/state/tenant.json"
printf '{"id":"event-1","timestamp":"2026-07-20T12:00:00Z"}\n' >"$work_root/source/events/events.jsonl"

archive="$work_root/guardianwaf-state.tar.gz"
metrics="$work_root/backup.prom"
"$repo_root/scripts/backup-state.sh" \
  --config "$work_root/source/config/guardianwaf.yaml" \
  --state-dir "$work_root/source/state" \
  --event-file "$work_root/source/events/events.jsonl" \
  --output "$archive" \
  --metrics-file "$metrics" \
  --rpo-seconds 3600 \
  --confirm-quiesced

"$repo_root/scripts/restore-state.sh" --archive "$archive" --guardianwaf "$binary" --verify-only

grep -q '^guardianwaf_backup_last_success_timestamp_seconds [0-9][0-9]*$' "$metrics" || fail "backup freshness metric missing"
grep -q '^guardianwaf_backup_rpo_target_seconds 3600$' "$metrics" || fail "backup RPO metric missing"

corrupt="$work_root/corrupt.tar.gz"
cp -- "$archive" "$corrupt"
cp -- "${archive}.sha256" "${corrupt}.sha256"
printf 'tamper' >>"$corrupt"
if "$repo_root/scripts/restore-state.sh" --archive "$corrupt" --guardianwaf "$binary" --verify-only >/dev/null 2>&1; then
  fail "tampered archive unexpectedly verified"
fi

mkdir -p -- "$work_root/restore/state" "$work_root/restore/config" "$work_root/restore/events"
printf 'stale-config\n' >"$work_root/restore/config/guardianwaf.yaml"
printf 'stale-state\n' >"$work_root/restore/state/stale.txt"
printf 'stale-event\n' >"$work_root/restore/events/events.jsonl"

restore_started=$(date +%s)
"$repo_root/scripts/restore-state.sh" \
  --archive "$archive" \
  --config "$work_root/restore/config/guardianwaf.yaml" \
  --state-dir "$work_root/restore/state" \
  --event-file "$work_root/restore/events/events.jsonl" \
  --guardianwaf "$binary" \
  --confirm-stopped
restore_elapsed=$(( $(date +%s) - restore_started ))

cmp -- "$work_root/source/config/guardianwaf.yaml" "$work_root/restore/config/guardianwaf.yaml"
diff -r --no-dereference "$work_root/source/state" "$work_root/restore/state"
cmp -- "$work_root/source/events/events.jsonl" "$work_root/restore/events/events.jsonl"
"$binary" validate -c "$work_root/restore/config/guardianwaf.yaml" >/dev/null
(( restore_elapsed <= rto_seconds )) || fail "restore took ${restore_elapsed}s; RTO target is ${rto_seconds}s"
if find "$work_root/restore" -name '.guardianwaf-*' -print -quit | grep -q .; then
  fail "restore left staging or rollback artifacts behind"
fi

printf 'Backup/restore smoke passed.\n'
printf 'RPO target: 3600s; measured restore: %ss; RTO target: %ss.\n' "$restore_elapsed" "$rto_seconds"
