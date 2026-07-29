#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

usage() {
  cat <<'EOF'
Usage: restore-state.sh --archive ARCHIVE [options]

Verify and restore a GuardianWAF state snapshot. GuardianWAF must be stopped.
Integrity, archive layout, and config validity are checked before targets change.

Options:
  --archive FILE        Snapshot .tar.gz (required)
  --config FILE         Restored config target (default: /etc/guardianwaf/guardianwaf.yaml)
  --state-dir DIR       Restored state root (default: /var/lib/guardianwaf)
  --event-file FILE     Restored event JSONL (default: /var/log/guardianwaf/events.jsonl)
  --guardianwaf FILE    GuardianWAF binary used for config validation
  --verify-only         Verify archive/checksums/config without mutating targets
  --confirm-stopped     Confirm GuardianWAF writers are stopped (required for restore)
  -h, --help            Show this help
EOF
}

fail() {
  printf 'restore-state: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

archive=
config_target=/etc/guardianwaf/guardianwaf.yaml
state_target=/var/lib/guardianwaf
event_target=/var/log/guardianwaf/events.jsonl
guardianwaf_bin=
verify_only=false
confirmed=false

while (($#)); do
  case "$1" in
    --archive)
      (($# >= 2)) || fail "--archive requires a value"
      archive=$2
      shift 2
      ;;
    --config)
      (($# >= 2)) || fail "--config requires a value"
      config_target=$2
      shift 2
      ;;
    --state-dir)
      (($# >= 2)) || fail "--state-dir requires a value"
      state_target=$2
      shift 2
      ;;
    --event-file)
      (($# >= 2)) || fail "--event-file requires a value"
      event_target=$2
      shift 2
      ;;
    --guardianwaf)
      (($# >= 2)) || fail "--guardianwaf requires a value"
      guardianwaf_bin=$2
      shift 2
      ;;
    --verify-only)
      verify_only=true
      shift
      ;;
    --confirm-stopped)
      confirmed=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n $archive ]] || fail "--archive is required"
[[ -f $archive ]] || fail "archive does not exist: $archive"
[[ ! -L $archive ]] || fail "archive must not be a symbolic link: $archive"
if [[ $verify_only != true ]]; then
  [[ $confirmed == true ]] || fail "refusing restore while writers may be active; stop GuardianWAF and pass --confirm-stopped"
  [[ -n $guardianwaf_bin ]] || fail "--guardianwaf is required for restore so config is validated before mutation"
fi
for target in "$config_target" "$state_target" "$event_target"; do
  [[ ! -L $target ]] || fail "restore target must not be a symbolic link: $target"
done

for command_name in awk cp find mv rm sha256sum tar; do
  require_command "$command_name"
done

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/guardianwaf-restore.XXXXXX")
config_stage=
state_stage=
event_stage=
config_backup=
state_backup=
event_backup=
config_backup_dir=
state_backup_dir=
event_backup_dir=
cleanup() {
  rm -rf -- "$work_dir"
  [[ -z ${config_stage:-} ]] || rm -rf -- "$config_stage"
  [[ -z ${state_stage:-} ]] || rm -rf -- "$state_stage"
  [[ -z ${event_stage:-} ]] || rm -rf -- "$event_stage"
  [[ -z ${config_backup_dir:-} ]] || rm -rf -- "$config_backup_dir"
  [[ -z ${state_backup_dir:-} ]] || rm -rf -- "$state_backup_dir"
  [[ -z ${event_backup_dir:-} ]] || rm -rf -- "$event_backup_dir"
}
trap cleanup EXIT

checksum_file="${archive}.sha256"
[[ -f $checksum_file ]] || fail "archive checksum sidecar is missing: $checksum_file"
expected_hash=$(awk 'NR == 1 {print $1}' "$checksum_file")
[[ $expected_hash =~ ^[0-9a-fA-F]{64}$ ]] || fail "invalid archive checksum sidecar"
actual_hash=$(sha256sum "$archive" | awk '{print $1}')
[[ $actual_hash == "$expected_hash" ]] || fail "archive SHA-256 mismatch"

while IFS= read -r member; do
  [[ -n $member ]] || continue
  [[ $member != /* ]] || fail "archive contains an absolute path: $member"
  case "/$member/" in
    */../*) fail "archive contains path traversal: $member" ;;
  esac
  case "$member" in
    metadata.env|SHA256SUMS|payload|payload/*) ;;
    *) fail "archive contains unexpected member: $member" ;;
  esac
done < <(tar -tzf "$archive")

if tar -tvzf "$archive" | awk '{print substr($1,1,1)}' | grep -Eq '[lhcbps]'; then
  fail "archive contains a link or special file"
fi

tar -xzf "$archive" -C "$work_dir"
[[ -f $work_dir/metadata.env ]] || fail "metadata.env is missing"
[[ -f $work_dir/SHA256SUMS ]] || fail "SHA256SUMS is missing"
[[ -f $work_dir/payload/config/guardianwaf.yaml ]] || fail "config payload is missing"
[[ -d $work_dir/payload/state ]] || fail "state payload is missing"
(
  cd "$work_dir"
  sha256sum --check --strict SHA256SUMS >/dev/null
) || fail "payload SHA-256 verification failed"

schema_version=$(awk -F= '$1 == "schema_version" {print $2}' "$work_dir/metadata.env")
[[ $schema_version == 1 ]] || fail "unsupported snapshot schema_version: ${schema_version:-missing}"
event_present=$(awk -F= '$1 == "event_file_present" {print $2}' "$work_dir/metadata.env")
[[ $event_present == true || $event_present == false ]] || fail "invalid event_file_present metadata"
if [[ $event_present == true ]]; then
  [[ -f $work_dir/payload/events/events.jsonl ]] || fail "event payload is missing"
fi

if [[ -n $guardianwaf_bin ]]; then
  [[ -x $guardianwaf_bin ]] || fail "GuardianWAF binary is not executable: $guardianwaf_bin"
  "$guardianwaf_bin" validate -c "$work_dir/payload/config/guardianwaf.yaml" >/dev/null || fail "restored config validation failed"
fi

if [[ $verify_only == true ]]; then
  printf 'GuardianWAF backup verified: %s\n' "$archive"
  printf 'SHA-256: %s; schema: %s\n' "$actual_hash" "$schema_version"
  exit 0
fi

config_parent=$(dirname -- "$config_target")
state_parent=$(dirname -- "$state_target")
event_parent=$(dirname -- "$event_target")
mkdir -p -- "$config_parent" "$state_parent" "$event_parent"
config_stage=$(mktemp -d "$config_parent/.guardianwaf-config-stage.XXXXXX")
state_stage=$(mktemp -d "$state_parent/.guardianwaf-state-stage.XXXXXX")
event_stage=$(mktemp -d "$event_parent/.guardianwaf-event-stage.XXXXXX")
cp -a -- "$work_dir/payload/config/guardianwaf.yaml" "$config_stage/guardianwaf.yaml"
cp -a -- "$work_dir/payload/state"/. "$state_stage/"
if [[ $event_present == true ]]; then
  cp -a -- "$work_dir/payload/events/events.jsonl" "$event_stage/events.jsonl"
fi

config_backup_dir=$(mktemp -d "$config_parent/.guardianwaf-config-backup.XXXXXX")
state_backup_dir=$(mktemp -d "$state_parent/.guardianwaf-state-backup.XXXXXX")
event_backup_dir=$(mktemp -d "$event_parent/.guardianwaf-event-backup.XXXXXX")
config_backup=$config_backup_dir/previous
state_backup=$state_backup_dir/previous
event_backup=$event_backup_dir/previous
config_had=false
state_had=false
event_had=false
committed=false
rollback() {
  if [[ $committed != true ]]; then
    rm -rf -- "$config_target" "$state_target"
    [[ $event_present != true ]] || rm -f -- "$event_target"
    [[ $config_had != true || ! -e $config_backup ]] || mv -- "$config_backup" "$config_target"
    [[ $state_had != true || ! -e $state_backup ]] || mv -- "$state_backup" "$state_target"
    [[ $event_had != true || ! -e $event_backup ]] || mv -- "$event_backup" "$event_target"
  fi
}
trap 'rollback; cleanup' EXIT

[[ ! -e $config_target ]] || { mv -- "$config_target" "$config_backup"; config_had=true; }
[[ ! -e $state_target ]] || { mv -- "$state_target" "$state_backup"; state_had=true; }
if [[ $event_present == true && -e $event_target ]]; then
  mv -- "$event_target" "$event_backup"
  event_had=true
fi

mv -- "$config_stage/guardianwaf.yaml" "$config_target"
rm -rf -- "$config_stage"
config_stage=
mv -- "$state_stage" "$state_target"
state_stage=
if [[ $event_present == true ]]; then
  mv -- "$event_stage/events.jsonl" "$event_target"
fi
rm -rf -- "$event_stage"
event_stage=
committed=true

printf 'GuardianWAF state restored from: %s\n' "$archive"
printf 'Run health/readiness and state replay checks before accepting traffic.\n'
