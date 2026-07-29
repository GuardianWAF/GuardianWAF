#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

usage() {
  cat <<'EOF'
Usage: backup-state.sh --output ARCHIVE --confirm-quiesced [options]

Create a versioned, integrity-protected GuardianWAF state snapshot.
GuardianWAF must be stopped or otherwise quiesced before this command runs.

Options:
  --config FILE         Runtime config (default: /etc/guardianwaf/guardianwaf.yaml)
  --state-dir DIR       Durable state root (default: /var/lib/guardianwaf)
  --event-file FILE     Event JSONL (default: /var/log/guardianwaf/events.jsonl)
  --no-event-file       Do not include a separate event JSONL
  --output ARCHIVE      Destination .tar.gz archive (required)
  --metrics-file FILE   Atomically write Prometheus textfile-collector metrics
  --rpo-seconds N       RPO target recorded in metadata (default: 3600)
  --confirm-quiesced    Confirm writers have been stopped (required)
  -h, --help            Show this help
EOF
}

fail() {
  printf 'backup-state: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

config_path=/etc/guardianwaf/guardianwaf.yaml
state_dir=/var/lib/guardianwaf
event_file=/var/log/guardianwaf/events.jsonl
output=
metrics_file=
rpo_seconds=3600
confirmed=false

while (($#)); do
  case "$1" in
    --config)
      (($# >= 2)) || fail "--config requires a value"
      config_path=$2
      shift 2
      ;;
    --state-dir)
      (($# >= 2)) || fail "--state-dir requires a value"
      state_dir=$2
      shift 2
      ;;
    --event-file)
      (($# >= 2)) || fail "--event-file requires a value"
      event_file=$2
      shift 2
      ;;
    --no-event-file)
      event_file=
      shift
      ;;
    --output)
      (($# >= 2)) || fail "--output requires a value"
      output=$2
      shift 2
      ;;
    --metrics-file)
      (($# >= 2)) || fail "--metrics-file requires a value"
      metrics_file=$2
      shift 2
      ;;
    --rpo-seconds)
      (($# >= 2)) || fail "--rpo-seconds requires a value"
      rpo_seconds=$2
      shift 2
      ;;
    --confirm-quiesced)
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

[[ $confirmed == true ]] || fail "refusing a potentially inconsistent snapshot; stop GuardianWAF and pass --confirm-quiesced"
[[ -n $output ]] || fail "--output is required"
[[ $rpo_seconds =~ ^[1-9][0-9]*$ ]] || fail "--rpo-seconds must be a positive integer"
[[ -f $config_path ]] || fail "config file does not exist: $config_path"
[[ ! -L $config_path ]] || fail "config file must not be a symbolic link: $config_path"
[[ -d $state_dir ]] || fail "state directory does not exist: $state_dir"
[[ ! -L $state_dir ]] || fail "state directory must not be a symbolic link: $state_dir"
if [[ -n $event_file ]]; then
  [[ -f $event_file ]] || fail "event file does not exist: $event_file"
  [[ ! -L $event_file ]] || fail "event file must not be a symbolic link: $event_file"
fi

for command_name in cp date find hostname mv sha256sum sort stat tar; do
  require_command "$command_name"
done

if find "$state_dir" -type l -print -quit | grep -q .; then
  fail "state directory contains a symbolic link; snapshots require regular files and directories only"
fi
if find "$state_dir" \! -type d \! -type f -print -quit | grep -q .; then
  fail "state directory contains a special file; snapshots require regular files and directories only"
fi

output_dir=$(dirname -- "$output")
mkdir -p -- "$output_dir"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/guardianwaf-backup.XXXXXX")
tmp_archive="${output}.tmp.$$"
tmp_checksum="${output}.sha256.tmp.$$"
tmp_metrics=
cleanup() {
  rm -rf -- "$work_dir"
  rm -f -- "$tmp_archive" "$tmp_checksum"
  if [[ -n ${tmp_metrics:-} ]]; then
    rm -f -- "$tmp_metrics"
  fi
}
trap cleanup EXIT

mkdir -p -- "$work_dir/payload/config" "$work_dir/payload/state" "$work_dir/payload/events"
cp -a -- "$config_path" "$work_dir/payload/config/guardianwaf.yaml"
cp -a -- "$state_dir"/. "$work_dir/payload/state/"
event_present=false
if [[ -n $event_file ]]; then
  cp -a -- "$event_file" "$work_dir/payload/events/events.jsonl"
  event_present=true
fi

created_epoch=$(date +%s)
created_at=$(date -u -d "@$created_epoch" +%Y-%m-%dT%H:%M:%SZ)
file_count=$(find "$work_dir/payload" -type f | wc -l | tr -d ' ')
cat >"$work_dir/metadata.env" <<EOF
schema_version=1
created_at=$created_at
created_epoch=$created_epoch
hostname=$(hostname)
rpo_target_seconds=$rpo_seconds
event_file_present=$event_present
file_count=$file_count
EOF

(
  cd "$work_dir"
  find payload -type f -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS
)

tar -C "$work_dir" -czf "$tmp_archive" metadata.env SHA256SUMS payload
chmod 0600 "$tmp_archive"
archive_name=$(basename -- "$output")
archive_hash=$(sha256sum "$tmp_archive" | awk '{print $1}')
printf '%s  %s\n' "$archive_hash" "$archive_name" >"$tmp_checksum"
chmod 0600 "$tmp_checksum"
mv -f -- "$tmp_archive" "$output"
mv -f -- "$tmp_checksum" "${output}.sha256"

if [[ -n $metrics_file ]]; then
  metrics_dir=$(dirname -- "$metrics_file")
  mkdir -p -- "$metrics_dir"
  tmp_metrics="${metrics_file}.tmp.$$"
  archive_bytes=$(stat -c %s "$output")
  cat >"$tmp_metrics" <<EOF
# HELP guardianwaf_backup_last_success_timestamp_seconds Unix timestamp of the last verified GuardianWAF state snapshot.
# TYPE guardianwaf_backup_last_success_timestamp_seconds gauge
guardianwaf_backup_last_success_timestamp_seconds $created_epoch
# HELP guardianwaf_backup_archive_bytes Size of the last GuardianWAF state snapshot in bytes.
# TYPE guardianwaf_backup_archive_bytes gauge
guardianwaf_backup_archive_bytes $archive_bytes
# HELP guardianwaf_backup_files Number of regular files in the last GuardianWAF state snapshot.
# TYPE guardianwaf_backup_files gauge
guardianwaf_backup_files $file_count
# HELP guardianwaf_backup_rpo_target_seconds Maximum accepted age of a successful GuardianWAF state snapshot.
# TYPE guardianwaf_backup_rpo_target_seconds gauge
guardianwaf_backup_rpo_target_seconds $rpo_seconds
EOF
  chmod 0644 "$tmp_metrics"
  mv -f -- "$tmp_metrics" "$metrics_file"
  tmp_metrics=
fi

printf 'GuardianWAF backup created: %s\n' "$output"
printf 'SHA-256: %s\n' "$archive_hash"
printf 'Files: %s; RPO target: %ss\n' "$file_count" "$rpo_seconds"
