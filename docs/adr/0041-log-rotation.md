# ADR 0041: Log Rotation and File Writer

**Date:** 2026-04-17
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

In production, WAF access logs and application logs are written to files. Without rotation:

- Log files grow unbounded, consuming disk space
- Very large files become slow to read and search
- No automatic cleanup of old logs

External tools like `logrotate` work but add an operational dependency. The WAF should handle its own log rotation to keep the deployment self-contained.

## Decision

Implement a `RotatingFileWriter` (`internal/engine/logrotate.go`) that wraps file writes with automatic rotation:

1. **Size-based rotation** — When the current file exceeds `MaxSizeMB` (default 100MB), it is renamed to `<name>.1` and a new file is opened. Existing backups are shifted (`<name>.1` → `<name>.2` → ...).
2. **Backup count limit** — `MaxBackups` (default 3) caps the number of retained backup files. Oldest backups are deleted.
3. **Age-based cleanup** — `MaxAgeDays` (default 0 = disabled) deletes backups older than the threshold, independent of count.
4. **Atomic rotation** — Rotation happens under a dedicated `rotateMu` lock, separate from the main write lock. The write lock is released during file I/O to avoid blocking concurrent writers.
5. **Configuration** — `logging.max_size_mb`, `logging.max_backups`, `logging.max_age_days` in config or `GWAF_LOGGING_*` env vars.
6. **Output routing** — `ParseLogOutput(s)` handles `stdout`, `stderr`, and file paths, returning `io.Writer` destinations.

### Why separate `rotateMu`

The initial implementation held `fs.mu` during file rename and backup shift operations. Under high write throughput, this blocked all concurrent log writes for the duration of file I/O. Moving rotation to a separate lock allows writers to buffer in memory while rotation proceeds.

## Consequences

**Positive:**
- Self-contained log management — no external `logrotate` dependency
- Bounded disk usage via size and count limits
- Non-blocking rotation under load
- Configurable per-deployment (dev: small files, prod: large files with many backups)

**Negative:**
- Not compressed — rotated files are not gzipped (could be added later)
- Per-writer state — each `RotatingFileWriter` tracks its own file handle and size counter

## References

- `internal/engine/logrotate.go` — Implementation
- `internal/engine/logrotate_test.go` — Tests
- `internal/config/config.go` — `LogConfig.MaxSizeMB`, `MaxBackups`, `MaxAgeDays`
