#!/usr/bin/env bash
#
# plainsight-backup.sh
# Nightly offsite backup of the Plainsight Security CRM + Vulnerability
# Dashboard (files AND MySQL) to a remote server over SSH, using restic's
# SFTP backend.
#
# Install to: /usr/local/bin/plainsight-backup.sh   (chmod 750, root:root)
# Run by:     systemd timer  (see plainsight-backup.timer)
#
# 2026-11-27: kept in the dashboard repo (config/backup/) and now records
# each run's result with plainsight-backup-status, so the dashboard's status
# panel shows it and the sync alert emails cover a failed or missed backup.
# Nothing about what is backed up, or how, has changed. Settings can be
# overridden from the environment (used for testing); the defaults are the
# live server's.
#
set -euo pipefail

# ─── Repository ──────────────────────────────────────────────────────────────
# "backup-offsite" is an SSH host alias defined in /root/.ssh/config (see guide).
export RESTIC_REPOSITORY="${RESTIC_REPOSITORY:-sftp:backup-offsite:/export/TrainingVideos/pentest_backup}"
export RESTIC_PASSWORD_FILE="${RESTIC_PASSWORD_FILE:-/etc/restic/repo-password}"
export RESTIC_CACHE_DIR="${RESTIC_CACHE_DIR:-/var/cache/restic}"

# ─── What to back up ─────────────────────────────────────────────────────────
if [ -n "${BACKUP_PATHS_OVERRIDE:-}" ]; then
  read -r -a BACKUP_PATHS <<< "$BACKUP_PATHS_OVERRIDE"
else
  BACKUP_PATHS=(
    "/var/www/html"                                  # CRM / pentest platform
    "/var/www/dashboard.plainsightsecurity.co.uk"    # Vulnerability dashboard project
  )
fi

# ─── Database dump ───────────────────────────────────────────────────────────
DUMP_DIR="${DUMP_DIR:-/var/backups/mysql}"
MYSQL_DEFAULTS="${MYSQL_DEFAULTS:-/etc/restic/db.cnf}"       # [client] block: dedicated backup user
EXCLUDE_FILE="${EXCLUDE_FILE:-/etc/restic/excludes.txt}"
STATUS_BIN="${STATUS_BIN:-/usr/local/bin/plainsight-backup-status}"

# ─── Retention ───────────────────────────────────────────────────────────────
KEEP_DAILY=7
KEEP_WEEKLY=4
KEEP_MONTHLY=6

# ─── Do not edit below ───────────────────────────────────────────────────────
LOG_TAG="plainsight-backup"
log() { logger -t "$LOG_TAG" -- "$*"; printf '%s  %s\n' "$(date '+%F %T')" "$*"; }
# Recording the result must never be what breaks a backup.
status() { "$STATUS_BIN" backup "$@" >/dev/null 2>&1 || log "WARNING: could not record status ($STATUS_BIN)"; }
fail() { log "ERROR: $*"; status status=failed "message=$*"; exit 1; }
trap 'fail "unexpected error at line $LINENO"' ERR
# Stopped part-way (systemctl stop, shutdown): record it, rather than the
# card showing "running" until the next night.
on_signal() { trap - ERR; log "Stopped by SIG$1 before finishing"; status status=failed "message=Stopped (SIG$1) before finishing"; exit 1; }
trap 'on_signal TERM' TERM
trap 'on_signal INT' INT
trap 'on_signal HUP' HUP

umask 077
mkdir -p "$DUMP_DIR" "$RESTIC_CACHE_DIR"
status last_run=now status=running message=

# 1) Consistent, restore-ready dump of ALL databases (captures both projects).
log "Dumping MySQL (all databases)…"
tmp="$DUMP_DIR/all-databases.sql.gz.tmp"
final="$DUMP_DIR/all-databases.sql.gz"
mysqldump --defaults-extra-file="$MYSQL_DEFAULTS" \
  --single-transaction --quick --routines --triggers --events \
  --all-databases \
  | gzip -c > "$tmp" || fail "mysqldump failed"
mv -f "$tmp" "$final"
dump_size="$(du -h "$final" | cut -f1)"
log "Dump complete ($dump_size)"

# 2) Back up the project trees + the fresh dump.
log "Running restic backup…"
restic backup \
  --exclude-file="$EXCLUDE_FILE" \
  --tag nightly \
  "${BACKUP_PATHS[@]}" "$DUMP_DIR" \
  || fail "restic backup failed"
log "restic backup OK"

# 3) Apply retention and reclaim space.
log "Applying retention policy + prune…"
restic forget \
  --keep-daily "$KEEP_DAILY" \
  --keep-weekly "$KEEP_WEEKLY" \
  --keep-monthly "$KEEP_MONTHLY" \
  --prune \
  || fail "restic forget/prune failed"

# 4) Fast integrity spot-check (5% of pack data). Full check runs weekly.
log "Integrity spot-check…"
if restic check --read-data-subset=5%; then
  status status=ok last_success=now "message=Dump $dump_size, backed up and spot-checked (5%)."
else
  log "WARNING: restic check reported problems"
  # The backup itself completed, so it still counts as a success; the
  # warning shows on the dashboard until a clean run.
  status status=warning last_success=now "message=Backup done, but the 5% integrity spot-check reported problems - run plainsight-backup-check.sh."
fi

log "Backup run finished OK"
