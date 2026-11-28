#!/usr/bin/env bash
#
# plainsight-backup-check.sh
# Weekly verification of the offsite restic backup:
#   1. Full integrity check of the repository (reads and re-hashes 100% of
#      pack data - slower, so it runs weekly, not nightly).
#   2. Restore test (2026-11-27): restores the latest nightly MySQL dump,
#      loads ONLY the vulndash database from it into a scratch database, and
#      compares row counts with live. Proves the dump inside the backup
#      actually restores, which an integrity check alone can't.
#
# Install to: /usr/local/bin/plainsight-backup-check.sh  (chmod 750, root:root)
# Run by:     plainsight-backup-check.timer (weekly)
#
# Each run's result is recorded with plainsight-backup-status, so the
# dashboard's status panel shows it and the sync alert emails cover a failed
# or missed check. Kept in the dashboard repo (config/backup/).
#
# Safety of the restore test - the nightly dump is mysqldump --all-databases,
# so it carries CREATE DATABASE / USE lines for every database, including
# MySQL's own user accounts. Loading it as-is would overwrite live data. So:
#   - only the `vulndash` section is taken, its CREATE DATABASE / USE lines
#     removed (and DEFINER clauses, which a restricted user can't set);
#   - the run stops before loading anything if what's left still mentions
#     USE, CREATE/DROP DATABASE, users/grants, or the live database by name;
#   - it's loaded as a temporary MySQL user that has rights on the scratch
#     database ONLY, so even a mistake can't write to live data; the user and
#     scratch database are removed afterwards, whatever happens;
#   - it's skipped (status "warning") if there isn't room for it on disk.
#
set -euo pipefail

export RESTIC_REPOSITORY="${RESTIC_REPOSITORY:-sftp:backup-offsite:/export/TrainingVideos/pentest_backup}"
export RESTIC_PASSWORD_FILE="${RESTIC_PASSWORD_FILE:-/etc/restic/repo-password}"
export RESTIC_CACHE_DIR="${RESTIC_CACHE_DIR:-/var/cache/restic}"

LIVE_DB="${LIVE_DB:-vulndash}"
SCRATCH_DB="${SCRATCH_DB:-vulndash_restore_check}"
RESTORE_USER="vd_restore_check"
DUMP_IN_SNAPSHOT="${DUMP_IN_SNAPSHOT:-/var/backups/mysql/all-databases.sql.gz}"
WORK_PARENT="${WORK_PARENT:-/var/tmp}"
# Tables compared after the restore; each must have at least this % of live's rows.
CHECK_TABLES=(users tags organisations assets host_detections knowledge_base)
MIN_PERCENT="${MIN_PERCENT:-80}"
# Leave this much free on top of twice the live database's size.
DISK_MARGIN_BYTES="${DISK_MARGIN_BYTES:-$((1024 * 1024 * 1024))}"
STATUS_BIN="${STATUS_BIN:-/usr/local/bin/plainsight-backup-status}"
# Admin access to MySQL: root over the local socket by default.
MYSQL_ADMIN=(mysql ${MYSQL_ADMIN_DEFAULTS:+--defaults-extra-file="$MYSQL_ADMIN_DEFAULTS"})
# Set SKIP_FULL_CHECK=1 to run only the restore test (manual use, testing).
SKIP_FULL_CHECK="${SKIP_FULL_CHECK:-0}"

LOG_TAG="plainsight-backup-check"
log() { logger -t "$LOG_TAG" -- "$*"; printf '%s  %s\n' "$(date '+%F %T')" "$*"; }
status() { "$STATUS_BIN" check "$@" >/dev/null 2>&1 || log "WARNING: could not record status ($STATUS_BIN)"; }
fail() { log "FAILED: $*"; status status=failed "message=$*"; exit 1; }
trap 'fail "unexpected error at line $LINENO"' ERR
sql() { "${MYSQL_ADMIN[@]}" -N -B -e "$1"; }

WORK=""
cleanup() {
  # Always: no scratch database, no temporary user, no restored files left.
  "${MYSQL_ADMIN[@]}" -e "DROP DATABASE IF EXISTS \`$SCRATCH_DB\`; DROP USER IF EXISTS '$RESTORE_USER'@'localhost';" 2>/dev/null || true
  if [ -n "$WORK" ]; then rm -rf "$WORK"; fi
  return 0   # never let cleanup itself look like a failure (the ERR trap is still set)
}
trap cleanup EXIT
# Stopped part-way (systemctl stop, Ctrl-C, shutdown): bash doesn't run the
# EXIT trap when killed by a signal it isn't trapping, so catch them, record
# it, and exit - which runs cleanup above. (Only kill -9 or a power cut can
# skip this; the next run drops a leftover scratch database and user before
# creating them, and removes stale restore folders just below.)
on_signal() { trap - ERR; log "Stopped by SIG$1 before finishing"; status status=failed "message=Stopped (SIG$1) before finishing"; exit 1; }
trap 'on_signal TERM' TERM
trap 'on_signal INT' INT
trap 'on_signal HUP' HUP

# ─── Reach the backup server first ───────────────────────────────────────────
# The backup server is a Raspberry Pi reached over ZeroTier. When the link has
# been idle, the first packets fail for a few seconds while ZeroTier sets the
# path up again, and ssh gives up at once ("No route to host") - which is how
# the nightly backup failed on 24 and 27 November 2026. So before each restic
# step: ping it (which also wakes the path) and wait for its SSH port to
# answer, retrying every 5 seconds for up to BACKUP_WAIT_SECONDS. Instant when
# the link is already up; does nothing for a repository that isn't sftp:.
BACKUP_WAIT_SECONDS="${BACKUP_WAIT_SECONDS:-180}"
wait_for_backup_server() {
  local target host port start waited limit
  case "$RESTIC_REPOSITORY" in sftp:*) ;; *) return 0 ;; esac
  target="${RESTIC_REPOSITORY#sftp:}"
  target="${target%%:*}"                 # the ssh alias (or user@host)
  # ssh -G prints the settings ssh would use for it (the HostName/Port from
  # /root/.ssh/config). If that lookup fails, fall back to the name itself.
  host="$( { ssh ${SSH_CONFIG_FILE:+-F "$SSH_CONFIG_FILE"} -G "$target" 2>/dev/null || true; } | awk '$1 == "hostname" { print $2; exit }')"
  port="$( { ssh ${SSH_CONFIG_FILE:+-F "$SSH_CONFIG_FILE"} -G "$target" 2>/dev/null || true; } | awk '$1 == "port" { print $2; exit }')"
  host="${host:-${target#*@}}"
  port="${port:-22}"
  if [ "$BACKUP_WAIT_SECONDS" -ge 120 ]; then limit="$((BACKUP_WAIT_SECONDS / 60)) minutes"; else limit="${BACKUP_WAIT_SECONDS}s"; fi
  start=$(date +%s)
  while :; do
    ping -c 1 -W 2 "$host" >/dev/null 2>&1 || true
    if timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
      waited=$(( $(date +%s) - start ))
      if [ "$waited" -gt 0 ]; then
        log "Backup server $target ($host) answered after ${waited}s"
      fi
      return 0
    fi
    if [ $(( $(date +%s) - start )) -ge "$BACKUP_WAIT_SECONDS" ]; then
      fail "Couldn't reach the backup server $target ($host, SSH port $port) for $limit - check the ZeroTier link and that it's switched on"
    fi
    sleep 5
  done
}

find "$WORK_PARENT" -maxdepth 1 -name 'plainsight-restore-check.*' -mmin +60 -exec rm -rf {} + 2>/dev/null || true

status last_run=now status=running message=

# ─── 1. Full integrity check (unchanged) ─────────────────────────────────────
if [ "$SKIP_FULL_CHECK" != "1" ]; then
  log "Starting full restic check (read-data)…"
  wait_for_backup_server
  if restic check --read-data; then
    log "Full check PASSED"
  else
    fail "Full restic check (read-data) failed - investigate the repository"
  fi
fi

# ─── 2. Restore test ─────────────────────────────────────────────────────────
log "Restore test: checking there's room…"
live_bytes="$(sql "SET SESSION information_schema_stats_expiry = 0; SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables WHERE table_schema = '$LIVE_DB'")"
[ "$live_bytes" -gt 0 ] || fail "Live database '$LIVE_DB' not found or empty - nothing to compare a restore with"
need=$((live_bytes * 2 + DISK_MARGIN_BYTES))
datadir="$(sql 'SELECT @@datadir')"
for place in "$WORK_PARENT" "$datadir"; do
  avail="$(df --output=avail -B1 "$place" | tail -1 | tr -d ' ')"
  if [ "$avail" -lt "$need" ]; then
    first="Integrity check passed"; [ "$SKIP_FULL_CHECK" = "1" ] && first="Full check skipped"
    msg="$first; restore test SKIPPED - $(numfmt --to=iec "$avail") free on $place, needs $(numfmt --to=iec "$need")."
    log "$msg"
    status status=warning last_success=now "message=$msg"
    exit 0
  fi
done

WORK="$(mktemp -d "$WORK_PARENT/plainsight-restore-check.XXXXXX")"
chmod 700 "$WORK"

log "Restore test: restoring the latest nightly dump…"
wait_for_backup_server
restic restore latest --tag nightly --target "$WORK/restore" --include "$DUMP_IN_SNAPSHOT" >/dev/null \
  || fail "restic restore of $DUMP_IN_SNAPSHOT from the latest nightly snapshot failed"
dump="$WORK/restore$DUMP_IN_SNAPSHOT"
[ -s "$dump" ] || fail "The latest nightly snapshot has no $DUMP_IN_SNAPSHOT"
snap_time="$(restic snapshots --tag nightly --latest 1 --json | php -r '$s = json_decode(stream_get_contents(STDIN), true); $t = end($s)["time"] ?? ""; echo $t !== "" ? date("Y-m-d H:i", strtotime($t)) : "?";')"

log "Restore test: extracting the $LIVE_DB section…"
section="$WORK/section.sql"
# Triggers, routines and events (mysqldump wraps each in a DELIMITER ;; ...
# DELIMITER ; block) are counted rather than loaded: MySQL 8 won't let a
# restricted user create them while binary logging is on, and giving the
# temporary user that power would undo the point of it. The counts are
# compared with live below, so none can go missing unnoticed.
#
# The dump's closing lines restore settings saved at the very top of the file
# (SET TIME_ZONE=@OLD_TIME_ZONE and so on). When vulndash is the last
# database in the dump - as on the live server - those follow its section,
# and without the top of the file they'd set NULL and fail. So the section
# stops at "-- Dump completed", and any line restoring an @OLD_ setting is
# dropped. LC_ALL=C: the dump is bytes, not text in this locale.
gzip -dc "$dump" \
  | LC_ALL=C awk -v want="-- Current Database: \`$LIVE_DB\`" '
      index($0, "-- Current Database: `") == 1 { keep = ($0 == want) }
      index($0, "-- Dump completed") == 1 { keep = 0 }
      keep' \
  | LC_ALL=C sed -E '/^CREATE DATABASE /d; /^USE `/d; /@OLD_[A-Z_]+/d; s/DEFINER=`[^`]*`@`[^`]*`//g' \
  | LC_ALL=C awk -v counts="$WORK/objects.txt" '
      /^DELIMITER ;;$/ { inblock = 1; next }
      inblock && /^DELIMITER ;$/ { inblock = 0; next }
      inblock {
        if ($0 ~ /CREATE/ && $0 ~ /TRIGGER `/) t++
        else if ($0 ~ /CREATE/ && $0 ~ /(PROCEDURE|FUNCTION) `/) r++
        else if ($0 ~ /CREATE/ && $0 ~ /EVENT `/) e++
        next
      }
      { print }
      END { printf "%d %d %d\n", t, r, e > counts }' \
  > "$section"
read -r dump_triggers dump_routines dump_events < "$WORK/objects.txt"
[ -s "$section" ] || fail "The dump has no \`$LIVE_DB\` database section"
grep -q '^CREATE TABLE ' "$section" || fail "The \`$LIVE_DB\` section of the dump contains no tables"

# Refuse anything that could reach beyond the scratch database.
# (A plain grep -q on the file: piping into head/grep would let pipefail mask a match.)
if LC_ALL=C grep -q -i -E '^[[:space:]]*(USE[[:space:]]|CREATE[[:space:]]+DATABASE|DROP[[:space:]]+DATABASE|CREATE[[:space:]]+USER|ALTER[[:space:]]+USER|DROP[[:space:]]+USER|GRANT[[:space:]]|REVOKE[[:space:]])' "$section"; then
  fail "Refusing to load: the extracted section still has database/user statements - check the dump format"
fi
if LC_ALL=C grep -q "\`$LIVE_DB\`\\." "$section"; then
  fail "Refusing to load: the extracted section names the live database (\`$LIVE_DB\`.) directly"
fi

log "Restore test: loading into scratch database $SCRATCH_DB as a restricted user…"
pw="$(head -c 24 /dev/urandom | base64 | tr -d '/+=')"
"${MYSQL_ADMIN[@]}" -e "DROP DATABASE IF EXISTS \`$SCRATCH_DB\`;
  CREATE DATABASE \`$SCRATCH_DB\` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
  DROP USER IF EXISTS '$RESTORE_USER'@'localhost';
  CREATE USER '$RESTORE_USER'@'localhost' IDENTIFIED BY '$pw';
  GRANT ALL PRIVILEGES ON \`$SCRATCH_DB\`.* TO '$RESTORE_USER'@'localhost';"
# Keep the restore out of the binary log (if one is on), so it doesn't fill
# the disk with a copy of the database every week. Only this session's own
# setting - SESSION_VARIABLES_ADMIN can't change anything else.
nolog=""
if [ "$(sql "SELECT @@log_bin")" = "1" ] \
   && "${MYSQL_ADMIN[@]}" -e "GRANT SESSION_VARIABLES_ADMIN ON *.* TO '$RESTORE_USER'@'localhost';" 2>/dev/null; then
  nolog="SET SESSION sql_log_bin = 0;"
fi
cnf="$WORK/restore.cnf"
printf '[client]\nuser=%s\npassword=%s\nhost=localhost\n' "$RESTORE_USER" "$pw" > "$cnf"
chmod 600 "$cnf"

started=$(date +%s)
{
  printf '%s\n' "$nolog" \
    "/*!40101 SET NAMES utf8mb4 */;" \
    "/*!40103 SET TIME_ZONE='+00:00' */;" \
    "/*!40014 SET UNIQUE_CHECKS=0 */;" \
    "/*!40014 SET FOREIGN_KEY_CHECKS=0 */;" \
    "/*!40101 SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;" \
    "/*!40111 SET SQL_NOTES=0 */;"
  cat "$section"
} | mysql --defaults-extra-file="$cnf" "$SCRATCH_DB" 2> "$WORK/load.err" \
  || fail "The dump didn't load into the scratch database: $(head -c 300 "$WORK/load.err" | tr '\n' ' ')"
took=$(( $(date +%s) - started ))

log "Restore test: comparing row counts with live…"
summary=()
short=()
for t in "${CHECK_TABLES[@]}"; do
  live="$(sql "SELECT COUNT(*) FROM \`$LIVE_DB\`.\`$t\`" 2>/dev/null || echo missing)"
  restored="$(sql "SELECT COUNT(*) FROM \`$SCRATCH_DB\`.\`$t\`" 2>/dev/null || echo missing)"
  summary+=("$t $restored/$live")
  if [ "$restored" = "missing" ] && [ "$live" != "missing" ]; then
    short+=("$t missing from the restore")
  elif [ "$live" != "missing" ] && [ "$live" -gt 0 ] && [ $((restored * 100)) -lt $((live * MIN_PERCENT)) ]; then
    short+=("$t has $restored rows, live has $live")
  fi
done
live_triggers="$(sql "SELECT COUNT(*) FROM information_schema.triggers WHERE trigger_schema = '$LIVE_DB'")"
live_routines="$(sql "SELECT COUNT(*) FROM information_schema.routines WHERE routine_schema = '$LIVE_DB'")"
live_events="$(sql "SELECT COUNT(*) FROM information_schema.events WHERE event_schema = '$LIVE_DB'")"
for pair in "triggers $dump_triggers $live_triggers" "routines $dump_routines $live_routines" "events $dump_events $live_events"; do
  read -r what in_dump in_live <<< "$pair"
  if [ "$in_dump" != "0" ] || [ "$in_live" != "0" ]; then
    summary+=("$what $in_dump/$in_live")
    [ "$in_dump" -lt "$in_live" ] && short+=("the backup has $in_dump $what, live has $in_live")
  fi
done
log "Row counts (restored/live): ${summary[*]}"
if [ "${#short[@]}" -gt 0 ]; then
  problems="$(printf '%s; ' "${short[@]}")"
  fail "Restore test: ${problems%; } (backup from $snap_time)"
fi

joined="$(printf '%s, ' "${summary[@]}")"
msg="Integrity check passed; backup from $snap_time restored in ${took}s - ${joined%, } (restored/live)."
[ "$SKIP_FULL_CHECK" = "1" ] && msg="Restore test only (full check skipped); ${msg#Integrity check passed; }"
log "$msg"
status status=ok last_success=now "message=$msg"
