#!/bin/bash
#
# Rescans the whole of 2026 - January through the current month - in
# separate, bounded month-sized chunks, unattended. Added 2026-07 so the
# April-through-July KB catch-up (see sync_knowledge_base.php's own
# docblock for the full incident history) doesn't need to be kicked off
# by hand, month by month, while still keeping each chunk's blast radius
# small: if one month fails partway through, only that month needs
# re-running, and the routine hourly cron sync is never blocked for more
# than the time a single month's chunk takes.
#
# Safe to re-run, in whole or from any later starting month: every
# month's rescan is independently idempotent (sync_knowledge_base.php's
# own upserts are all ON DUPLICATE KEY UPDATE), and none of them touch
# the normal incremental cursor - re-confirming an already-correct month
# just costs API calls, it doesn't risk anything. Runs sequentially, one
# month at a time, and deliberately does NOT try to run months in
# parallel - that would multiply, not divide, the API call rate against
# Qualys's per-version hourly limits for no benefit, since a single
# month's rescan already round-robins across all three API versions on
# its own.
#
# If sync_knowledge_base.php's own file lock happens to be held by the
# routine cron job at the exact moment this script tries to start a
# month (a narrow but real race - cron exits 0 immediately when it loses
# that race, which would otherwise look like a false "success" and cause
# this script to silently skip a whole month), this script detects that
# specific case from the child's own output and retries the same month
# after a short wait rather than advancing past it.
#
# Usage:
#   ./scripts/rescan_2026.sh              # January 2026 through the current month
#   ./scripts/rescan_2026.sh 2026-05      # start from May instead of January -
#                                          # e.g. to skip re-confirming months
#                                          # you already know are done
#
# Expect this to run for hours given what April-July have already shown -
# safe to leave running in the background (nohup ... &), same as any
# individual month's rescan.

set -euo pipefail
cd "$(dirname "$0")/.."

START_MONTH="${1:-2026-01}"
CURRENT_MONTH="$(date +%Y-%m)"
LOCK_RETRY_WAIT_SEC=60
LOCK_MAX_RETRIES=30

if ! date -d "${START_MONTH}-01" >/dev/null 2>&1; then
    echo "Invalid start month '${START_MONTH}' - expected YYYY-MM." >&2
    exit 1
fi
if [ "$(date -d "${START_MONTH}-01" +%s)" -gt "$(date -d "${CURRENT_MONTH}-01" +%s)" ]; then
    echo "Start month ${START_MONTH} is after the current month (${CURRENT_MONTH}) - nothing to do." >&2
    exit 1
fi

month="$START_MONTH"
while [ "$(date -d "${month}-01" +%s)" -le "$(date -d "${CURRENT_MONTH}-01" +%s)" ]; do
    since="${month}-01"

    if [ "$month" = "$CURRENT_MONTH" ]; then
        # The current month is bounded to "now" by simply omitting
        # --rescan-until - there's no real "next month" boundary to give
        # it yet, and the script's own default (walk to now) is exactly
        # what's wanted here.
        until_args=()
        until_desc="now"
    else
        until_date="$(date -d "${since} +1 month" +%Y-%m-%d)"
        until_args=(--rescan-until="${until_date}")
        until_desc="${until_date}"
    fi

    echo "=================================================================="
    echo "Rescanning ${since} to ${until_desc}"
    echo "=================================================================="

    attempt=0
    while :; do
        attempt=$((attempt + 1))
        output_file="$(mktemp)"
        set +e
        php scripts/sync_knowledge_base.php --rescan-since="${since}" "${until_args[@]}" 2>&1 | tee "${output_file}"
        exit_code="${PIPESTATUS[0]}"
        set -e

        if grep -q "Another knowledge base sync is already running" "${output_file}"; then
            rm -f "${output_file}"
            if [ "${attempt}" -ge "${LOCK_MAX_RETRIES}" ]; then
                echo "Gave up on ${since} after ${attempt} attempts - the lock never freed up. Stopping rather than silently skipping this month." >&2
                exit 1
            fi
            echo "Lock was held by another sync (likely the routine cron) - waiting ${LOCK_RETRY_WAIT_SEC}s and retrying ${since} (attempt ${attempt}/${LOCK_MAX_RETRIES})..."
            sleep "${LOCK_RETRY_WAIT_SEC}"
            continue
        fi

        rm -f "${output_file}"
        if [ "${exit_code}" -ne 0 ]; then
            echo "Rescan of ${since} to ${until_desc} failed (exit ${exit_code}) - stopping here rather than continuing past an unverified month. Re-run this script (optionally with ${month} as the start month) once you've looked into it." >&2
            exit "${exit_code}"
        fi
        break
    done

    month="$(date -d "${since} +1 month" +%Y-%m)"
done

echo "=================================================================="
echo "All months from ${START_MONTH} through ${CURRENT_MONTH} complete."
echo "=================================================================="
