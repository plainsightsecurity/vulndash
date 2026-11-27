#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Also checks disk space each run (src/Lib/ServerHealthAlerts.php: an email
 * when a disk the app depends on reaches alerts.disk_warn_percent, default
 * 85%), so that needs no cron line of its own.
 *
 * Emails admins when the Knowledge Base, host detection or exploit intel
 * (CISA KEV + EPSS) sync has failed,
 * is stuck or is overdue, and again when it's back to normal. The rules
 * (grace period, reminders, what counts as a problem) are in
 * src/Lib/SyncHealthAlerts.php; health is judged exactly as the dashboard's
 * sync status panel judges it. Makes NO Qualys API calls; reads sync_log and
 * writes only its own state row in sync_state.
 *
 * Config (src/config/config.php, all optional, under 'alerts'):
 *   sync_health                => false turns these emails off (default on)
 *   sync_failed_grace_minutes  default 60 - a failure must last this long
 *   sync_reminder_hours        default 24 - repeat while unresolved; 0 = never
 *   admin_emails               recipients, shared with the API budget alerts
 *
 * Usage:
 *   php scripts/send_sync_alerts.php            # normal cron run
 *   php scripts/send_sync_alerts.php --dry-run  # say what would be sent; send and save nothing
 *
 * Cron (as www-data): every 15 minutes - written as an explicit minute list,
 * since the usual step shorthand would end this docblock early:
 *   5,20,35,50 * * * *  php /var/www/dashboard.plainsightsecurity.co.uk/scripts/send_sync_alerts.php >> /var/log/vulndash/sync_alerts.log 2>&1
 */

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\ServerHealthAlerts;
use VulnDash\Lib\SyncHealthAlerts;

$options = getopt('', ['dry-run']);
$dryRun  = array_key_exists('dry-run', $options);

// --- single-instance lock (same pattern as send_kev_alerts.php) --------------
$lockPath   = sys_get_temp_dir() . '/vulndash_sync_alerts.lock';
$lockHandle = \VulnDash\Lib\LockFile::open($lockPath);
if ($lockHandle === false) {
    fwrite(STDERR, "Could not open lock file {$lockPath} - check its ownership/permissions.\n");
    exit(1);
}
@chmod($lockPath, 0666);
if (!flock($lockHandle, LOCK_EX | LOCK_NB)) {
    fwrite(STDOUT, "Another sync alert run is already in progress - exiting.\n");
    exit(0);
}

$exitCode = 0;
// Syncs first, then disk space (src/Lib/ServerHealthAlerts.php) - each its
// own email, and one failing doesn't stop the other being checked.
foreach (['Syncs' => static fn () => SyncHealthAlerts::check(null, $dryRun),
          'Disk'  => static fn () => ServerHealthAlerts::check(null, $dryRun)] as $what => $check) {
    try {
        $r = $check();
        $stamp = date('Y-m-d H:i:s');
        if ($r['problems'] === [] && $r['recoveries'] === []) {
            fwrite(STDOUT, "{$stamp} {$what}: nothing new to report.\n");
            continue;
        }
        foreach ($r['problems'] as $l) {
            fwrite(STDOUT, "{$stamp} PROBLEM  {$l}\n");
        }
        foreach ($r['recoveries'] as $l) {
            fwrite(STDOUT, "{$stamp} OK AGAIN {$l}\n");
        }
        if ($dryRun) {
            fwrite(STDOUT, "{$stamp} Dry run - no email sent, nothing saved.\n");
        } elseif ($r['sent_to'] === []) {
            fwrite(STDERR, "{$stamp} No email could be sent (no recipients, or Resend refused - see the PHP error log).\n");
            $exitCode = 1;
        } else {
            fwrite(STDOUT, "{$stamp} Emailed: " . implode(', ', $r['sent_to']) . "\n");
        }
    } catch (Throwable $e) {
        fwrite(STDERR, date('Y-m-d H:i:s') . " ERROR ({$what}): " . $e->getMessage() . "\n");
        $exitCode = 1;
    }
}
flock($lockHandle, LOCK_UN);
fclose($lockHandle);

exit($exitCode);
