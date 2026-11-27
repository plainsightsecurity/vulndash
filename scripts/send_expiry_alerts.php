#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Emails admins when a tag's access end date is 30 days away, and again once
 * it has passed. Rules in src/Lib/AccessExpiryAlerts.php; the dates are set
 * in the Tags table on Manage Users (see src/Lib/AccessExpiry.php). Makes NO
 * Qualys API calls. Expiry itself doesn't depend on this job - every page
 * checks the date directly - it only sends the reminders.
 *
 * Usage:
 *   php scripts/send_expiry_alerts.php            # normal cron run
 *   php scripts/send_expiry_alerts.php --dry-run  # say what would be sent; send and save nothing
 *
 * Cron (as www-data): once a day, e.g.
 *   5 7 * * *  php /var/www/dashboard.plainsightsecurity.co.uk/scripts/send_expiry_alerts.php >> /var/log/vulndash/expiry_alerts.log 2>&1
 */

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\AccessExpiryAlerts;

$options = getopt('', ['dry-run']);
$dryRun  = array_key_exists('dry-run', $options);

// --- single-instance lock (same pattern as send_kev_alerts.php) --------------
$lockPath   = sys_get_temp_dir() . '/vulndash_expiry_alerts.lock';
$lockHandle = \VulnDash\Lib\LockFile::open($lockPath);
if ($lockHandle === false) {
    fwrite(STDERR, "Could not open lock file {$lockPath} - check its ownership/permissions.\n");
    exit(1);
}
@chmod($lockPath, 0666);
if (!flock($lockHandle, LOCK_EX | LOCK_NB)) {
    fwrite(STDOUT, "Another expiry alert run is already in progress - exiting.\n");
    exit(0);
}

$exitCode = 0;
try {
    $r = AccessExpiryAlerts::check(null, $dryRun);
    $stamp = date('Y-m-d H:i:s');
    if ($r['lines'] === []) {
        fwrite(STDOUT, "{$stamp} Nothing new to report.\n");
    } else {
        foreach ($r['lines'] as $l) {
            fwrite(STDOUT, "{$stamp} {$l}\n");
        }
        if ($dryRun) {
            fwrite(STDOUT, "{$stamp} Dry run - no email sent, nothing saved.\n");
        } elseif ($r['sent_to'] === []) {
            fwrite(STDERR, "{$stamp} No email could be sent (no recipients, or Resend refused - see the PHP error log). Will retry next run.\n");
            $exitCode = 1;
        } else {
            fwrite(STDOUT, "{$stamp} Emailed: " . implode(', ', $r['sent_to']) . "\n");
        }
    }
} catch (Throwable $e) {
    fwrite(STDERR, date('Y-m-d H:i:s') . ' ERROR: ' . $e->getMessage() . "\n");
    $exitCode = 1;
} finally {
    flock($lockHandle, LOCK_UN);
    fclose($lockHandle);
}

exit($exitCode);
