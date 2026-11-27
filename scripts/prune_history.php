#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Daily retention for the history tables that would otherwise grow forever:
 * qualys_api_call_log, sync_log, finished on-demand scan requests and the
 * daily posture snapshots (asset_vuln_snapshot). See src/Lib/HistoryPruner.php
 * for what is kept and why. Makes NO Qualys API calls.
 *
 * Retention is set under `retention` in src/config/config.php (defaults:
 * API call log 90 days, sync log 90, scan requests 90, posture snapshots 400);
 * a value below a table's minimum is raised to it.
 *
 * Usage:
 *   php scripts/prune_history.php              # normal cron run
 *   php scripts/prune_history.php --dry-run    # report what WOULD go; deletes nothing
 *
 * Cron (as www-data): once a day, e.g.
 *   20 3 * * *  php /var/www/dashboard.plainsightsecurity.co.uk/scripts/prune_history.php >> /var/log/vulndash/prune_history.log 2>&1
 */

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\HistoryPruner;

$options = getopt('', ['dry-run']);
$dryRun  = array_key_exists('dry-run', $options);

// --- single-instance lock (same pattern as send_kev_alerts.php) --------------
$lockPath   = sys_get_temp_dir() . '/vulndash_prune_history.lock';
$lockHandle = \VulnDash\Lib\LockFile::open($lockPath);
if ($lockHandle === false) {
    fwrite(STDERR, "Could not open lock file {$lockPath} - check its ownership/permissions.\n");
    exit(1);
}
@chmod($lockPath, 0666);
if (!flock($lockHandle, LOCK_EX | LOCK_NB)) {
    fwrite(STDOUT, "Another prune run is already in progress - exiting.\n");
    exit(0);
}

$labels = [
    'api_call_log'   => 'Qualys API call log',
    'sync_log'       => 'Sync log',
    'scan_requests'  => 'Finished scan requests',
    'vuln_snapshots' => 'Posture snapshots',
];

$exitCode = 0;
$stamp = static fn (): string => date('Y-m-d H:i:s');

// Flag rather than exit() in the catch, so finally always releases the lock.
try {
    fwrite(STDOUT, "[{$stamp()}] History prune starting" . ($dryRun ? ' (DRY RUN - nothing deleted)' : '') . ".\n");
    foreach (HistoryPruner::run($dryRun) as $table => $r) {
        fwrite(STDOUT, sprintf("  %-24s older than %3d days: %d row(s) %s\n",
            $labels[$table], $r['days'], $r['rows'], $dryRun ? 'would be deleted' : 'deleted'));
    }
    fwrite(STDOUT, "[{$stamp()}] Done.\n");
} catch (\Throwable $e) {
    fwrite(STDERR, "[{$stamp()}] History prune failed: " . $e->getMessage() . "\n");
    $exitCode = 1;
} finally {
    flock($lockHandle, LOCK_UN);
    fclose($lockHandle);
}

exit($exitCode);
