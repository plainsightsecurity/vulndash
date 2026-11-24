#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Emails accounts when a vulnerability on the CISA Known Exploited
 * Vulnerabilities (KEV) list newly appears in their scope - a new detection of
 * a KEV-listed QID, or CISA adding an existing finding's CVE to the list.
 * Makes NO Qualys API calls; it reads what the host detection and exploit
 * intel syncs have already stored.
 *
 * For each active account with KEV alerts on (users.kev_alerts, under
 * Preferences):
 *   - not yet baselined: record every KEV finding currently in scope as seen,
 *     send nothing (no backlog email when alerts are first switched on or an
 *     account is created);
 *   - otherwise: KEV findings in scope now, minus those already seen. Any new
 *     -> one email (however many new findings) and record them as seen.
 * A failed send records nothing, so the next run retries it.
 *
 * Scope is the dashboard's (VulnerabilityRepository::getOpenKevKeys()):
 * fail-closed tag scoping, open findings only, the account's hidden findings
 * excluded. Admins are platform-wide, so they hear about every client.
 *
 * The email carries no vulnerability detail (see Mailer::sendKevAlertEmail()),
 * only a link to the KEV-filtered vulnerability list behind the login.
 *
 * Usage:
 *   php scripts/send_kev_alerts.php              # normal cron run
 *   php scripts/send_kev_alerts.php --dry-run    # report who WOULD be emailed;
 *                                                # sends nothing, writes nothing
 *
 * Cron (as www-data): hourly, after the host detection sync has had time to
 * land, e.g.
 *   55 * * * *  php /var/www/dashboard.plainsightsecurity.co.uk/scripts/send_kev_alerts.php >> /var/log/vulndash/kev_alerts.log 2>&1
 */

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Config;
use VulnDash\Lib\KevAlertRepository;
use VulnDash\Lib\Mailer;
use VulnDash\Lib\UserRepository;
use VulnDash\Lib\VulnerabilityRepository;

$options = getopt('', ['dry-run']);
$dryRun  = array_key_exists('dry-run', $options);

$baseUrl   = rtrim((string)(Config::get('app.base_url') ?? 'https://dashboard.plainsightsecurity.co.uk'), '/');
$reviewUrl = $baseUrl . '/vulnerabilities?kev=1';

// --- single-instance lock (same pattern as send_notifications.php) ----------
$lockPath   = sys_get_temp_dir() . '/vulndash_send_kev_alerts.lock';
$lockHandle = fopen($lockPath, 'c');
if ($lockHandle === false) {
    fwrite(STDERR, "Could not open lock file {$lockPath} - check its ownership/permissions.\n");
    exit(1);
}
@chmod($lockPath, 0666);
if (!flock($lockHandle, LOCK_EX | LOCK_NB)) {
    fwrite(STDOUT, "Another KEV alert run is already in progress - exiting.\n");
    exit(0);
}

$exitCode = 0;
$stamp = static fn (): string => date('Y-m-d H:i:s');

try {
    fwrite(STDOUT, "[{$stamp()}] KEV alert run starting" . ($dryRun ? ' (DRY RUN - no emails, no writes)' : '') . ".\n");

    if (!$dryRun) {
        $pruned = KevAlertRepository::pruneClosed();
        if ($pruned > 0) {
            fwrite(STDOUT, "  Forgot {$pruned} seen finding(s) that are no longer open.\n");
        }
    }

    $recipients = KevAlertRepository::recipients();
    fwrite(STDOUT, '  Accounts with KEV alerts on: ' . count($recipients) . "\n");

    $emailed = $baselined = $nothingNew = $failed = 0;

    foreach ($recipients as $r) {
        $tagIds  = $r['is_admin'] ? [] : UserRepository::getEffectiveTagIds($r['id']);
        $current = VulnerabilityRepository::getOpenKevKeys($tagIds, $r['is_admin'], $r['id']);

        if (!$r['baselined']) {
            if ($dryRun) {
                fwrite(STDOUT, "    WOULD BASELINE: {$r['username']} (" . count($current) . " KEV finding(s) recorded, no email)\n");
            } else {
                KevAlertRepository::markSeen($r['id'], $current);
                KevAlertRepository::markBaselined($r['id']);
                fwrite(STDOUT, "    Baselined {$r['username']}: " . count($current) . " existing KEV finding(s) recorded, no email.\n");
            }
            $baselined++;
            continue;
        }

        $new = array_values(array_diff($current, KevAlertRepository::seenKeys($r['id'])));
        if ($new === []) {
            $nothingNew++;
            continue;
        }

        if ($dryRun) {
            fwrite(STDOUT, "    WOULD EMAIL: {$r['username']} <{$r['email']}> - " . count($new) . " new KEV finding(s)\n");
            $emailed++;
            continue;
        }

        if (Mailer::sendKevAlertEmail($r['email'], $r['username'], $reviewUrl)) {
            KevAlertRepository::markSeen($r['id'], $new);
            fwrite(STDOUT, "    Emailed {$r['username']} <{$r['email']}> - " . count($new) . " new KEV finding(s).\n");
            $emailed++;
        } else {
            $failed++;
            fwrite(STDERR, "    Send FAILED for {$r['username']} <{$r['email']}> - left for retry next run (see error_log).\n");
        }
    }

    fwrite(STDOUT, sprintf(
        "  %s %d, baselined %d, nothing new for %d%s.\n",
        $dryRun ? 'Would email' : 'Emailed',
        $emailed,
        $baselined,
        $nothingNew,
        $failed > 0 ? ", {$failed} send failure(s)" : ''
    ));
    fwrite(STDOUT, "[{$stamp()}] KEV alert run complete.\n");
} catch (\Throwable $e) {
    fwrite(STDERR, 'KEV alert run failed: ' . $e->getMessage() . "\n");
    $exitCode = 1;
} finally {
    flock($lockHandle, LOCK_UN);
    fclose($lockHandle);
}

// exit() outside finally: exiting from inside catch would skip finally and
// leave the lock held.
exit($exitCode);
