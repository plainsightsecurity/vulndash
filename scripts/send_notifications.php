#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Sends the opt-in "new activity" email nudges. Intended to run ONCE A DAY from
 * cron (as www-data); the per-account cadence gate inside NotificationRepository
 * decides who is actually due on any given run, so a daily invocation serves both
 * daily and weekly subscribers correctly. It makes NO Qualys API calls and does
 * not touch the Qualys rate budget.
 *
 * What it does:
 *   1. Snapshot the current max host_detections.id once (the watermark every
 *      account nudged on THIS run is advanced to - a single consistent cut, so
 *      anything landing mid-run is simply caught next run rather than split).
 *   2. Ask NotificationRepository for opted-in, active accounts whose cadence
 *      (daily/weekly) has elapsed.
 *   3. For each, ask VulnerabilityRepository::scopeHasNewActivity() whether that
 *      account's OWN tag scope contains anything new since its stored watermark -
 *      the same fail-closed tag scoping, open/non-info filter and hidden-exclusion
 *      as the dashboard, so the nudge and what they'll see on login agree.
 *   4. If (and only if) there's something new, send the nudge and advance that
 *      account's watermark + last-sent timestamp. Nothing new -> nothing sent and
 *      no state changed, so the account is nudged the moment something does land.
 *
 * The email itself deliberately contains NO vulnerability information (see
 * Mailer::sendActivityDigestEmail) - it only says "there's new activity, sign in
 * to review" and links to the login page. Security-posture detail never leaves
 * the authenticated, TLS-served dashboard.
 *
 * A send that fails (Mailer returns false - unconfigured Resend key, network,
 * non-2xx) leaves that account's watermark/last-sent untouched, so it's retried
 * on the next run rather than silently skipped.
 *
 * Usage:
 *   php scripts/send_notifications.php              # normal daily cron run
 *   php scripts/send_notifications.php --dry-run    # report who WOULD be nudged;
 *                                                   # sends nothing, writes nothing
 *
 * Suggested cron (as www-data), e.g. 07:00 daily:
 *   0 7 * * *  php /path/to/scripts/send_notifications.php >> /var/log/vulndash/notifications.log 2>&1
 */

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Config;
use VulnDash\Lib\Database;
use VulnDash\Lib\Mailer;
use VulnDash\Lib\NotificationRepository;
use VulnDash\Lib\UserRepository;
use VulnDash\Lib\VulnerabilityRepository;

$options = getopt('', ['dry-run']);
$dryRun  = array_key_exists('dry-run', $options);

// Where the nudge points people to sign in. Built from the app's own base_url;
// never a token or deep link - the email carries no scoped access of any kind.
$baseUrl   = rtrim((string)(Config::get('app.base_url') ?? 'https://dashboard.plainsightsecurity.co.uk'), '/');
$signInUrl = $baseUrl . '/login';

// --- single-instance lock (mirrors sync_exploit_intel.php) ------------------
$lockPath   = sys_get_temp_dir() . '/vulndash_send_notifications.lock';
$lockHandle = \VulnDash\Lib\LockFile::open($lockPath);
if ($lockHandle === false) {
    fwrite(STDERR, "Could not open lock file {$lockPath} - check its ownership/permissions.\n");
    exit(1);
}
@chmod($lockPath, 0666);
if (!flock($lockHandle, LOCK_EX | LOCK_NB)) {
    fwrite(STDOUT, "Another notification run is already in progress - exiting.\n");
    exit(0);
}

$pdo = Database::getConnection();

// A dry run reports only; it never writes a sync_log row either, so it can be run
// freely to preview without leaving a trace or a phantom "run".
$logId = null;
if (!$dryRun) {
    $logStmt = $pdo->prepare('INSERT INTO sync_log (sync_type, started_at, status) VALUES (:type, :started, :status)');
    $logStmt->execute(['type' => 'notifications', 'started' => date('Y-m-d H:i:s'), 'status' => 'running']);
    $logId = (int)$pdo->lastInsertId();
}

$exitCode = 0;

try {
    fwrite(STDOUT, "Notification run starting" . ($dryRun ? " (DRY RUN - no emails, no writes)" : "") . ".\n");
    fwrite(STDOUT, "  Sign-in link: {$signInUrl}\n");

    // One consistent watermark for everyone nudged this run (see step 1 above).
    $watermark = VulnerabilityRepository::currentMaxDetectionId();
    fwrite(STDOUT, "  Current max detection id (watermark to advance to): {$watermark}\n");

    $recipients = NotificationRepository::dueRecipients();
    fwrite(STDOUT, "  Due recipients (opted-in, active, cadence elapsed): " . count($recipients) . "\n");

    $sent = 0;
    $noActivity = 0;
    $failed = 0;

    foreach ($recipients as $r) {
        $userId  = $r['id'];
        $isAdmin = $r['is_admin'] === 1;
        // Admins are scoped platform-wide inside scopeHasNewActivity(); their tag
        // list is irrelevant there, so skip the lookup for them.
        $tagIds  = $isAdmin ? [] : UserRepository::getEffectiveTagIds($userId);
        $since   = $r['notify_watermark_id'] ?? 0;

        $hasNew = VulnerabilityRepository::scopeHasNewActivity($tagIds, $isAdmin, $since, $userId);

        if (!$hasNew) {
            $noActivity++;
            continue;
        }

        if ($dryRun) {
            fwrite(STDOUT, "    WOULD NOTIFY: {$r['username']} <{$r['email']}> "
                . "({$r['notify_frequency']}, new since detection id {$since})\n");
            $sent++;
            continue;
        }

        $ok = Mailer::sendActivityDigestEmail($r['email'], $r['username'], $signInUrl);
        if ($ok) {
            NotificationRepository::recordSent($userId, $watermark);
            $sent++;
            fwrite(STDOUT, "    Notified {$r['username']} <{$r['email']}> ({$r['notify_frequency']}).\n");
        } else {
            $failed++;
            fwrite(STDERR, "    Send FAILED for {$r['username']} <{$r['email']}> - "
                . "left un-notified for retry next run (see error_log for the Resend/cURL detail).\n");
        }
    }

    $summary = ($dryRun ? "Would notify {$sent}" : "Notified {$sent}")
        . ", {$noActivity} due but nothing new"
        . ($failed > 0 ? ", {$failed} send failure(s)" : "")
        . ".";
    fwrite(STDOUT, "  {$summary}\n");

    if (!$dryRun) {
        $pdo->prepare('UPDATE sync_log SET status = :status, completed_at = :completed, records_processed = :count, error_message = :note WHERE id = :id')
            ->execute([
                'status'    => 'success',
                'completed' => date('Y-m-d H:i:s'),
                'count'     => $sent,
                'note'      => $failed > 0 ? "{$failed} send failure(s) - see error_log; left for retry" : null,
                'id'        => $logId,
            ]);
    }

    fwrite(STDOUT, "Notification run complete.\n");
} catch (\Throwable $e) {
    if (!$dryRun && $logId !== null) {
        $pdo->prepare('UPDATE sync_log SET status = :status, completed_at = :completed, error_message = :err WHERE id = :id')
            ->execute(['status' => 'failed', 'completed' => date('Y-m-d H:i:s'), 'err' => $e->getMessage(), 'id' => $logId]);
    }
    fwrite(STDERR, 'Notification run failed: ' . $e->getMessage() . "\n");
    $exitCode = 1;
} finally {
    flock($lockHandle, LOCK_UN);
    fclose($lockHandle);
}

// exit() outside finally, same reason as sync_exploit_intel.php: exit() from
// inside catch would skip finally and leak the lock on every failure.
exit($exitCode);
