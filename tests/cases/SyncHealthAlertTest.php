<?php
declare(strict_types=1);

// Sync failure/stall emails (src/Lib/SyncHealthAlerts.php,
// scripts/send_sync_alerts.php): a failure emails only once it has lasted
// the grace period, stuck/overdue email straight away, nothing repeats until
// it changes or the reminder is due, a fix sends one "back to normal", and
// an email nobody received is tried again. Test config has no
// sync.*_expected_interval_minutes, so the defaults apply: KB 1440 minutes
// (overdue after 48h), host detections 180 (overdue/stuck after 6h).

use VulnDash\Lib\Database;
use VulnDash\Lib\SyncHealthAlerts;

function log_sync(string $type, string $status, int $startedMinAgo, ?int $completedMinAgo, ?string $error = null): void
{
    Database::getConnection()->prepare("
        INSERT INTO sync_log (sync_type, status, started_at, completed_at, error_message)
        VALUES (:t, :s, NOW() - INTERVAL :a MINUTE, IF(:c IS NULL, NULL, NOW() - INTERVAL :c2 MINUTE), :e)
    ")->execute(['t' => $type, 's' => $status, 'a' => $startedMinAgo, 'c' => $completedMinAgo, 'c2' => $completedMinAgo ?? 0, 'e' => $error]);
}

/** Both syncs healthy: a success a few minutes ago. */
function healthy_syncs(): void
{
    log_sync('knowledge_base', 'success', 30, 25);
    log_sync('host_detections', 'success', 10, 9);
}

/** Runs $fn with mail captured; returns [result of $fn, emails sent]. */
function capture_mail(callable $fn): array
{
    $log = tempnam(sys_get_temp_dir(), 'vdmail');
    putenv("VULNDASH_MAIL_LOG=$log");
    try {
        $r = $fn();
        $mails = array_map(fn ($l) => json_decode($l, true), array_filter(explode("\n", (string)file_get_contents($log))));
        return [$r, array_values($mails)];
    } finally {
        putenv('VULNDASH_MAIL_LOG');
        unlink($log);
    }
}

function saved_health_state(): array
{
    $v = Database::getConnection()->query("SELECT state_json FROM sync_state WHERE sync_type = 'sync_health_alerts'")->fetchColumn();
    return $v === false ? [] : (array)json_decode((string)$v, true);
}

test('healthy syncs send nothing and save nothing', function () {
    seed_estate();
    healthy_syncs();
    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check());
    eq([$r['problems'], $r['recoveries'], count($mails)], [[], [], 0]);
    eq(saved_health_state(), [], 'no state row');
});

test('a failure emails only after the grace period, then not again until the reminder', function () {
    seed_estate();
    healthy_syncs();
    log_sync('host_detections', 'failed', 4, 3, 'Qualys returned HTTP 503');
    $t = time();
    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check($t));
    eq([$r['problems'], count($mails)], [[], 0], 'not yet - inside the 60-minute grace');
    [$r] = capture_mail(fn () => SyncHealthAlerts::check($t + 59 * 60));
    eq($r['problems'], [], 'still inside the grace');

    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check($t + 61 * 60));
    eq(count($r['problems']), 1);
    ok(str_contains($r['problems'][0], 'Host detection sync failed at') && str_contains($r['problems'][0], 'Qualys returned HTTP 503')
        && str_contains($r['problems'][0], 'Last success:'), $r['problems'][0]);
    eq(array_column($mails, 'to'), ['admin@test'], 'one email to the admin, not the client');
    ok(str_contains($mails[0]['subject'], 'admin alert: sync problem'), $mails[0]['subject']);
    ok(str_contains($mails[0]['text'], '/dashboard'), 'links to the dashboard');

    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check($t + 120 * 60));
    eq([$r['problems'], count($mails)], [[], 0], 'not repeated');
    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check($t + 61 * 60 + 24 * 3600));
    ok(count($mails) === 1 && str_starts_with($r['problems'][0], 'Still not fixed: '), 'reminder after 24h');
});

test('a failure the next run recovers from never emails anyone', function () {
    seed_estate();
    healthy_syncs();
    log_sync('host_detections', 'failed', 4, 3, 'timeout');
    $t = time();
    capture_mail(fn () => SyncHealthAlerts::check($t));
    log_sync('host_detections', 'success', 2, 1);
    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check($t + 90 * 60));
    eq([$r['problems'], $r['recoveries'], count($mails)], [[], [], 0], 'no problem and no "recovered" email');
    eq(saved_health_state(), [], 'forgotten');
});

test('once fixed, one "back to normal" email, then silence', function () {
    seed_estate();
    healthy_syncs();
    log_sync('host_detections', 'failed', 4, 3, 'timeout');
    $t = time();
    capture_mail(fn () => SyncHealthAlerts::check($t));
    capture_mail(fn () => SyncHealthAlerts::check($t + 61 * 60));
    log_sync('host_detections', 'success', 2, 1);
    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check($t + 70 * 60));
    eq([$r['problems'], count($r['recoveries']), count($mails)], [[], 1, 1]);
    ok(str_contains($r['recoveries'][0], 'Host detection sync is working again'), $r['recoveries'][0]);
    ok(str_contains($mails[0]['subject'], 'syncs back to normal'), $mails[0]['subject']);
    [, $mails] = capture_mail(fn () => SyncHealthAlerts::check($t + 80 * 60));
    eq(count($mails), 0, 'not repeated');
});

test('stuck and overdue email straight away, together in one email', function () {
    seed_estate();
    log_sync('knowledge_base', 'success', 3 * 1440, 3 * 1440 - 5);          // 3 days ago: overdue (> 48h)
    log_sync('host_detections', 'success', 11 * 60, 11 * 60 - 1);
    log_sync('host_detections', 'running', 10 * 60, null);                  // running 10h: stuck (> 6h)
    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check());
    eq(count($r['problems']), 2, implode(' | ', $r['problems']));
    ok(str_contains($r['problems'][0], "Knowledge Base sync hasn't succeeded") && str_contains($r['problems'][0], 'check cron'), $r['problems'][0]);
    ok(str_contains($r['problems'][1], 'Host detection sync has said "running" since'), $r['problems'][1]);
    eq(count($mails), 1, 'one email for both');
});

test('a new run starting is neutral, and a change of problem emails again', function () {
    seed_estate();
    healthy_syncs();
    log_sync('host_detections', 'failed', 4, 3, 'timeout');
    $t = time();
    capture_mail(fn () => SyncHealthAlerts::check($t));
    capture_mail(fn () => SyncHealthAlerts::check($t + 61 * 60));            // failure emailed

    log_sync('host_detections', 'running', 1, null);
    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check($t + 65 * 60));
    eq([$r['problems'], $r['recoveries'], count($mails)], [[], [], 0], '"running" neither clears nor repeats');

    log_sync('host_detections', 'failed', 1, 0, 'timeout again');
    [, $mails] = capture_mail(fn () => SyncHealthAlerts::check($t + 70 * 60));
    eq(count($mails), 0, 'failing again is the same problem - no new email');

    Database::getConnection()->exec("DELETE FROM sync_log WHERE sync_type = 'host_detections'");
    log_sync('host_detections', 'success', 8 * 60, 8 * 60 - 1);
    log_sync('host_detections', 'running', 7 * 60, null);                   // running 7h: stuck
    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check($t + 75 * 60));
    ok(count($mails) === 1 && str_contains($r['problems'][0], 'has said "running"'), 'failed -> stuck emails again');
});

test('dry run sends and saves nothing; alerts.sync_health => false turns it off', function () {
    seed_estate();
    log_sync('knowledge_base', 'success', 3 * 1440, 3 * 1440 - 5);
    log_sync('host_detections', 'success', 10, 9);
    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check(null, true));
    eq([count($r['problems']), count($mails)], [1, 0], 'dry run reports but sends nothing');
    eq(saved_health_state(), [], 'dry run saved nothing');
    set_config('alerts.sync_health', false);
    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check());
    eq([$r['problems'], count($mails)], [[], 0], 'off');
});

test('an alert nobody received is sent on the next run', function () {
    // No accounts yet, so no admin recipients.
    log_sync('knowledge_base', 'success', 3 * 1440, 3 * 1440 - 5);
    log_sync('host_detections', 'success', 10, 9);
    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check());
    eq([count($r['problems']), $r['sent_to'], count($mails)], [1, [], 0]);
    seed_estate();
    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check());
    eq([count($r['problems']), array_column($mails, 'to')], [1, ['admin@test']], 'sent once there is someone to send to');
});

test('the script: dry run, real run, exit codes', function () {
    seed_estate();
    log_sync('knowledge_base', 'success', 3 * 1440, 3 * 1440 - 5);
    log_sync('host_detections', 'success', 10, 9);
    $run = function (array $args): array {
        $log = tempnam(sys_get_temp_dir(), 'vdmail');
        $proc = proc_open([PHP_BINARY, __DIR__ . '/../../scripts/send_sync_alerts.php', ...$args],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, getenv() + ['VULNDASH_MAIL_LOG' => $log]);
        $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        $code = proc_close($proc);
        $n = count(array_filter(explode("\n", (string)file_get_contents($log))));
        unlink($log);
        return [$code, $out, $n];
    };
    [$code, $out, $n] = $run(['--dry-run']);
    ok($code === 0 && $n === 0 && str_contains($out, 'PROBLEM  Knowledge Base sync') && str_contains($out, 'Dry run'), $out);
    [$code, $out, $n] = $run([]);
    ok($code === 0 && $n === 1 && str_contains($out, 'Emailed: admin@test'), $out);
    [$code, $out, $n] = $run([]);
    ok($code === 0 && $n === 0 && str_contains($out, 'Nothing new to report'), $out);
});

/** Both exploit-intel feeds loaded $kevHoursAgo / $epssHoursAgo hours ago. */
function exploit_feeds(int $kevHoursAgo, int $epssHoursAgo): void
{
    $pdo = Database::getConnection();
    $pdo->exec("INSERT INTO cisa_kev (cve, synced_at) VALUES ('CVE-2026-0001', NOW() - INTERVAL $kevHoursAgo HOUR)");
    $pdo->exec("INSERT INTO epss_scores (cve, epss, percentile, synced_at) VALUES ('CVE-2026-0001', 0.5, 0.9, NOW() - INTERVAL $epssHoursAgo HOUR)");
}

test('exploit intel sync: on the panel, healthy when both feeds are fresh', function () {
    seed_estate();
    healthy_syncs();
    log_sync('exploit_intel', 'success', 60, 59);
    exploit_feeds(1, 1);
    $byType = array_column(\VulnDash\Lib\SyncStatusRepository::getSyncStatuses(), null, 'sync_type');
    eq([$byType['exploit_intel']['state'], $byType['exploit_intel']['label']], ['healthy', 'Exploit intel sync (CISA KEV + EPSS)']);
    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check());
    eq([$r['problems'], count($mails)], [[], 0]);
    $page = render_page('dashboard.php', '', 'admin');
    ok(!str_contains($page, 'PHPERR') && str_contains($page, 'Exploit intel sync (CISA KEV + EPSS)'), 'card on the dashboard');
});

test('exploit intel sync: a failure emails after the grace period like the others', function () {
    seed_estate();
    healthy_syncs();
    exploit_feeds(1, 1);
    log_sync('exploit_intel', 'success', 400, 399);
    log_sync('exploit_intel', 'failed', 5, 4, 'all attempted feed fetches failed: KEV feed failed: HTTP 403 | EPSS feed failed: timeout');
    $t = time();
    eq(capture_mail(fn () => SyncHealthAlerts::check($t))[0]['problems'], [], 'inside the grace');
    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check($t + 61 * 60));
    ok(count($mails) === 1 && str_contains($r['problems'][0], 'Exploit intel sync (CISA KEV + EPSS) failed at')
        && str_contains($r['problems'][0], 'HTTP 403'), implode(' | ', $r['problems']));
});

test('exploit intel sync: one feed stale while runs still succeed is a warning, emailed and shown', function () {
    seed_estate();
    healthy_syncs();
    log_sync('exploit_intel', 'success', 60, 59);   // runs keep "succeeding" on EPSS alone
    exploit_feeds(30, 1);                            // KEV last loaded 30h ago (> 2 x 6h)
    $byType = array_column(\VulnDash\Lib\SyncStatusRepository::getSyncStatuses(), null, 'sync_type');
    eq($byType['exploit_intel']['state'], 'warning');
    eq(array_column($byType['exploit_intel']['stale_feeds'], 'feed'), ['CISA KEV feed']);

    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check());
    ok(count($mails) === 1 && str_contains($r['problems'][0], 'CISA KEV feed last refreshed')
        && str_contains($r['problems'][0], 'Runs still succeed on the other feed'), implode(' | ', $r['problems']));
    $page = render_page('dashboard.php', '', 'admin');
    ok(str_contains($page, 'CISA KEV feed last refreshed') && str_contains($page, 'sync-status-warning'), 'amber card with the reason');

    Database::getConnection()->exec('UPDATE cisa_kev SET synced_at = NOW()');   // feed back
    [$r, $mails] = capture_mail(fn () => SyncHealthAlerts::check());
    ok(count($mails) === 1 && str_contains($r['recoveries'][0], 'Exploit intel sync (CISA KEV + EPSS) is working again'), 'recovery');
});

test('exploit intel sync: an empty feed table counts as stale', function () {
    seed_estate();
    log_sync('exploit_intel', 'success', 60, 59);
    Database::getConnection()->exec("INSERT INTO epss_scores (cve, epss, percentile) VALUES ('CVE-2026-0001', 0.5, 0.9)");
    $byType = array_column(\VulnDash\Lib\SyncStatusRepository::getSyncStatuses(), null, 'sync_type');
    eq($byType['exploit_intel']['stale_feeds'], [['feed' => 'CISA KEV feed', 'last' => null]]);
});
