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
