<?php
declare(strict_types=1);

// The nightly backup and weekly backup check cards (SyncStatusRepository::
// backupStatuses()), read from the status file the backup scripts in
// config/backup/ write, and the alert emails for them (SyncHealthAlerts).
// Also runs the real plainsight-backup-status helper.

use VulnDash\Lib\SyncHealthAlerts;
use VulnDash\Lib\SyncStatusRepository;

function backup_status_file(?array $data): string
{
    $f = sys_get_temp_dir() . '/vdbackup_' . bin2hex(random_bytes(4)) . '.json';
    if ($data !== null) {
        file_put_contents($f, json_encode($data));
    }
    set_config('backup.status_file', $f);
    return $f;
}

function backup_cards(): array
{
    return array_column(SyncStatusRepository::backupStatuses(), null, 'sync_type');
}

/** Runs $fn with mail captured; returns [result, emails]. */
function backup_mail(callable $fn): array
{
    $log = tempnam(sys_get_temp_dir(), 'vdmail');
    putenv("VULNDASH_MAIL_LOG=$log");
    try {
        $r = $fn();
        return [$r, array_values(array_filter(explode("\n", (string)file_get_contents($log))))];
    } finally {
        putenv('VULNDASH_MAIL_LOG');
        unlink($log);
    }
}

function ago(int $hours): string
{
    return date('c', time() - $hours * 3600);
}

test('no status file yet: both cards "never run", with how to fix it, and no alerts', function () {
    seed_estate();
    backup_status_file(null);
    $c = backup_cards();
    eq([$c['backup']['state'], $c['backup_check']['state']], ['never_run', 'never_run']);
    ok(str_contains($c['backup']['notes'][0], 'install the backup scripts from config/backup/'), $c['backup']['notes'][0]);
    eq(SyncHealthAlerts::check(null, true)['problems'], [], 'never_run is neutral');
});

test('healthy, warning, failed, running and stuck are read from the file', function () {
    seed_estate();
    $f = backup_status_file([
        'backup' => ['status' => 'ok', 'last_run' => ago(3), 'last_success' => ago(3), 'message' => 'Dump 96M, backed up and spot-checked (5%).'],
        'check'  => ['status' => 'warning', 'last_run' => ago(30), 'last_success' => ago(30), 'message' => 'Integrity check passed; restore test SKIPPED - 1G free.'],
    ]);
    $c = backup_cards();
    eq([$c['backup']['state'], $c['backup']['notes']], ['healthy', ['Dump 96M, backed up and spot-checked (5%).']]);
    eq($c['backup']['last_success_at'], date('Y-m-d H:i:s', strtotime(ago(3))), 'times shown in local time');
    eq($c['backup_check']['state'], 'warning');

    file_put_contents($f, json_encode(['backup' => ['status' => 'failed', 'last_run' => ago(1), 'last_success' => ago(25), 'message' => 'restic backup failed']]));
    $c = backup_cards();
    eq([$c['backup']['state'], $c['backup']['last_error_message'], $c['backup']['notes']], ['failed', 'restic backup failed', []]);

    file_put_contents($f, json_encode(['backup' => ['status' => 'running', 'last_run' => ago(1), 'last_success' => ago(25)]]));
    eq(backup_cards()['backup']['state'], 'running');
    file_put_contents($f, json_encode(['backup' => ['status' => 'running', 'last_run' => ago(30), 'last_success' => ago(50)]]));
    eq(backup_cards()['backup']['state'], 'stuck', 'running for over a day');
});

test('overdue after 48 hours (backup) and 14 days (check)', function () {
    seed_estate();
    $f = backup_status_file([
        'backup' => ['status' => 'ok', 'last_run' => ago(47), 'last_success' => ago(47)],
        'check'  => ['status' => 'ok', 'last_run' => ago(13 * 24), 'last_success' => ago(13 * 24)],
    ]);
    eq(array_column(backup_cards(), 'state'), ['healthy', 'healthy']);
    file_put_contents($f, json_encode([
        'backup' => ['status' => 'ok', 'last_run' => ago(49), 'last_success' => ago(49)],
        'check'  => ['status' => 'ok', 'last_run' => ago(15 * 24), 'last_success' => ago(15 * 24)],
    ]));
    eq(array_column(backup_cards(), 'state'), ['overdue', 'overdue']);
});

test('alerts: a failed backup emails after the grace period; overdue names the systemd timer', function () {
    seed_estate();
    \VulnDash\Lib\Database::getConnection()->exec("INSERT INTO sync_log (sync_type, status, started_at, completed_at) VALUES
        ('knowledge_base', 'success', NOW() - INTERVAL 30 MINUTE, NOW() - INTERVAL 25 MINUTE),
        ('host_detections', 'success', NOW() - INTERVAL 10 MINUTE, NOW() - INTERVAL 9 MINUTE)");
    $f = backup_status_file(['backup' => ['status' => 'failed', 'last_run' => ago(1), 'last_success' => ago(25), 'message' => 'restic backup failed']]);
    $t = time();
    eq(backup_mail(fn () => SyncHealthAlerts::check($t))[0]['problems'], [], 'inside the grace');
    [$r, $mails] = backup_mail(fn () => SyncHealthAlerts::check($t + 61 * 60));
    ok(count($mails) === 1 && str_contains($r['problems'][0], 'Nightly backup (restic) failed') && str_contains($r['problems'][0], 'restic backup failed'),
        implode(' | ', $r['problems']));

    file_put_contents($f, json_encode(['backup' => ['status' => 'ok', 'last_run' => ago(1), 'last_success' => ago(1)]]));
    [$r] = backup_mail(fn () => SyncHealthAlerts::check($t + 62 * 60));
    ok(str_contains($r['recoveries'][0] ?? '', 'Nightly backup (restic) is working again'), 'recovery');

    file_put_contents($f, json_encode(['check' => ['status' => 'ok', 'last_run' => ago(20 * 24), 'last_success' => ago(20 * 24)]]));
    [$r] = backup_mail(fn () => SyncHealthAlerts::check($t + 63 * 60));
    ok(str_contains($r['problems'][0] ?? '', "Weekly backup check hasn't succeeded") && str_contains($r['problems'][0], 'systemctl list-timers'),
        implode(' | ', $r['problems']));
});

test('the dashboard shows both cards with their message', function () {
    seed_estate();
    $f = backup_status_file(['check' => ['status' => 'ok', 'last_run' => ago(2), 'last_success' => ago(2),
        'message' => 'Integrity check passed; backup from 2026-11-28 02:40 restored in 41s - users 15/15 (restored/live).']]);
    putenv("PLAINSIGHT_BACKUP_STATUS=$f");    // the page renders in its own process
    try {
        $page = render_page('dashboard.php', '', 'admin');
    } finally {
        putenv('PLAINSIGHT_BACKUP_STATUS');
        @unlink($f);
    }
    ok(!str_contains($page, 'PHPERR') && str_contains($page, 'Nightly backup (restic)') && str_contains($page, 'Weekly backup check'), 'cards');
    ok(str_contains($page, 'restored in 41s - users 15/15'), 'message under the card');
});

test('plainsight-backup-status writes the file the cards read', function () {
    seed_estate();
    $f = backup_status_file(null);
    $dirMode = substr(sprintf('%o', fileperms(dirname($f))), -4);   // e.g. 1777 for /tmp
    $bin = __DIR__ . '/../../config/backup/plainsight-backup-status';
    $run = function (array $args) use ($bin, $f): int {
        $p = proc_open([PHP_BINARY, $bin, ...$args], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, getenv() + ['PLAINSIGHT_BACKUP_STATUS' => $f]);
        stream_get_contents($pipes[1]);
        stream_get_contents($pipes[2]);
        return proc_close($p);
    };
    eq($run(['backup', 'last_run=now', 'status=running']), 0);
    eq($run(['backup', 'status=ok', 'last_success=now', 'message=Dump 96M, done.']), 0);
    $d = json_decode((string)file_get_contents($f), true);
    ok(isset($d['backup']['last_run']) && $d['backup']['status'] === 'ok' && strtotime($d['backup']['last_success']) >= time() - 60, json_encode($d));
    eq(substr(sprintf('%o', fileperms($f)), -4), '0644', 'readable by www-data');
    clearstatcache();
    eq(substr(sprintf('%o', fileperms(dirname($f))), -4), $dirMode, 'an existing directory keeps its permissions');

    $newDir = sys_get_temp_dir() . '/vdbackupdir_' . bin2hex(random_bytes(4)) . '/sub';
    $p = proc_open([PHP_BINARY, $bin, 'check', 'status=ok'], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null,
        getenv() + ['PLAINSIGHT_BACKUP_STATUS' => "$newDir/status.json"]);
    stream_get_contents($pipes[1]);
    stream_get_contents($pipes[2]);
    proc_close($p);
    eq(substr(sprintf('%o', fileperms($newDir)), -4), '0755', 'a directory it creates is 0755');
    @unlink("$newDir/status.json");
    @rmdir($newDir);
    @rmdir(dirname($newDir));
    eq(backup_cards()['backup']['state'], 'healthy');
    eq($run(['nonsense', 'a=b']), 2, 'bad section refused');
    eq($run(['check', 'novalue']), 2, 'bad pair refused');
    @unlink($f);
});
