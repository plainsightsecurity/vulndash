<?php
declare(strict_types=1);

// Disk space and database size (src/Lib/ServerHealth.php) and the disk
// alerts (src/Lib/ServerHealthAlerts.php, run by send_sync_alerts.php).
// Alert tests pass their own filesystem figures; the rest read this machine.

use VulnDash\Lib\Database;
use VulnDash\Lib\ServerHealth;
use VulnDash\Lib\ServerHealthAlerts;

function fake_disk(float $usedPct): array
{
    $total = 100 * 1024 ** 3;
    return [['mount' => '/', 'holds' => ['system', 'MySQL data'], 'total' => (float)$total,
             'free' => $total * (1 - $usedPct / 100), 'used_pct' => $usedPct]];
}

function disk_mail(callable $fn): array
{
    $log = tempnam(sys_get_temp_dir(), 'vdmail');
    putenv("VULNDASH_MAIL_LOG=$log");
    try {
        $r = $fn();
        return [$r, array_values(array_map(fn ($l) => json_decode($l, true), array_filter(explode("\n", (string)file_get_contents($log)))))];
    } finally {
        putenv('VULNDASH_MAIL_LOG');
        unlink($log);
    }
}

test('reads real disks and the database size', function () {
    seed_estate();
    $fs = ServerHealth::filesystems();
    ok($fs !== [], 'at least one filesystem');
    ok(in_array('system', array_merge(...array_column($fs, 'holds')), true), 'the root filesystem is included');
    ok(in_array('MySQL data', array_merge(...array_column($fs, 'holds')), true), "MySQL's data directory is included");
    foreach ($fs as $f) {
        ok($f['total'] > 0 && $f['free'] >= 0 && $f['used_pct'] >= 0 && $f['used_pct'] <= 100, json_encode($f));
    }
    eq(count(array_unique(array_column($fs, 'mount'))), count($fs), 'each filesystem once');
    $db = ServerHealth::databaseSize(3);
    ok($db['total'] > 0 && count($db['tables']) === 3 && $db['tables'][0]['bytes'] >= $db['tables'][2]['bytes'], 'largest first');
    eq([ServerHealth::bytes(512), ServerHealth::bytes(1536), ServerHealth::bytes(3.2 * 1024 ** 3), ServerHealth::bytes(250 * 1024 ** 3)],
       ['512 B', '1.5 KB', '3.2 GB', '250 GB']);
});

test('alerts at 85%, once; reminder after 24h; recovery only below 80%', function () {
    seed_estate();
    set_config('alerts.disk_warn_percent', 85);   // the default (tests/config.test.php uses 99)
    $t = time();
    eq(disk_mail(fn () => ServerHealthAlerts::check($t, false, fake_disk(84.9)))[1], [], 'under the line: nothing');

    [$r, $mails] = disk_mail(fn () => ServerHealthAlerts::check($t, false, fake_disk(86.0)));
    eq(count($mails), 1);
    eq($mails[0]['to'], 'admin@test');
    ok(str_contains($mails[0]['subject'], 'admin alert: disk space'), $mails[0]['subject']);
    ok(str_contains($r['problems'][0], 'Disk / (system, MySQL data) is 86% full - 14.0 GB free of 100 GB.')
        && str_contains($r['problems'][0], 'MySQL, the cron logs and the nightly backups all stop'), $r['problems'][0]);
    ok(str_contains($mails[0]['text'], '/admin/api_usage#server'), 'links to the Server panel');

    eq(disk_mail(fn () => ServerHealthAlerts::check($t + 3600, false, fake_disk(90.0)))[1], [], 'not repeated within 24h');
    [$r, $mails] = disk_mail(fn () => ServerHealthAlerts::check($t + 25 * 3600, false, fake_disk(90.0)));
    ok(count($mails) === 1 && str_starts_with($r['problems'][0], 'Still not fixed: '), 'reminder');

    eq(disk_mail(fn () => ServerHealthAlerts::check($t + 26 * 3600, false, fake_disk(82.0)))[1], [], '82%: not yet back to normal');
    [$r, $mails] = disk_mail(fn () => ServerHealthAlerts::check($t + 27 * 3600, false, fake_disk(79.0)));
    ok(count($mails) === 1 && str_starts_with($r['recoveries'][0], 'Back to normal: ') && str_contains($mails[0]['subject'], 'back to normal'), 'recovery');
    eq(disk_mail(fn () => ServerHealthAlerts::check($t + 28 * 3600, false, fake_disk(79.0)))[1], [], 'recovery sent once');
});

test('threshold from config; dry run saves nothing; an unsent alert is retried', function () {
    seed_estate();
    set_config('alerts.disk_warn_percent', 70);
    ok(count(ServerHealthAlerts::check(null, true, fake_disk(72.0))['problems']) === 1, 'custom threshold');
    eq((int)Database::getConnection()->query("SELECT COUNT(*) FROM sync_state WHERE sync_type = 'server_health_alerts'")->fetchColumn(), 0, 'dry run saved nothing');

    Database::getConnection()->exec('UPDATE users SET is_admin = 0 WHERE id = 1');   // nobody to send to
    [$r, $mails] = disk_mail(fn () => ServerHealthAlerts::check(null, false, fake_disk(75.0)));
    ok(count($r['problems']) === 1 && $mails === [] && $r['sent_to'] === [], 'unsent');
    Database::getConnection()->exec('UPDATE users SET is_admin = 1 WHERE id = 1');
    [, $mails] = disk_mail(fn () => ServerHealthAlerts::check(null, false, fake_disk(75.0)));
    eq(array_column($mails, 'to'), ['admin@test'], 'sent on the next run');
});

test('pages: Server panel on API Usage, Disk space card on the dashboard, admins only', function () {
    seed_estate();
    $api = render_page('admin/api_usage.php', '', 'admin');
    ok(!str_contains($api, 'PHPERR') && str_contains($api, 'id="server"') && str_contains($api, 'Database: <strong>'), 'Server panel');
    $dash = render_page('dashboard.php', '', 'admin');
    ok(!str_contains($dash, 'PHPERR') && str_contains($dash, '>Disk space</span>') && str_contains($dash, '% full on'), 'dashboard card');
    ok(!str_contains(render_page('dashboard.php', '', 'client'), 'Disk space'), 'not for clients');
});
