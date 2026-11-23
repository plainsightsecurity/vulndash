<?php
declare(strict_types=1);

// New-KEV alert emails (scripts/send_kev_alerts.php): baseline silently,
// then one email per run when new KEV findings appear in the account's own
// scope, never for another tenant's, and retry after a failed send.

use VulnDash\Lib\Database;
use VulnDash\Lib\KevAlertRepository;

/** Runs the real script with mail captured to a file; returns [exit code, output, emails]. */
function run_kev_alerts(array $args = []): array
{
    $log = tempnam(sys_get_temp_dir(), 'vdmail');
    $cmd = [PHP_BINARY, __DIR__ . '/../../scripts/send_kev_alerts.php', ...$args];
    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null,
        getenv() + ['VULNDASH_MAIL_LOG' => $log]);
    $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
    $code = proc_close($proc);
    $mails = array_map(fn ($l) => json_decode($l, true), array_filter(explode("\n", (string)file_get_contents($log))));
    unlink($log);
    return [$code, $out, $mails];
}

function new_kev_finding(int $assetId, int $qid): void
{
    $pdo = Database::getConnection();
    $pdo->exec("INSERT IGNORE INTO knowledge_base (qid, title, severity_level, cvss3_base) VALUES ($qid, 'New exploited thing', 5, 9.1)");
    $pdo->exec("INSERT INTO qid_exploit (qid, is_kev, cve_count) VALUES ($qid, 1, 1) ON DUPLICATE KEY UPDATE is_kev = 1");
    $pdo->exec("INSERT INTO host_detections (asset_id, qid, status, first_found, last_found, times_found, effective_cvss_score, effective_cvss_source, is_ce_plus_fail)
                VALUES ($assetId, $qid, 'New', NOW(), NOW(), 1, 9.1, 'CVSS3', 1)");
}

test('first run baselines silently, second run sends nothing', function () {
    seed_estate();
    [$code, $out, $mails] = run_kev_alerts();
    eq([$code, count($mails)], [0, 0], 'first run');
    ok(str_contains($out, 'Baselined client: 1 existing'), 'client baselined with its 1 KEV finding');
    [, , $mails] = run_kev_alerts();
    eq(count($mails), 0, 'second run');
});

test('new KEV finding emails the owning client and admins only', function () {
    seed_estate();
    run_kev_alerts();
    new_kev_finding(1, 6001);           // host-a, ClientA
    [, $out, $mails] = run_kev_alerts();
    eq(array_column($mails, 'to'), ['admin@test', 'client@test']);
    ok(str_contains($mails[1]['text'], '/vulnerabilities?kev=1'), 'links to the KEV list');
    ok(!str_contains($mails[1]['text'], 'host-a') && !str_contains($mails[1]['text'], '6001'), 'no detail in the email');
    [, , $mails] = run_kev_alerts();
    eq(count($mails), 0, 'not repeated');
});

test('another tenant\'s or an untagged asset\'s KEV never reaches the client', function () {
    seed_estate();
    run_kev_alerts();
    new_kev_finding(2, 6002);           // host-b, ClientB
    new_kev_finding(3, 6003);           // host-untagged
    [, , $mails] = run_kev_alerts();
    eq(array_column($mails, 'to'), ['admin@test']);
});

test('CISA adding an existing finding to KEV triggers an alert', function () {
    seed_estate();
    run_kev_alerts();
    Database::getConnection()->exec('UPDATE qid_exploit SET is_kev = 1 WHERE qid = 5003'); // on host-a
    [, , $mails] = run_kev_alerts();
    eq(array_column($mails, 'to'), ['admin@test', 'client@test']);
});

test('alerts off: no email; back on: re-baselined without a backlog', function () {
    seed_estate();
    run_kev_alerts();
    KevAlertRepository::setEnabled(2, false);
    new_kev_finding(1, 6004);
    [, , $mails] = run_kev_alerts();
    eq(array_column($mails, 'to'), ['admin@test'], 'off');
    KevAlertRepository::setEnabled(2, true);
    [, , $mails] = run_kev_alerts();
    eq(count($mails), 0, 'back on: baseline, no email');
    new_kev_finding(1, 6005);
    [, , $mails] = run_kev_alerts();
    eq(array_column($mails, 'to'), ['admin@test', 'client@test'], 'next new one alerts');
});

test('a fixed finding that comes back alerts again', function () {
    seed_estate();
    run_kev_alerts();
    $pdo = Database::getConnection();
    $pdo->exec("UPDATE host_detections SET status = 'Fixed' WHERE qid = 5001");
    run_kev_alerts();
    $pdo->exec("UPDATE host_detections SET status = 'Active' WHERE qid = 5001");
    [, , $mails] = run_kev_alerts();
    eq(array_column($mails, 'to'), ['admin@test', 'client@test']);
});

test('dry run sends and records nothing', function () {
    seed_estate();
    run_kev_alerts();
    new_kev_finding(1, 6006);
    [, $out, $mails] = run_kev_alerts(['--dry-run']);
    eq(count($mails), 0);
    ok(str_contains($out, 'WOULD EMAIL: client'), 'reports who would be emailed');
    [, , $mails] = run_kev_alerts();
    eq(count($mails), 2, 'real run still sends');
});

test('a KEV finding the client has hidden is not alerted to them', function () {
    seed_estate();
    run_kev_alerts();
    new_kev_finding(1, 6007);
    \VulnDash\Lib\HiddenIssueRepository::hideAsset(6007, 1, 2);
    [, , $mails] = run_kev_alerts();
    eq(array_column($mails, 'to'), ['admin@test']);
});
