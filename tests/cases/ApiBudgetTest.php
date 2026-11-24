<?php
declare(strict_types=1);

// Qualys API budget forecast, the host sync's auto interval and the admin
// budget alerts (src/Lib/ApiBudget.php, ApiBudgetAlerts.php).

use VulnDash\Lib\ApiBudget;
use VulnDash\Lib\ApiBudgetAlerts;
use VulnDash\Lib\Database;

/** Today's production shape: 4 versions, 60-min Host List pass, 4 reconciles a day. */
function budget_inputs(array $over = []): array
{
    return $over + [
        'assets' => 35, 'page_size' => 5000, 'inc_pages' => 1.0,
        'versions' => ['2.0', '3.0', '4.0', '5.0'], 'reconcile_versions' => ['2.0', '3.0', '4.0', '5.0'],
        'reconcile_runs_per_day' => 4, 'host_list_interval' => 60,
        'limit' => 25, 'reserve' => 3, 'cron_minutes' => 30, 'intervals' => [30, 60, 120, 240],
    ];
}

function log_call(string $endpoint, string $version, ?int $remaining, string $ago = '1 hour'): void
{
    Database::getConnection()->prepare('INSERT INTO qualys_api_call_log (endpoint, api_version, called_at, http_status, rate_limit_remaining, rate_limit_limit)
        VALUES (?, ?, ?, 200, ?, ?)')->execute([$endpoint, $version, date('Y-m-d H:i:s', strtotime("-$ago")), $remaining, $remaining === null ? null : 25]);
}

test('forecast matches what the API Usage page shows today', function () {
    // 48 runs / 4 versions x 1 page + 1 reconcile each = 13 Host Detection;
    // 24 passes / 4 x 1 page + 1 reconcile = 7 Host List.
    $f = ApiBudget::forecast(budget_inputs(), 30);
    eq($f['2.0'], ['detection' => 13.0, 'host_list' => 7.0]);
    eq(ApiBudget::chooseInterval(budget_inputs()), ['interval' => 30, 'fits' => true, 'peak' => 13.0]);
});

test('a second page on every pull slows the sync to 60 minutes', function () {
    $in = budget_inputs(['assets' => 6000, 'inc_pages' => 2.0]);
    eq(ApiBudget::forecast($in, 30)['2.0']['detection'], 26.0, '24 + 2 reconcile pages');
    eq(ApiBudget::chooseInterval($in)['interval'], 60);
    eq(ApiBudget::forecast($in, 60)['2.0'], ['detection' => 14.0, 'host_list' => 14.0]);
});

test('when nothing fits, the longest interval is chosen and flagged', function () {
    $c = ApiBudget::chooseInterval(budget_inputs(['assets' => 60000, 'inc_pages' => 12.0]));
    eq([$c['interval'], $c['fits']], [240, false]);
});

test('asset capacity per interval', function () {
    $in = budget_inputs(['inc_pages' => 1.0]);
    // 30 min: detection 12 + p, host list 6p + p = 7p <= 22 -> p = 3.
    eq(ApiBudget::assetCapacity($in, 30), 15000);
    // At 60 the hourly Host List pass is already the limit, so no gain;
    // at 120 the pass can only run every 120: 3p + p = 4p <= 22 -> p = 5.
    eq(ApiBudget::assetCapacity($in, 60), 15000);
    eq(ApiBudget::assetCapacity($in, 120), 25000);
    eq(ApiBudget::assetCapacity(budget_inputs(['inc_pages' => 30.0]), 30), null, 'nothing fits');
});

test('the Host List pass can only run as often as the sync', function () {
    $f = ApiBudget::forecast(budget_inputs(), 120);
    eq($f['2.0']['host_list'], 4.0, '12 passes / 4 + 1 reconcile');
});

test('currentInputs reads pages, runs and limit from the database', function () {
    seed_estate(); // 3 assets
    set_config('qualys.host_detection_api_versions', ['2.0', '4.0']);
    set_config('qualys.reconcile_api_versions', ['2.0', '4.0']);
    set_config('sync.reconcile_runs_per_day', 1);
    $pdo = Database::getConnection();
    foreach (range(1, 4) as $i) {
        $pdo->exec("INSERT INTO sync_log (sync_type, started_at, status) VALUES ('host_detections', NOW() - INTERVAL $i HOUR, 'success')");
    }
    foreach (range(1, 9) as $i) {
        log_call('/fo/asset/host/vm/detection/', '2.0', 20 - $i);
    }
    $in = ApiBudget::currentInputs();
    eq($in['assets'], 3);
    eq($in['inc_pages'], 2.0, '(9 calls - 1 reconcile page) / 4 runs');
    eq($in['limit'], 25, 'from Qualys headers');
    eq($in['intervals'], [30, 60, 120, 240]);
});

test('pickVersion skips versions Qualys last reported at the reserve', function () {
    seed_estate();
    log_call('/fo/asset/host/vm/detection/', '3.0', 3);
    log_call('/fo/asset/host/vm/detection/', '4.0', 2);
    $v = ['2.0', '3.0', '4.0', '5.0'];
    eq(ApiBudget::pickVersion($v, 1, '/fo/asset/host/vm/detection/', 3), ['version' => '5.0', 'index' => 3]);
    eq(ApiBudget::pickVersion($v, 0, '/fo/asset/host/vm/detection/', 3), ['version' => '2.0', 'index' => 0]);
    eq(ApiBudget::pickVersion($v, 1, '/fo/asset/host/', 3), ['version' => '3.0', 'index' => 1], 'other endpoints unaffected');
    eq(ApiBudget::pickVersion(['3.0', '4.0'], 0, '/fo/asset/host/vm/detection/', 3), null);
});

test('alerts: low endpoint, interval change, no repeat within 24h', function () {
    seed_estate();
    log_call('/fo/asset/host/', '2.0', 4);
    log_call('/fo/asset/host/', '3.0', 12);
    $log = tempnam(sys_get_temp_dir(), 'vdmail');
    putenv("VULNDASH_MAIL_LOG=$log");
    try {
        $choice = ['interval' => 60, 'fits' => true, 'peak' => 14.0];
        $lines = ApiBudgetAlerts::check(budget_inputs(), $choice, 30);
        eq(count($lines), 2, implode(' | ', $lines));
        ok(str_contains($lines[0], 'slowed from every 30 to every 60'), $lines[0]);
        ok(str_contains($lines[1], '/api/2.0/ Host List: Qualys reports 4 of 25'), $lines[1]);
        $mails = array_map(fn ($l) => json_decode($l, true), array_filter(explode("\n", (string)file_get_contents($log))));
        eq(count($mails), 1, 'one email to the one admin');
        eq($mails[0]['to'], 'admin@test');
        ok(str_contains($mails[0]['subject'], 'admin alert: Qualys API budget'), $mails[0]['subject']);

        eq(ApiBudgetAlerts::check(budget_inputs(), $choice, 60), [], 'same state, nothing new');
        $over = ['interval' => 240, 'fits' => false, 'peak' => 40.0];
        $lines = ApiBudgetAlerts::check(budget_inputs(), $over, 240);
        eq(count($lines), 1);
        ok(str_contains($lines[0], 'Even at every 240 minutes'), $lines[0]);
        eq(ApiBudgetAlerts::check(budget_inputs(), $over, 240), [], '"over" not repeated');
    } finally {
        putenv('VULNDASH_MAIL_LOG');
        unlink($log);
    }
});

test('alerts go to alerts.admin_emails when set', function () {
    seed_estate();
    set_config('alerts.admin_emails', 'ops@example.com');
    $log = tempnam(sys_get_temp_dir(), 'vdmail');
    putenv("VULNDASH_MAIL_LOG=$log");
    try {
        ApiBudgetAlerts::check(budget_inputs(), ['interval' => 60, 'fits' => true, 'peak' => 1.0], 30);
        eq(json_decode(trim((string)file_get_contents($log)), true)['to'], 'ops@example.com');
    } finally {
        putenv('VULNDASH_MAIL_LOG');
        unlink($log);
    }
});

test('the API Usage page shows the forecast', function () {
    seed_estate();
    log_call('/fo/asset/host/vm/detection/', '2.0', 20);
    $out = render_page('admin/api_usage.php');
    ok(!str_contains($out, 'PHPERR'), 'no PHP errors: ' . $out);
    ok(str_contains($out, '<h2>Forecast</h2>'), 'panel');
    ok(str_contains($out, 'every 30 minutes'), 'interval');
    ok(str_contains($out, 'Roughly how many assets fit'), 'capacity');
});

/**
 * The real sync script against a stand-in Qualys server, with a budget so
 * small (one version, limit 10, reserve 3) that only a 240-minute interval
 * fits: the first run goes ahead, the next is skipped without touching
 * Qualys or sync_log, and it runs again once 240 minutes have passed.
 */
test('the sync skips runs until the auto interval has passed', function () {
    seed_estate();
    $dir = sys_get_temp_dir() . '/vdbudget' . bin2hex(random_bytes(4));
    mkdir($dir);
    file_put_contents("$dir/router.php", <<<'PHP'
<?php
file_put_contents(__DIR__ . '/requests.log', $_SERVER['REQUEST_URI'] . "\n", FILE_APPEND);
header('Content-Type: text/xml');
$root = str_contains($_SERVER['REQUEST_URI'], '/vm/detection/') ? 'HOST_LIST_VM_DETECTION_OUTPUT' : 'HOST_LIST_OUTPUT';
echo "<?xml version=\"1.0\"?><{$root}><RESPONSE><DATETIME>2026-11-24T12:00:00Z</DATETIME><HOST_LIST>"
   . "<HOST><ID>1001</ID><IP>10.0.0.1</IP><TRACKING_METHOD>QAGENT</TRACKING_METHOD><DNS_DATA><HOSTNAME>host-a</HOSTNAME></DNS_DATA></HOST>"
   . "</HOST_LIST></RESPONSE></{$root}>";
PHP);
    $port = 40000 + random_int(0, 9999);
    $server = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", "$dir/router.php"], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $p);
    for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
        usleep(100000);
    }
    $cfg = require __DIR__ . '/../config.test.php';
    $cfg['qualys'] += ['host_detection_api_versions' => ['4.0'], 'reconcile_api_versions' => ['4.0'],
        'daily_call_limit' => 10, 'min_calls_reserve' => 3, 'host_list_pass_interval_minutes' => 60, 'host_list_prune_missing' => false];
    $cfg['qualys']['api_base_url'] = "http://127.0.0.1:$port";
    $cfg['sync'] = ['reconcile_runs_per_day' => 0];
    file_put_contents("$dir/config.php", '<?php return ' . var_export($cfg, true) . ';');

    $pdo = Database::getConnection();
    $run = function (array $args = []) use ($dir): string {
        $proc = proc_open(array_merge([PHP_BINARY, __DIR__ . '/../../scripts/sync_host_detections.php'], $args),
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, ['VULNDASH_CONFIG' => "$dir/config.php"] + getenv());
        $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        proc_close($proc);
        return $out;
    };
    $requests = fn (): int => count(array_filter(explode("\n", (string)@file_get_contents("$dir/requests.log"))));
    $syncRuns = fn (): int => (int)$pdo->query("SELECT COUNT(*) FROM sync_log WHERE sync_type = 'host_detections'")->fetchColumn();

    try {
        $out = $run();
        ok(str_contains($out, 'Auto interval: every 240 min'), $out);
        ok(str_contains($out, 'Host detection sync complete'), 'first run went ahead: ' . $out);
        $afterFirst = $requests();
        ok($afterFirst >= 1, 'called Qualys');
        eq($syncRuns(), 1);

        $out = $run();
        ok(str_contains($out, 'Skipping this run'), $out);
        eq($requests(), $afterFirst, 'no Qualys calls when skipped');
        eq($syncRuns(), 1, 'no sync_log row when skipped');

        $out = $run(['--force']);
        ok(str_contains($out, 'Host detection sync complete'), '--force runs: ' . $out);
        eq($syncRuns(), 2);

        // 4 hours later (less a minute of cron jitter) it runs again.
        $state = json_decode((string)$pdo->query("SELECT state_json FROM sync_state WHERE sync_type = 'host_detection_auto'")->fetchColumn(), true);
        $state['last_run_started_at'] -= 239 * 60;
        $pdo->prepare("UPDATE sync_state SET state_json = ? WHERE sync_type = 'host_detection_auto'")->execute([json_encode($state)]);
        $out = $run();
        ok(str_contains($out, 'Host detection sync complete'), 'due again: ' . $out);
        eq($syncRuns(), 3);
    } finally {
        proc_terminate($server);
        proc_close($server);
        array_map('unlink', glob("$dir/*"));
        rmdir($dir);
    }
});
