<?php
declare(strict_types=1);

// sync_host_detections.php's Host List pass rotates through the API versions
// on its own counter, so with the pass on every other run (60-minute
// interval, 30-minute sync) it no longer lands on the same two versions as
// the detection pull. Runs the real script against a stand-in Qualys server
// (PHP's built-in server) that logs every request path.

use VulnDash\Lib\Database;

/**
 * Starts the fake Qualys, runs the sync $runs times and returns the
 * [detection versions, host list versions] actually requested, in order.
 * $passEveryOtherRun simulates the 60-minute pass interval by letting the
 * pass's last-started time look an hour old before every other run.
 */
function run_host_sync(int $runs, bool $passEveryOtherRun): array
{
    $dir = sys_get_temp_dir() . '/vdfakeq' . bin2hex(random_bytes(4));
    mkdir($dir);
    $log = "$dir/requests.log";
    file_put_contents("$dir/router.php", <<<'PHP'
<?php
file_put_contents(__DIR__ . '/requests.log', $_SERVER['REQUEST_URI'] . "\n", FILE_APPEND);
header('Content-Type: text/xml');
$host = '<HOST><ID>5001</ID><IP>10.0.0.5</IP><TRACKING_METHOD>QAGENT</TRACKING_METHOD>'
      . '<DNS_DATA><HOSTNAME>rot-host</HOSTNAME></DNS_DATA><OS>Linux</OS>'
      . '</HOST>';
$root = str_contains($_SERVER['REQUEST_URI'], '/vm/detection/') ? 'HOST_LIST_VM_DETECTION_OUTPUT' : 'HOST_LIST_OUTPUT';
echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?><{$root}><RESPONSE><DATETIME>2026-11-24T12:00:00Z</DATETIME><HOST_LIST>{$host}</HOST_LIST></RESPONSE></{$root}>";
PHP);
    $port = 20000 + random_int(0, 9999);
    $server = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", "$dir/router.php"], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $p);
    for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
        usleep(100000);
    }

    // The suite's own config with Qualys pointed at the fake server.
    $cfg = require __DIR__ . '/../config.test.php';
    $cfg['qualys']['api_base_url'] = "http://127.0.0.1:$port";
    $cfg['qualys']['host_detection_api_versions'] = ['2.0', '3.0', '4.0', '5.0'];
    $cfg['qualys']['host_list_pass_interval_minutes'] = $passEveryOtherRun ? 60 : 0;
    file_put_contents("$dir/config.php", '<?php return ' . var_export($cfg, true) . ';');

    $pdo = Database::getConnection();
    $outputs = [];
    try {
        for ($run = 0; $run < $runs; $run++) {
            if ($passEveryOtherRun) {
                $lastStarted = $run % 2 === 0 ? time() - 3600 : time() - 60;
                $pdo->prepare("REPLACE INTO sync_state (sync_type, state_json) VALUES ('host_list_pass', ?)")
                    ->execute([json_encode(['last_started_at' => $lastStarted])]);
            }
            $proc = proc_open([PHP_BINARY, __DIR__ . '/../../scripts/sync_host_detections.php'],
                [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, ['VULNDASH_CONFIG' => "$dir/config.php"] + getenv());
            $outputs[] = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
            proc_close($proc);
        }
    } finally {
        proc_terminate($server);
        proc_close($server);
    }

    $detection = $hostList = [];
    foreach (array_filter(explode("\n", (string)@file_get_contents($log))) as $uri) {
        preg_match('#/api/([0-9.]+)/fo/asset/host/(vm/detection/)?#', $uri, $m);
        if (!$m) {
            continue;
        }
        if (!empty($m[2])) {
            $detection[] = $m[1];
        } else {
            $hostList[] = $m[1];
        }
    }
    array_map('unlink', glob("$dir/*"));
    rmdir($dir);
    return [$detection, $hostList, $outputs];
}

test('with the pass on every other run, Host List still uses every version', function () {
    [$detection, $hostList, $outputs] = run_host_sync(8, true);
    eq($detection, ["2.0","3.0","4.0","5.0","2.0","3.0","4.0","5.0"], "detection rotation unchanged");
    eq($hostList, ['2.0', '3.0', '4.0', '5.0'], 'host list spread over all four (was 2.0, 4.0, 2.0, 4.0)');
    ok(str_contains($outputs[0], 'New-host pass (Host List): using /api/2.0/'), 'logs its version');
    eq((int)Database::getConnection()->query("SELECT COUNT(*) FROM assets WHERE qualys_host_id = 5001")->fetchColumn(), 1, 'host stored');
});

test('with the pass on every run, Host List rotates on its own counter', function () {
    [$detection, $hostList] = run_host_sync(5, false);
    eq($detection, ['2.0', '3.0', '4.0', '5.0', '2.0']);
    eq($hostList, ['2.0', '3.0', '4.0', '5.0', '2.0']);
});
