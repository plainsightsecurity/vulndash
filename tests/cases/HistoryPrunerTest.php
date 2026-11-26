<?php
declare(strict_types=1);

// History retention: old rows go, recent rows and the rows readers depend on
// (live scan requests, the sync cursor) stay, and config can't go below the
// minimums the pages need.

use VulnDash\Lib\Database;
use VulnDash\Lib\HistoryPruner;

function hp_ago(int $days): string
{
    return (new DateTimeImmutable())->modify("-{$days} days")->format('Y-m-d H:i:s');
}

function hp_col(string $sql): array
{
    return array_map('intval', Database::getConnection()->query($sql)->fetchAll(PDO::FETCH_COLUMN));
}

test('API call log keeps the retention window', function () {
    $stmt = Database::getConnection()->prepare('INSERT INTO qualys_api_call_log (id, endpoint, called_at) VALUES (?, ?, ?)');
    $stmt->execute([1, '/fo/asset/host/', hp_ago(200)]);
    $stmt->execute([2, '/fo/asset/host/', hp_ago(91)]);
    $stmt->execute([3, '/fo/asset/host/', hp_ago(89)]);
    $stmt->execute([4, '/fo/asset/host/', hp_ago(0)]);
    $r = HistoryPruner::run();
    eq($r['api_call_log'], ['days' => 90, 'rows' => 2]);
    eq(hp_col('SELECT id FROM qualys_api_call_log ORDER BY id'), [3, 4]);
});

test('dry run counts but deletes nothing', function () {
    Database::getConnection()->prepare('INSERT INTO qualys_api_call_log (endpoint, called_at) VALUES (?, ?)')
        ->execute(['/fo/asset/host/', hp_ago(200)]);
    eq(HistoryPruner::run(true)['api_call_log']['rows'], 1);
    eq(hp_col('SELECT COUNT(*) FROM qualys_api_call_log'), [1]);
});

test('sync log always keeps the latest run and latest success per type', function () {
    $stmt = Database::getConnection()->prepare(
        'INSERT INTO sync_log (id, sync_type, started_at, completed_at, status) VALUES (?, ?, ?, ?, ?)'
    );
    // host_detections: old successes, then a long outage of failures - the
    // last success (id 2) is the incremental cursor and must survive.
    $stmt->execute([1, 'host_detections', hp_ago(300), hp_ago(300), 'success']);
    $stmt->execute([2, 'host_detections', hp_ago(200), hp_ago(200), 'success']);
    $stmt->execute([3, 'host_detections', hp_ago(150), hp_ago(150), 'failed']);
    $stmt->execute([4, 'host_detections', hp_ago(120), hp_ago(120), 'failed']);
    // knowledge_base: one old and one recent success
    $stmt->execute([5, 'knowledge_base', hp_ago(200), hp_ago(200), 'success']);
    $stmt->execute([6, 'knowledge_base', hp_ago(1), hp_ago(1), 'success']);
    $r = HistoryPruner::run();
    eq($r['sync_log']['rows'], 3);
    eq(hp_col('SELECT id FROM sync_log ORDER BY id'), [2, 4, 6], 'last success + latest run kept for host sync');
});

test('scan queue only prunes finished requests', function () {
    seed_estate();
    $stmt = Database::getConnection()->prepare(
        'INSERT INTO scan_request_queue (id, asset_id, qualys_host_id, status, requested_at, processed_at) VALUES (?, 1, ?, ?, ?, ?)'
    );
    $stmt->execute([1, 1001, 'sent', hp_ago(100), hp_ago(100)]);
    $stmt->execute([2, 1002, 'failed', hp_ago(100), hp_ago(100)]);
    $stmt->execute([3, 1003, 'pending', hp_ago(100), null]);
    $stmt->execute([4, 1004, 'processing', hp_ago(100), hp_ago(100)]);
    $stmt->execute([5, 1005, 'sent', hp_ago(1), hp_ago(1)]);
    eq(HistoryPruner::run()['scan_requests']['rows'], 2);
    eq(hp_col('SELECT id FROM scan_request_queue ORDER BY id'), [3, 4, 5]);
});

test('posture snapshots keep 400 days by default', function () {
    seed_estate();
    $stmt = Database::getConnection()->prepare('INSERT INTO asset_vuln_snapshot (snapshot_date, asset_id, open_count) VALUES (?, 1, 5)');
    foreach ([401, 400, 399, 0] as $d) {
        $stmt->execute([substr(hp_ago($d), 0, 10)]);
    }
    eq(HistoryPruner::run()['vuln_snapshots'], ['days' => 400, 'rows' => 1]);
    eq(hp_col('SELECT COUNT(*) FROM asset_vuln_snapshot'), [3]);
});

test('config below a minimum is raised to it', function () {
    set_config('retention.api_call_log_days', 1);
    set_config('retention.vuln_snapshot_days', 10);
    set_config('retention.sync_log_days', 0);
    set_config('retention.scan_request_days', 30);
    eq(HistoryPruner::retentionDays('api_call_log'), 30);
    eq(HistoryPruner::retentionDays('vuln_snapshots'), 90);
    eq(HistoryPruner::retentionDays('sync_log'), 90, 'zero falls back to the default');
    eq(HistoryPruner::retentionDays('scan_requests'), 30);
});

test('batched delete clears more than one batch', function () {
    $pdo = Database::getConnection();
    // 12,001 rows (over two batches) from a digits cross join; a recursive
    // CTE would hit cte_max_recursion_depth (1000) first.
    $pdo->exec("INSERT INTO qualys_api_call_log (endpoint, called_at)
                WITH d(n) AS (SELECT 0 UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4
                              UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9)
                SELECT '/fo/asset/host/', NOW() - INTERVAL 200 DAY
                FROM d a, d b, d c, d e, d f
                WHERE a.n + 10 * b.n + 100 * c.n + 1000 * e.n + 10000 * f.n < 12001");
    eq(HistoryPruner::run()['api_call_log']['rows'], 12001);
    eq(hp_col('SELECT COUNT(*) FROM qualys_api_call_log'), [0]);
});
