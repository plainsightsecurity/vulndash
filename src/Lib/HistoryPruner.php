<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Retention for the history tables that nothing else trims:
 * qualys_api_call_log, sync_log, finished scan_request_queue rows and
 * asset_vuln_snapshot. (audit_log, login_throttle and detection_resolutions
 * already prune themselves.) Run daily by scripts/prune_history.php.
 *
 * Each table's retention comes from config `retention.*`, but is never
 * allowed below what a reader of that table still needs - a typo in config
 * must not be able to blank the API Usage page or the Trends chart:
 *   - qualys_api_call_log: API Usage page shows 30 days; ApiBudget reads 7.
 *   - sync_log: dashboard status strip and ApiBudget read at most 24 hours,
 *     but the newest row and newest successful row per sync_type are always
 *     kept whatever their age - the host and KB syncs take their incremental
 *     cursor from the last success, so losing it after a long outage would
 *     force a full pull and burn the Qualys API budget.
 *   - scan_request_queue: only sent/failed rows are pruned; pending and
 *     processing rows are live work. Readers look back hours, not days.
 *   - asset_vuln_snapshot: Trends offers up to a 90-day window.
 *
 * Deletes run in batches so a first run over a large backlog doesn't hold
 * long locks on a small server.
 */
final class HistoryPruner
{
    private const BATCH = 5000;

    /** table key => [config key, default days, minimum days] */
    public const TABLES = [
        'api_call_log'    => ['retention.api_call_log_days',  90,  30],
        'sync_log'        => ['retention.sync_log_days',      90,   7],
        'scan_requests'   => ['retention.scan_request_days',  90,   7],
        'vuln_snapshots'  => ['retention.vuln_snapshot_days', 400, 90],
    ];

    /** Configured retention for a table, raised to its minimum if set lower. */
    public static function retentionDays(string $table): int
    {
        [$key, $default, $min] = self::TABLES[$table];
        $days = (int)(Config::get($key) ?? $default);
        if ($days <= 0) {
            $days = $default;
        }
        return max($days, $min);
    }

    /**
     * Prunes (or, with $dryRun, only counts) every table.
     *
     * @return array<string, array{days: int, rows: int}>
     */
    public static function run(bool $dryRun = false): array
    {
        $out = [];
        foreach (array_keys(self::TABLES) as $table) {
            $days = self::retentionDays($table);
            [$where, $params] = self::condition($table, $days);
            $out[$table] = [
                'days' => $days,
                'rows' => $dryRun ? self::count($table, $where, $params) : self::delete($table, $where, $params),
            ];
        }
        return $out;
    }

    /** @return array{0: string, 1: array<int, mixed>} WHERE clause (positional params) */
    private static function condition(string $table, int $days): array
    {
        // Cutoff computed in PHP, in the app's zone like every other datetime
        // the app writes, rather than an INTERVAL bind.
        $cutoff = (new \DateTimeImmutable())->modify("-{$days} days");
        $dt = $cutoff->format('Y-m-d H:i:s');

        switch ($table) {
            case 'api_call_log':
                return ['called_at < ?', [$dt]];

            case 'scan_requests':
                return ["status IN ('sent', 'failed') AND processed_at IS NOT NULL AND processed_at < ?", [$dt]];

            case 'vuln_snapshots':
                return ['snapshot_date < ?', [$cutoff->format('Y-m-d')]];

            case 'sync_log':
                $keep = self::syncLogKeepIds();
                $where = 'started_at < ?';
                if ($keep !== []) {
                    $where .= ' AND id NOT IN (' . implode(',', array_fill(0, count($keep), '?')) . ')';
                }
                return [$where, array_merge([$dt], $keep)];
        }
        throw new \InvalidArgumentException("Unknown table {$table}");
    }

    /**
     * The rows sync_log readers depend on regardless of age: per sync_type,
     * the newest run (status strip) and the newest success (incremental
     * cursor). Ordered the same way those readers order them.
     *
     * @return int[]
     */
    private static function syncLogKeepIds(): array
    {
        $pdo = Database::getConnection();
        $ids = [];
        $types = $pdo->query('SELECT DISTINCT sync_type FROM sync_log')->fetchAll(\PDO::FETCH_COLUMN);
        $latest = $pdo->prepare('SELECT id FROM sync_log WHERE sync_type = ? ORDER BY started_at DESC, id DESC LIMIT 1');
        $success = $pdo->prepare("SELECT id FROM sync_log WHERE sync_type = ? AND status = 'success' AND completed_at IS NOT NULL
                                  ORDER BY completed_at DESC, id DESC LIMIT 1");
        foreach ($types as $type) {
            foreach ([$latest, $success] as $stmt) {
                $stmt->execute([$type]);
                $id = $stmt->fetchColumn();
                if ($id !== false) {
                    $ids[] = (int)$id;
                }
            }
        }
        return array_values(array_unique($ids));
    }

    private static function tableName(string $table): string
    {
        return [
            'api_call_log'   => 'qualys_api_call_log',
            'sync_log'       => 'sync_log',
            'scan_requests'  => 'scan_request_queue',
            'vuln_snapshots' => 'asset_vuln_snapshot',
        ][$table];
    }

    /** @param array<int, mixed> $params */
    private static function count(string $table, string $where, array $params): int
    {
        $stmt = Database::getConnection()->prepare('SELECT COUNT(*) FROM ' . self::tableName($table) . ' WHERE ' . $where);
        $stmt->execute($params);
        return (int)$stmt->fetchColumn();
    }

    /** @param array<int, mixed> $params */
    private static function delete(string $table, string $where, array $params): int
    {
        $stmt = Database::getConnection()->prepare(
            'DELETE FROM ' . self::tableName($table) . ' WHERE ' . $where . ' LIMIT ' . self::BATCH
        );
        $total = 0;
        do {
            $stmt->execute($params);
            $n = $stmt->rowCount();
            $total += $n;
        } while ($n === self::BATCH);
        return $total;
    }
}
