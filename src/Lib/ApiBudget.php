<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Qualys API budget forecast for the host endpoints, and the host sync's
 * automatic interval (2026-11-24).
 *
 * The licence gives 25 calls per endpoint per API version per rolling 24h.
 * Host List and Host Detection usage depends on how many pages each pull
 * needs, so it grows in steps with the estate: everything fits while one
 * page (qualys.host_page_size hosts) covers every agent, and roughly doubles
 * the moment it doesn't. This class works out, per API version per day:
 *
 *   Host Detection = incremental sync runs  x pages per incremental pull
 *                  + reconcile runs         x pages per full pull
 *   Host List      = Host List passes       x pages per full pull
 *                  + reconcile runs         x pages per full pull
 *
 * shared evenly across the versions each job rotates through. "Pages per
 * full pull" is ceil(assets / page size). "Pages per incremental pull" is
 * observed from the last 24h of the call log (it depends on how many agents
 * reported in the window, not the estate size), never taken as below 1.
 *
 * The usable budget is Qualys's limit (highest rate_limit_limit seen in the
 * call log over the last week, else qualys.daily_call_limit, default 25)
 * less qualys.min_calls_reserve - the same reserve QualysApiClient refuses
 * to dip into.
 *
 * Auto interval: sync_host_detections.php runs from cron every
 * sync.host_detection_cron_minutes (default 30). With
 * sync.host_detection_auto_interval on (default), each run picks the
 * shortest of sync.host_detection_auto_intervals (default 30, 60, 120, 240
 * minutes) whose forecast fits, and skips itself until that long has passed
 * since the last run that went ahead. So the sync slows down before the
 * budget runs out at 11pm, and speeds back up when it fits again.
 *
 * These are KnowledgeBase-free numbers: the KB sync is twice daily and its
 * usage doesn't depend on the estate size, so it's shown as actuals only.
 */
final class ApiBudget
{
    public const DEFAULT_LIMIT          = 25;
    public const DEFAULT_RESERVE        = 3;
    public const DEFAULT_PAGE_SIZE      = 1000;
    public const DEFAULT_CRON_MINUTES   = 30;
    public const DEFAULT_INTERVALS      = [30, 60, 120, 240];
    public const DEFAULT_RECONCILE_RUNS = 4;

    /**
     * Everything the forecast needs, gathered from config and the database.
     *
     * @return array{assets: int, page_size: int, inc_pages: float, versions: string[], reconcile_versions: string[],
     *               reconcile_runs_per_day: int, host_list_interval: int, limit: int, reserve: int,
     *               cron_minutes: int, intervals: int[]}
     */
    public static function currentInputs(): array
    {
        $pdo = Database::getConnection();

        $versions = array_values(array_map('strval', (array)(Config::get('qualys.host_detection_api_versions') ?? ['2.0', '3.0', '4.0'])));
        $reconcileVersions = Config::get('qualys.reconcile_api_versions');
        $reconcileVersions = is_array($reconcileVersions) && $reconcileVersions !== []
            ? array_values(array_map('strval', $reconcileVersions))
            : [(string)(Config::get('qualys.reconcile_api_version') ?? Config::get('qualys.api_version') ?? '4.0')];

        $pageSize = (int)(Config::get('qualys.host_page_size') ?? self::DEFAULT_PAGE_SIZE);
        $pageSize = $pageSize > 0 ? $pageSize : self::DEFAULT_PAGE_SIZE;
        $assets = (int)$pdo->query('SELECT COUNT(*) FROM assets')->fetchColumn();
        $reconcileRuns = max(0, (int)(Config::get('sync.reconcile_runs_per_day') ?? self::DEFAULT_RECONCILE_RUNS));

        // Pages per incremental detection pull, from the last 24h: detection
        // calls, less what the reconcile's full pulls would have used, over
        // the number of sync runs that went ahead.
        $since = date('Y-m-d H:i:s', time() - 86400);
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM qualys_api_call_log WHERE endpoint = '/fo/asset/host/vm/detection/' AND called_at >= :since");
        $stmt->execute(['since' => $since]);
        $detectionCalls = (int)$stmt->fetchColumn();
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM sync_log WHERE sync_type = 'host_detections' AND started_at >= :since");
        $stmt->execute(['since' => $since]);
        $runs = (int)$stmt->fetchColumn();
        $fullPages = self::fullPages($assets, $pageSize);
        $incPages = $runs > 0 ? max(1.0, ($detectionCalls - $reconcileRuns * $fullPages) / $runs) : 1.0;

        // Qualys's own limit when it has told us; the config value otherwise.
        $stmt = $pdo->prepare('SELECT MAX(rate_limit_limit) FROM qualys_api_call_log WHERE called_at >= :since');
        $stmt->execute(['since' => date('Y-m-d H:i:s', time() - 7 * 86400)]);
        $seenLimit = $stmt->fetchColumn();
        $limit = $seenLimit !== null && $seenLimit !== false && (int)$seenLimit > 0
            ? (int)$seenLimit
            : (int)(Config::get('qualys.daily_call_limit') ?? self::DEFAULT_LIMIT);

        $cron = max(1, (int)(Config::get('sync.host_detection_cron_minutes') ?? self::DEFAULT_CRON_MINUTES));
        $intervals = array_map('intval', (array)(Config::get('sync.host_detection_auto_intervals') ?? self::DEFAULT_INTERVALS));
        $intervals = array_values(array_unique(array_filter($intervals, static fn (int $i): bool => $i >= $cron)));
        sort($intervals);
        if ($intervals === []) {
            $intervals = [$cron];
        }

        return [
            'assets'                 => $assets,
            'page_size'              => $pageSize,
            'inc_pages'              => round($incPages, 2),
            'versions'               => $versions !== [] ? $versions : ['4.0'],
            'reconcile_versions'     => $reconcileVersions,
            'reconcile_runs_per_day' => $reconcileRuns,
            'host_list_interval'     => (bool)filter_var(Config::get('qualys.host_list_new_host_pass') ?? true, FILTER_VALIDATE_BOOLEAN)
                ? max(0, (int)(Config::get('qualys.host_list_pass_interval_minutes') ?? 0)) : -1,
            'limit'                  => $limit,
            'reserve'                => max(0, (int)(Config::get('qualys.min_calls_reserve') ?? self::DEFAULT_RESERVE)),
            'cron_minutes'           => $cron,
            'intervals'              => $intervals,
        ];
    }

    public static function fullPages(int $assets, int $pageSize): int
    {
        return max(1, (int)ceil($assets / max(1, $pageSize)));
    }

    /**
     * Forecast calls per day for each API version at a given sync interval.
     *
     * @param array<string, mixed> $in currentInputs()-shaped; 'assets' may be overridden to ask "what if"
     * @return array<string, array{detection: float, host_list: float}> keyed by version
     */
    public static function forecast(array $in, int $intervalMinutes): array
    {
        $fullPages = self::fullPages((int)$in['assets'], (int)$in['page_size']);
        $versions = array_values(array_unique(array_merge($in['versions'], $in['reconcile_versions'])));
        $runsPerDay = 1440 / max(1, $intervalMinutes);

        // The Host List pass only happens on a run that goes ahead, so at a
        // 60-minute pass interval and a 120-minute sync it's every 120.
        $hl = (int)$in['host_list_interval'];
        $hlEvery = $hl < 0 ? null : ($hl <= $intervalMinutes ? $intervalMinutes : (int)(ceil($hl / $intervalMinutes) * $intervalMinutes));
        $passesPerDay = $hlEvery === null ? 0.0 : 1440 / $hlEvery;

        $out = [];
        foreach ($versions as $v) {
            $syncShare = in_array($v, $in['versions'], true) ? 1 / count($in['versions']) : 0.0;
            $reconShare = in_array($v, $in['reconcile_versions'], true) ? (int)$in['reconcile_runs_per_day'] / count($in['reconcile_versions']) : 0.0;
            $out[$v] = [
                'detection' => round($runsPerDay * $syncShare * (float)$in['inc_pages'] + $reconShare * $fullPages, 1),
                'host_list' => round($passesPerDay * $syncShare * $fullPages + $reconShare * $fullPages, 1),
            ];
        }
        return $out;
    }

    /** Busiest endpoint on the busiest version, calls per day. */
    public static function peak(array $forecast): float
    {
        $peak = 0.0;
        foreach ($forecast as $f) {
            $peak = max($peak, $f['detection'], $f['host_list']);
        }
        return $peak;
    }

    public static function usable(array $in): int
    {
        return max(0, (int)$in['limit'] - (int)$in['reserve']);
    }

    /**
     * The shortest candidate interval whose forecast fits the usable budget.
     *
     * @return array{interval: int, fits: bool, peak: float}  fits=false: even the longest doesn't
     */
    public static function chooseInterval(array $in): array
    {
        foreach ($in['intervals'] as $interval) {
            $peak = self::peak(self::forecast($in, $interval));
            if ($peak <= self::usable($in)) {
                return ['interval' => $interval, 'fits' => true, 'peak' => $peak];
            }
        }
        $longest = (int)end($in['intervals']);
        return ['interval' => $longest, 'fits' => false, 'peak' => self::peak(self::forecast($in, $longest))];
    }

    /**
     * Roughly how many assets fit at this interval: whole pages until the
     * forecast goes over. Null if it doesn't fit even at one page.
     */
    public static function assetCapacity(array $in, int $intervalMinutes): ?int
    {
        $fitting = 0;
        for ($pages = 1; $pages <= 200; $pages++) {
            $peak = self::peak(self::forecast(['assets' => $pages * (int)$in['page_size']] + $in, $intervalMinutes));
            if ($peak > self::usable($in)) {
                break;
            }
            $fitting = $pages;
        }
        return $fitting === 0 ? null : $fitting * (int)$in['page_size'];
    }

    /**
     * The auto interval as last decided by the sync (sync_state
     * 'host_detection_auto'), for the API Usage page and the overdue check.
     *
     * @return array{interval?: int, fits?: bool, decided_at?: int, last_run_started_at?: int}
     */
    public static function autoState(): array
    {
        $stmt = Database::getConnection()->prepare("SELECT state_json FROM sync_state WHERE sync_type = 'host_detection_auto'");
        $stmt->execute();
        $state = json_decode((string)$stmt->fetchColumn(), true);
        return is_array($state) ? $state : [];
    }

    public static function autoEnabled(): bool
    {
        return (bool)filter_var(Config::get('sync.host_detection_auto_interval') ?? true, FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * Qualys's last reported "calls left" per version for one endpoint path,
     * from the call log - as of the last call on that pair, and only ever
     * higher now, since calls free up as the rolling window moves.
     *
     * @return array<string, int> version => remaining
     */
    public static function lastRemaining(string $endpoint): array
    {
        $stmt = Database::getConnection()->prepare('
            SELECT l.api_version, l.rate_limit_remaining
            FROM qualys_api_call_log l
            JOIN (
                SELECT api_version, MAX(id) AS id FROM qualys_api_call_log
                WHERE endpoint = :endpoint AND rate_limit_remaining IS NOT NULL AND api_version IS NOT NULL
                  AND called_at >= :since
                GROUP BY api_version
            ) last ON last.id = l.id
        ');
        $stmt->execute(['endpoint' => $endpoint, 'since' => date('Y-m-d H:i:s', time() - 86400)]);
        $out = [];
        foreach ($stmt->fetchAll() as $row) {
            $out[(string)$row['api_version']] = (int)$row['rate_limit_remaining'];
        }
        return $out;
    }

    /**
     * The first version, going round from $startIndex, that Qualys didn't
     * last report as at or below the reserve on $endpoint. Null if every
     * version is that low.
     *
     * @param string[] $versions
     * @return array{version: string, index: int}|null
     */
    public static function pickVersion(array $versions, int $startIndex, string $endpoint, int $reserve): ?array
    {
        $remaining = self::lastRemaining($endpoint);
        $n = count($versions);
        for ($i = 0; $i < $n; $i++) {
            $index = $startIndex + $i;
            $v = $versions[$index % $n];
            if (!isset($remaining[$v]) || $remaining[$v] > $reserve) {
                return ['version' => $v, 'index' => $index];
            }
        }
        return null;
    }
}
