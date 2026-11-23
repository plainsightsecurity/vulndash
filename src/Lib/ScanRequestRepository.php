<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * The on-demand scan work queue (see
 * database/migrations/2026-11-add-scan-request-queue.sql for the table).
 *
 * Two consumers, mirroring AgentUninstallRepository:
 *   - The Assets page calls enqueue() when a user asks for a scan, and
 *     latestForAssets() to show each row's request status.
 *   - The cron worker (scripts/process_scan_requests.php) calls
 *     claimPending()/markSent()/markFailed()/releaseToPending() to send the
 *     queue to Qualys in one bulk on-demand scan call, whenever
 *     sendWindow() allows.
 *
 * Access control lives in enqueue(): requested ids are re-resolved through
 * the caller's own tag scope, so nobody can queue a scan for an asset outside
 * their tags. Any account may request scans within its scope - a scan changes
 * nothing on the host beyond running the agent's normal check early, and
 * however many requests are queued, they cost one API call per send.
 *
 * Per-asset cooldown (2026-11): the call budget is safe however often people
 * click, but the agents aren't - nothing stopped one asset being rescanned
 * out of cycle on every send all day. enqueue() therefore refuses a new
 * request for an asset whose last request was sent to Qualys less than
 * qualys.ods_asset_cooldown_minutes ago (default 60; 0 turns it off). It
 * counts from the send, not the click, because that is when the agent was
 * asked to scan; a failed request asked for nothing, so it doesn't count.
 * Admins are exempt, for testing and for the odd deliberate rescan.
 */
class ScanRequestRepository
{
    /** Endpoint path as logged in qualys_api_call_log - see sendWindow(). */
    public const ODS_ENDPOINT = '/qps/rest/1.0/ods/ca/agentasset';

    /**
     * Defaults for the send budget - see sendWindow(). 22 of Qualys's 25
     * calls per 24h, leaving 3 for manual runs such as
     * scripts/check_ods_api_versions.php; 10 minutes between sends, so a
     * burst of clicks is batched into one call rather than spending several.
     */
    public const DEFAULT_DAILY_BUDGET = 22;
    public const DEFAULT_MIN_GAP_MINUTES = 10;

    /** Default for qualys.ods_asset_cooldown_minutes - see the class docblock. */
    public const DEFAULT_ASSET_COOLDOWN_MINUTES = 60;

    /** Qualys's rolling window for the on-demand scan endpoint's limit. */
    private const WINDOW_SECONDS = 86400;

    /** How long a finished request keeps showing on the Assets page. */
    private const RECENT_HOURS = 24;

    public const NOTE_NOT_FOUND_IN_QUALYS = 'Not found in Qualys asset inventory - the host is no longer in Qualys, so no scan could be requested.';

    /**
     * Queue a scan for each in-scope asset that doesn't already have one
     * waiting and isn't in its cooldown (see the class docblock). Everything
     * else is counted and reported, not silently dropped.
     *
     * @param int[] $assetIds internal assets.id values from the form
     * @param int[] $tagIds   the caller's assigned tag ids (Auth::tagIds())
     * @return array{queued:int, already_queued:int, not_permitted:int, cooling_down:int, hostnames:string[], cooldown_until:array<string, string>, cooldown_minutes:int}
     *         cooldown_until maps each cooling-down asset's display name to
     *         when it may be requested again ('H:i', Europe/London)
     */
    public static function enqueue(array $assetIds, int $requestedBy, array $tagIds, bool $isAdmin): array
    {
        $assetIds = array_values(array_unique(array_filter(array_map('intval', $assetIds), static fn ($v) => $v > 0)));
        $cooldownMinutes = $isAdmin ? 0 : self::assetCooldownMinutes();
        $result = ['queued' => 0, 'already_queued' => 0, 'not_permitted' => 0, 'cooling_down' => 0, 'hostnames' => [], 'cooldown_until' => [], 'cooldown_minutes' => $cooldownMinutes];
        if ($assetIds === []) {
            return $result;
        }

        $scopedById = [];
        foreach (VulnerabilityRepository::getScopedAssetsByIds($assetIds, $tagIds, $isAdmin) as $row) {
            $scopedById[(int)$row['id']] = $row;
        }

        $lastSent = $cooldownMinutes > 0 ? self::lastSentWithin(array_keys($scopedById), $cooldownMinutes) : [];

        $insert = Database::getConnection()->prepare(
            'INSERT INTO scan_request_queue
                (asset_id, qualys_host_id, qualys_asset_id, hostname, ip_address, status, requested_by)
             VALUES
                (:asset_id, :qualys_host_id, :qualys_asset_id, :hostname, :ip_address, \'pending\', :requested_by)'
        );

        foreach ($assetIds as $id) {
            if (!isset($scopedById[$id])) {
                $result['not_permitted']++;
                continue;
            }
            $asset = $scopedById[$id];
            if (isset($lastSent[$id])) {
                $result['cooling_down']++;
                $name = (string)($asset['hostname'] ?: $asset['ip_address'] ?: ('host ' . $asset['qualys_host_id']));
                $result['cooldown_until'][$name] = date('H:i', $lastSent[$id] + $cooldownMinutes * 60);
                continue;
            }
            try {
                $insert->execute([
                    'asset_id'        => $id,
                    'qualys_host_id'  => $asset['qualys_host_id'],
                    'qualys_asset_id' => $asset['qualys_asset_id'],
                    'hostname'        => $asset['hostname'],
                    'ip_address'      => $asset['ip_address'],
                    'requested_by'    => $requestedBy,
                ]);
                $result['queued']++;
                $result['hostnames'][] = (string)($asset['hostname'] ?: $asset['ip_address'] ?: ('host ' . $asset['qualys_host_id']));
            } catch (\PDOException $e) {
                // Unique violation on active_dedup: this host already has a
                // request waiting, which will cover this one too.
                if (($e->errorInfo[1] ?? null) === 1062) {
                    $result['already_queued']++;
                    continue;
                }
                throw $e;
            }
        }

        return $result;
    }

    /** qualys.ods_asset_cooldown_minutes, or the default; 0 turns the cooldown off. */
    public static function assetCooldownMinutes(): int
    {
        $value = Config::get('qualys.ods_asset_cooldown_minutes');
        return max(0, $value !== null ? (int)$value : self::DEFAULT_ASSET_COOLDOWN_MINUTES);
    }

    /**
     * When each of these assets last had a request sent to Qualys, as a unix
     * time, for those sent within the last $minutes. Assets with none are
     * absent. Only 'sent' rows count - see the class docblock.
     *
     * @param int[] $assetIds
     * @return array<int, int> assets.id => last send time
     */
    private static function lastSentWithin(array $assetIds, int $minutes): array
    {
        $assetIds = array_values(array_filter(array_map('intval', $assetIds), static fn ($v) => $v > 0));
        if ($assetIds === [] || $minutes <= 0) {
            return [];
        }
        $in = implode(',', array_fill(0, count($assetIds), '?'));
        $stmt = Database::getConnection()->prepare(
            'SELECT asset_id, MAX(processed_at) AS last_sent
             FROM scan_request_queue
             WHERE status = \'sent\'
               AND asset_id IN (' . $in . ')
               AND processed_at >= NOW() - INTERVAL ' . $minutes . ' MINUTE
             GROUP BY asset_id'
        );
        $stmt->execute($assetIds);

        $out = [];
        foreach ($stmt->fetchAll() as $row) {
            // processed_at is written with NOW() in the app's own zone.
            $ts = strtotime((string)$row['last_sent']);
            if ($ts !== false) {
                $out[(int)$row['asset_id']] = $ts;
            }
        }
        return $out;
    }

    /**
     * Each asset's most recent request, for the Assets page: always while it
     * is waiting, and for RECENT_HOURS after it was sent or failed. Assets
     * with nothing to show are absent from the result.
     *
     * @param int[] $assetIds
     * @return array<int, array{status:string, requested_at:string, processed_at:?string, last_error:?string}>
     *         keyed by assets.id
     */
    public static function latestForAssets(array $assetIds): array
    {
        $assetIds = array_values(array_unique(array_filter(array_map('intval', $assetIds), static fn ($v) => $v > 0)));
        if ($assetIds === []) {
            return [];
        }
        $in = implode(',', array_fill(0, count($assetIds), '?'));
        $stmt = Database::getConnection()->prepare(
            'SELECT q.asset_id, q.status, q.requested_at, q.processed_at, q.last_error
             FROM scan_request_queue q
             JOIN (
                 SELECT asset_id, MAX(id) AS id
                 FROM scan_request_queue
                 WHERE asset_id IN (' . $in . ')
                 GROUP BY asset_id
             ) latest ON latest.id = q.id
             WHERE q.status IN (\'pending\', \'processing\')
                OR q.processed_at >= NOW() - INTERVAL ' . self::RECENT_HOURS . ' HOUR'
        );
        $stmt->execute($assetIds);

        $out = [];
        foreach ($stmt->fetchAll() as $row) {
            $out[(int)$row['asset_id']] = [
                'status'       => (string)$row['status'],
                'requested_at' => (string)$row['requested_at'],
                'processed_at' => $row['processed_at'] !== null ? (string)$row['processed_at'] : null,
                'last_error'   => $row['last_error'] !== null ? (string)$row['last_error'] : null,
            ];
        }
        return $out;
    }

    /**
     * When the worker may next send, under the on-demand scan endpoint's
     * limit of 25 calls per rolling 24h. Replaces a fixed hourly gap
     * (2026-11-10): a send goes as soon as anything is queued, provided
     *   - fewer than qualys.ods_daily_budget calls were made in the last
     *     24h, and
     *   - at least qualys.ods_min_interval_minutes have passed since the
     *     last call.
     * When the budget is used up, the next send is allowed once enough of
     * the oldest calls in the window are 24h old - the same moment Qualys
     * frees them, since its window is rolling too.
     *
     * Counted from qualys_api_call_log rather than from this queue, so a
     * failed call and a manual probe count, exactly as they do at Qualys.
     * called_at is written with PHP's date() in the app's own zone, which is
     * how strtotime() reads it back here.
     *
     * @return array{calls_24h:int, budget:int, min_gap_minutes:int, next_at:int}
     *         next_at <= time() means a send is allowed now
     */
    public static function sendWindow(?int $now = null): array
    {
        $now ??= time();
        $budget = max(1, (int)(Config::get('qualys.ods_daily_budget') ?? self::DEFAULT_DAILY_BUDGET));
        $gapMinutes = max(0, (int)(Config::get('qualys.ods_min_interval_minutes') ?? self::DEFAULT_MIN_GAP_MINUTES));

        $stmt = Database::getConnection()->prepare(
            'SELECT called_at FROM qualys_api_call_log
             WHERE endpoint = :endpoint AND called_at >= :since
             ORDER BY called_at ASC'
        );
        $stmt->execute([
            'endpoint' => self::ODS_ENDPOINT,
            'since'    => date('Y-m-d H:i:s', $now - self::WINDOW_SECONDS),
        ]);
        $calls = array_values(array_filter(array_map(
            static fn ($v) => strtotime((string)$v),
            $stmt->fetchAll(\PDO::FETCH_COLUMN)
        )));

        $nextAt = $now;
        if ($calls !== []) {
            $nextAt = max($nextAt, end($calls) + $gapMinutes * 60);
        }
        if (count($calls) >= $budget) {
            // The window must lose (count - budget + 1) calls to fit one more,
            // and the oldest go first.
            $nextAt = max($nextAt, $calls[count($calls) - $budget] + self::WINDOW_SECONDS);
        }

        return [
            'calls_24h'       => count($calls),
            'budget'          => $budget,
            'min_gap_minutes' => $gapMinutes,
            'next_at'         => $nextAt,
        ];
    }

    public static function countPending(): int
    {
        return (int)Database::getConnection()
            ->query('SELECT COUNT(*) FROM scan_request_queue WHERE status = \'pending\'')
            ->fetchColumn();
    }

    /**
     * Claim up to $limit pending rows, flipping them to 'processing' and
     * bumping attempts, in one transaction - the same claim as
     * AgentUninstallRepository::claimPending(). attempts in the returned rows
     * already includes this claim.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function claimPending(int $limit = 500): array
    {
        $pdo = Database::getConnection();
        $pdo->beginTransaction();
        try {
            $sel = $pdo->prepare(
                'SELECT id, asset_id, qualys_host_id, qualys_asset_id, hostname, ip_address, attempts
                 FROM scan_request_queue
                 WHERE status = \'pending\'
                 ORDER BY requested_at ASC, id ASC
                 LIMIT ' . (int)$limit . '
                 FOR UPDATE'
            );
            $sel->execute();
            $rows = $sel->fetchAll();

            if ($rows !== []) {
                $ids = array_map(static fn ($r) => (int)$r['id'], $rows);
                $in = implode(',', array_fill(0, count($ids), '?'));
                $pdo->prepare(
                    'UPDATE scan_request_queue
                     SET status = \'processing\', attempts = attempts + 1
                     WHERE id IN (' . $in . ')'
                )->execute($ids);
                foreach ($rows as &$r) {
                    $r['attempts'] = (int)$r['attempts'] + 1;
                }
                unset($r);
            }

            $pdo->commit();
            return $rows;
        } catch (\Throwable $e) {
            $pdo->rollBack();
            throw $e;
        }
    }

    /**
     * Read-only view of pending rows, for the worker's --dry-run.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function listPending(int $limit = 500): array
    {
        $stmt = Database::getConnection()->prepare(
            'SELECT id, asset_id, qualys_host_id, qualys_asset_id, hostname, ip_address, attempts
             FROM scan_request_queue
             WHERE status = \'pending\'
             ORDER BY requested_at ASC, id ASC
             LIMIT ' . (int)$limit
        );
        $stmt->execute();
        return $stmt->fetchAll();
    }

    /** Records the AssetView id on both the queue row and the asset, so the next request needs no lookup. */
    public static function storeAssetViewId(int $rowId, ?int $assetId, int $assetViewId): void
    {
        $pdo = Database::getConnection();
        $pdo->prepare('UPDATE scan_request_queue SET qualys_asset_id = :aid WHERE id = :id')
            ->execute(['aid' => $assetViewId, 'id' => $rowId]);
        if ($assetId !== null) {
            $pdo->prepare('UPDATE assets SET qualys_asset_id = :aid WHERE id = :id')
                ->execute(['aid' => $assetViewId, 'id' => $assetId]);
        }
    }

    /** @param int[] $ids */
    public static function markSent(array $ids): void
    {
        self::setStatus($ids, 'sent', null);
    }

    /** @param int[] $ids */
    public static function markFailed(array $ids, string $error): void
    {
        self::setStatus($ids, 'failed', $error);
    }

    /**
     * Back to 'pending' for the next send, keeping the reason it didn't go
     * this time in last_error so the Assets page tooltip can show it.
     *
     * @param int[] $ids
     */
    public static function releaseToPending(array $ids, ?string $reason = null): void
    {
        self::setStatus($ids, 'pending', $reason);
    }

    /** @param int[] $ids */
    private static function setStatus(array $ids, string $status, ?string $error): void
    {
        $ids = array_values(array_filter(array_map('intval', $ids), static fn ($v) => $v > 0));
        if ($ids === []) {
            return;
        }
        $in = implode(',', array_fill(0, count($ids), '?'));
        $processedAt = in_array($status, ['sent', 'failed'], true) ? 'NOW()' : 'NULL';
        Database::getConnection()->prepare(
            'UPDATE scan_request_queue
             SET status = ?, last_error = ?, processed_at = ' . $processedAt . '
             WHERE id IN (' . $in . ')'
        )->execute(array_merge([$status, $error], $ids));
    }
}
