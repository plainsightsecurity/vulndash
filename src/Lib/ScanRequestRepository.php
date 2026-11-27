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
     * calls per 24h, leaving 3 for manual runs; 10 minutes between sends, so a
     * burst of clicks is batched into one call rather than spending several.
     */
    public const DEFAULT_DAILY_BUDGET = 22;
    public const DEFAULT_MIN_GAP_MINUTES = 10;

    /**
     * Default for qualys.ods_burst - see sendWindow(): how many sends can go
     * close together (10 minutes apart) after a quiet spell before pacing
     * spreads the rest of the budget through the day.
     */
    public const DEFAULT_BURST = 6;

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
     * limit of 25 calls per rolling 24h. Three rules; the latest wins:
     *
     *   1. Gap: at least qualys.ods_min_interval_minutes (default 10) since
     *      the last call, so a burst of clicks goes out as one call.
     *   2. Pacing (2026-11-25): a token bucket holding up to
     *      qualys.ods_burst calls (default 6), refilling at what's left of the
     *      budget after a burst, spread over 24h ((22 - 6) a day = one every
     *      90 minutes). When it's been quiet, sends go every 10 minutes as
     *      before; under steady demand they settle to one every ~90 minutes
     *      all day, instead of the whole day's budget going by lunchtime and
     *      later requests waiting until the next morning. Burst plus refill
     *      never exceeds the budget in any 24h, so steady demand never runs
     *      into rule 3. qualys.ods_burst = 0 turns pacing off.
     *   3. Budget: fewer than qualys.ods_daily_budget (default 22) calls in
     *      the rolling 24h - the hard stop, freed when the oldest calls in the
     *      window turn 24h old, the same moment Qualys frees them.
     *
     * The bucket is worked out from the call log each time (no stored
     * state): it starts full 48h back and is replayed over the calls since.
     * Counted from qualys_api_call_log rather than from this queue, so a
     * failed call and a manual probe count, exactly as they do at Qualys.
     * called_at is written with PHP's date() in the app's own zone, which is
     * how strtotime() reads it back here.
     *
     * @return array{calls_24h:int, budget:int, min_gap_minutes:int, burst:int, next_at:int, reason:string}
     *         next_at <= time() means a send is allowed now; reason says which
     *         rule set next_at: 'now', 'gap', 'pacing' or 'budget'
     */
    public static function sendWindow(?int $now = null): array
    {
        $now ??= time();
        $budget = max(1, (int)(Config::get('qualys.ods_daily_budget') ?? self::DEFAULT_DAILY_BUDGET));
        $gapMinutes = max(0, (int)(Config::get('qualys.ods_min_interval_minutes') ?? self::DEFAULT_MIN_GAP_MINUTES));
        $burst = max(0, (int)(Config::get('qualys.ods_burst') ?? self::DEFAULT_BURST));

        $stmt = Database::getConnection()->prepare(
            'SELECT called_at FROM qualys_api_call_log
             WHERE endpoint = :endpoint AND called_at >= :since
             ORDER BY called_at ASC'
        );
        $stmt->execute([
            'endpoint' => self::ODS_ENDPOINT,
            'since'    => date('Y-m-d H:i:s', $now - 2 * self::WINDOW_SECONDS),
        ]);
        $all = array_values(array_filter(array_map(
            static fn ($v) => strtotime((string)$v),
            $stmt->fetchAll(\PDO::FETCH_COLUMN)
        )));
        $calls = array_values(array_filter($all, static fn (int $t) => $t >= $now - self::WINDOW_SECONDS));

        $nextAt = $now;
        $reason = 'now';
        $later = static function (int $t, string $why) use (&$nextAt, &$reason): void {
            if ($t > $nextAt) {
                $nextAt = $t;
                $reason = $why;
            }
        };

        if ($calls !== []) {
            $later(end($calls) + $gapMinutes * 60, 'gap');
        }

        if ($burst > 0) {
            // Token bucket replayed over the last 48h of calls. A call spends
            // one token; tokens come back at $budget per 24h, up to $burst.
            $burst = min($burst, $budget - 1);
            $rate = ($budget - $burst) / self::WINDOW_SECONDS; // tokens per second
            $tokens = (float)$burst;
            $t = $now - 2 * self::WINDOW_SECONDS;
            foreach ($all as $callAt) {
                $tokens = min((float)$burst, $tokens + ($callAt - $t) * $rate) - 1.0;
                $t = $callAt;
            }
            $tokens = min((float)$burst, $tokens + ($now - $t) * $rate);
            if ($tokens < 1.0) {
                $later($now + (int)ceil((1.0 - $tokens) / $rate), 'pacing');
            }
        }

        if (count($calls) >= $budget) {
            // The window must lose (count - budget + 1) calls to fit one more,
            // and the oldest go first.
            $later($calls[count($calls) - $budget] + self::WINDOW_SECONDS, 'budget');
        }

        return [
            'calls_24h'       => count($calls),
            'budget'          => $budget,
            'min_gap_minutes' => $gapMinutes,
            'burst'           => $burst,
            'next_at'         => $nextAt,
            'reason'          => $reason,
        ];
    }

    /**
     * When a request queued now will go to Qualys, in words, for the Assets
     * page and its flash message. The worker runs every 5 minutes, so a send
     * allowed within that is "within about 5 minutes"; anything later is
     * quoted as a time, with why when it's pacing or the daily limit.
     *
     * @param array{next_at:int, reason:string} $window sendWindow()
     */
    public static function describeNextSend(array $window, ?int $now = null): string
    {
        $now ??= time();
        if ($window['next_at'] <= $now + 300) {
            return 'within about 5 minutes';
        }
        // The worker picks it up on its next 5-minute run after next_at.
        $at = $window['next_at'];
        $when = (date('Y-m-d', $at) === date('Y-m-d', $now) ? 'at about ' : 'tomorrow at about ') . date('H:i', $at);
        return match ($window['reason']) {
            'pacing' => $when . ' - it\'s been a busy day, so scan requests are being spread out to keep some of the daily Qualys allowance for later',
            'budget' => $when . ', when the daily Qualys allowance for on-demand scans frees up',
            default  => $when,
        };
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
