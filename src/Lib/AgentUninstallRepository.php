<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * The agent-uninstall work queue (see
 * database/migrations/2026-07-add-agent-uninstall.sql for the table and the
 * full lifecycle/suppression rationale).
 *
 * Two consumers:
 *   - The dashboard (public/assets.php) calls enqueue() when a permitted user
 *     confirms an uninstall. From that instant the asset(s) vanish from every
 *     dashboard read, because VulnerabilityRepository::buildTagScopeJoin()
 *     anti-joins any asset with a ('pending','processing') row here.
 *   - The cron worker (scripts/process_agent_uninstalls.php) calls
 *     claimPending()/markUninstalled()/markFailed() to drain the queue via
 *     the Qualys Cloud Agent uninstall API.
 *
 * Access control lives in enqueue(): it re-resolves the requested asset ids
 * through the caller's own tag scope (VulnerabilityRepository::
 * getScopedAssetsByIds), so a client can never queue an uninstall for an
 * asset outside the tags they're assigned - the request body is untrusted
 * ($_POST ids), and this is the boundary that makes it safe.
 */
class AgentUninstallRepository
{
    /**
     * Recorded in last_error (as a note, not an error) on a row the worker
     * settled without an uninstall call - see markAlreadyGone().
     */
    public const NOTE_NOT_FOUND_IN_QUALYS = 'Not found in Qualys asset inventory - the host was already removed there, so no uninstall call was needed. Cleaned up locally.';

    /**
     * Queue one or more assets for uninstall on behalf of $requestedBy.
     *
     * Only assets the caller is actually allowed to see (per their tag scope)
     * AND that aren't already actively queued get inserted. Everything else is
     * reported back rather than silently dropped, so the UI can say what
     * happened.
     *
     * @param int[]  $assetIds  internal assets.id values from the form
     * @param int[]  $tagIds    the caller's assigned tag ids (Auth::tagIds())
     * @return array{queued:int, already_queued:int, not_permitted:int, hostnames:string[]}
     */
    public static function enqueue(array $assetIds, int $requestedBy, array $tagIds, bool $isAdmin): array
    {
        $assetIds = array_values(array_unique(array_filter(array_map('intval', $assetIds), static fn ($v) => $v > 0)));
        $result = ['queued' => 0, 'already_queued' => 0, 'not_permitted' => 0, 'hostnames' => []];
        if ($assetIds === []) {
            return $result;
        }

        // Only assets in the caller's scope come back here. Any requested id
        // that isn't visible to them (wrong tag, or already suppressed by an
        // existing active queue row - buildTagScopeJoin hides both) is absent
        // from $scoped, and therefore counted as not-permitted below.
        $scoped = VulnerabilityRepository::getScopedAssetsByIds($assetIds, $tagIds, $isAdmin);
        $scopedById = [];
        foreach ($scoped as $row) {
            $scopedById[(int)$row['id']] = $row;
        }

        $pdo = Database::getConnection();
        $insert = $pdo->prepare(
            'INSERT INTO agent_uninstall_queue
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
                // Unique violation on active_dedup = this asset already has a
                // pending/processing row. (In practice getScopedAssetsByIds
                // already hides those, so this is just the race-safe backstop
                // for two tabs submitting at once.)
                if (($e->errorInfo[1] ?? null) === 1062) {
                    $result['already_queued']++;
                    continue;
                }
                throw $e;
            }
        }

        return $result;
    }

    /**
     * Claim up to $limit pending rows for this worker run, flipping them to
     * 'processing' and bumping attempts, and return them. Done in a
     * transaction so two overlapping worker runs can't both claim the same
     * row. (The cron worker also takes a file lock, but this is the
     * correctness backstop.)
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
                 FROM agent_uninstall_queue
                 WHERE status = \'pending\'
                 ORDER BY requested_at ASC
                 LIMIT ' . (int)$limit . '
                 FOR UPDATE'
            );
            $sel->execute();
            $rows = $sel->fetchAll();

            if ($rows !== []) {
                $ids = array_map(static fn ($r) => (int)$r['id'], $rows);
                $in = implode(',', array_fill(0, count($ids), '?'));
                $upd = $pdo->prepare(
                    'UPDATE agent_uninstall_queue
                     SET status = \'processing\', attempts = attempts + 1
                     WHERE id IN (' . $in . ')'
                );
                $upd->execute($ids);

                // Reflect the increment we just wrote so callers see the true
                // current attempt number (the SELECT above captured the
                // pre-increment value). The worker uses this to decide when a
                // row has been retried too many times.
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
     * Read-only view of pending rows, oldest first - used by the worker's
     * dry-run so it can show exactly what it WOULD act on without claiming
     * anything (claimPending mutates status/attempts, which a dry run must not).
     *
     * @return array<int, array<string, mixed>>
     */
    public static function listPending(int $limit = 500): array
    {
        $stmt = Database::getConnection()->prepare(
            'SELECT id, asset_id, qualys_host_id, qualys_asset_id, hostname, ip_address, attempts
             FROM agent_uninstall_queue
             WHERE status = \'pending\'
             ORDER BY requested_at ASC
             LIMIT ' . (int)$limit
        );
        $stmt->execute();
        return $stmt->fetchAll();
    }

    /**
     * Local cleanup applied after Qualys confirms an uninstall (or, see
     * markAlreadyGone(), after finding Qualys has already removed the host),
     * mirroring what Qualys itself does on its side (purge the host's findings
     * and drop the host). Soft, not a hard delete: the asset row is kept but
     * marked inactive and its detections removed, so (a) detection-count
     * reads - which don't filter on is_active - immediately drop to zero for
     * it, and (b) the assets list (which does filter is_active) hides it.
     * asset_vuln_snapshot history is deliberately preserved.
     *
     * The row itself goes once Qualys stops listing the host: the hourly
     * prune in scripts/sync_host_detections.php (or the reconcile job) deletes
     * it through AssetInventoryPruner. Nothing sets is_active back to 1 - no
     * sync touches that column - so this is not a path back for a re-installed
     * agent; Qualys gives a re-installed agent a new host ID, which arrives as
     * a new asset row of its own (corrected 2026-11: this docblock used to say
     * the next sync reactivated this row, which no code did).
     *
     * @param int[] $assetIds internal assets.id values
     */
    public static function applyLocalCleanup(array $assetIds): void
    {
        $assetIds = array_values(array_filter(array_map('intval', $assetIds), static fn ($v) => $v > 0));
        if ($assetIds === []) {
            return;
        }
        $pdo = Database::getConnection();
        $in = implode(',', array_fill(0, count($assetIds), '?'));
        $pdo->beginTransaction();
        try {
            $pdo->prepare('DELETE FROM host_detections WHERE asset_id IN (' . $in . ')')->execute($assetIds);
            $pdo->prepare('UPDATE assets SET is_active = 0 WHERE id IN (' . $in . ')')->execute($assetIds);
            $pdo->commit();
        } catch (\Throwable $e) {
            $pdo->rollBack();
            throw $e;
        }
    }

    /** @param int[] $ids */
    public static function markUninstalled(array $ids): void
    {
        self::setStatus($ids, 'uninstalled', null);
    }

    /**
     * Settle rows whose host Qualys has already removed: the AssetView lookup
     * call succeeded but returned nothing for them, so there is nothing left
     * to uninstall and the user's intent is already met. Terminal
     * 'uninstalled' rather than 'failed' - 'failed' ends the suppression
     * without any cleanup, which is what made such a host reappear on the
     * dashboard (2026-11-06, "bernard", three requests in a row). The caller
     * applies applyLocalCleanup() to the same assets. last_error carries
     * NOTE_NOT_FOUND_IN_QUALYS so the queue shows why no call was made.
     *
     * @param int[] $ids
     */
    public static function markAlreadyGone(array $ids): void
    {
        self::setStatus($ids, 'uninstalled', self::NOTE_NOT_FOUND_IN_QUALYS);
    }

    /**
     * @param int[]  $ids
     * @param string $error recorded on every row (truncated by the TEXT column)
     */
    public static function markFailed(array $ids, string $error): void
    {
        self::setStatus($ids, 'failed', $error);
    }

    /**
     * Return a claimed 'processing' row to 'pending' so a later run retries it
     * - used when the whole batch couldn't even be sent (e.g. the API call
     * threw before any per-asset result was known), so nothing was actually
     * uninstalled and these shouldn't be marked failed/terminal yet.
     *
     * @param int[] $ids
     */
    public static function releaseToPending(array $ids): void
    {
        self::setStatus($ids, 'pending', null);
    }

    /** @param int[] $ids */
    private static function setStatus(array $ids, string $status, ?string $error): void
    {
        $ids = array_values(array_filter(array_map('intval', $ids), static fn ($v) => $v > 0));
        if ($ids === []) {
            return;
        }
        $pdo = Database::getConnection();
        $in = implode(',', array_fill(0, count($ids), '?'));
        // processed_at is set for terminal states only; a release back to
        // pending clears it again so the audit timestamp always reflects the
        // real completion, not an interim claim.
        $processedAt = in_array($status, ['uninstalled', 'failed'], true) ? 'NOW()' : 'NULL';
        $stmt = $pdo->prepare(
            'UPDATE agent_uninstall_queue
             SET status = ?, last_error = ?, processed_at = ' . $processedAt . '
             WHERE id IN (' . $in . ')'
        );
        $stmt->execute(array_merge([$status, $error], $ids));
    }

    /**
     * Admin queue view: every row, newest first, with the requester's
     * username joined in. Used by the (future) admin queue page and by
     * diagnostics.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function listAll(int $limit = 200): array
    {
        $stmt = Database::getConnection()->prepare(
            'SELECT q.id, q.asset_id, q.qualys_host_id, q.qualys_asset_id, q.hostname, q.ip_address,
                    q.status, q.requested_at, q.processed_at, q.attempts, q.last_error,
                    u.username AS requested_by_username
             FROM agent_uninstall_queue q
             LEFT JOIN users u ON u.id = q.requested_by
             ORDER BY q.requested_at DESC
             LIMIT ' . (int)$limit
        );
        $stmt->execute();
        return $stmt->fetchAll();
    }

    /**
     * Cancel a still-pending request (un-hides the asset). Only 'pending' rows
     * can be cancelled - once the worker has claimed it ('processing') or
     * acted on it, cancellation from the UI is unsafe/meaningless. Returns
     * whether a row was actually cancelled.
     */
    public static function cancelPending(int $id): bool
    {
        $stmt = Database::getConnection()->prepare(
            'DELETE FROM agent_uninstall_queue WHERE id = :id AND status = \'pending\''
        );
        $stmt->execute(['id' => $id]);
        return $stmt->rowCount() > 0;
    }
}
