<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * The one copy of "which local assets has Qualys stopped reporting, is it
 * safe to delete them, and delete them" - shared by
 * scripts/reconcile_asset_inventory.php (every 6 hours) and
 * scripts/sync_host_detections.php's hourly new-host pass, which both make
 * a full, unfiltered Host List pull and so both know for certain which
 * hosts Qualys still has.
 *
 * WHY ONE COPY. Deleting an asset is the most destructive thing either job
 * does (its tags, detections, snapshots and tombstones all go with it via
 * ON DELETE CASCADE), and it is driven purely by absence. Two hand-kept
 * copies of that logic is how HostSyncWriter's three drift bugs happened
 * (see that class's docblock); here a drift could mean one job deleting
 * what the other's guard would have refused. So both call this, and a
 * change to the rule or the guard applies to both at once.
 *
 * WHAT COUNTS AS PRESENT. The caller passes every Qualys host ID it saw in
 * COMPLETE pulls this run - for reconcile, its full detection pull plus its
 * full Host List pull; for the hourly sync, its full Host List pull plus
 * the hosts from its (incremental) detection pull. Host List alone is
 * already the full scoped inventory - it returns hosts with and without
 * detections - so adding the detection hosts is belt and braces. A caller
 * must only call this after its pulls have finished: a pull that throws
 * partway leaves the set incomplete, and absence from an incomplete set
 * means nothing.
 *
 * THE GUARD (moved here from the reconcile job, where it was added
 * 2026-10 after Qualys's two-week suspension returned valid but empty
 * results). plan() refuses - returns reasons, deletes nothing - when:
 *   - Qualys returned no hosts at all while assets are stored locally; or
 *   - more than qualys.reconcile_max_removal_percent (default 50) of local
 *     assets would be deleted.
 * The reconcile job adds its own third reason (clearing ALL findings on too
 * many hosts), which only it can judge, since only it makes the full
 * detection pull that judgement needs.
 */
final class AssetInventoryPruner
{
    public const DEFAULT_MAX_REMOVAL_PERCENT = 50.0;

    /** qualys.reconcile_max_removal_percent, validated; a bad value warns and falls back to the default. */
    public static function maxRemovalPercent(): float
    {
        $setting = Config::get('qualys.reconcile_max_removal_percent');
        if ($setting === null) {
            return self::DEFAULT_MAX_REMOVAL_PERCENT;
        }
        if (!is_numeric($setting) || $setting < 0 || $setting > 100) {
            if (defined('STDERR')) {
                fwrite(STDERR, 'Warning: qualys.reconcile_max_removal_percent must be a number from 0 to 100 - ignoring ' . var_export($setting, true) . " and using 50.\n");
            }
            return self::DEFAULT_MAX_REMOVAL_PERCENT;
        }
        return (float)$setting;
    }

    /** "50" rather than "50.00", "12.5" rather than "12.50" - for guard messages. */
    public static function formatPercent(float $percent): string
    {
        return rtrim(rtrim(number_format($percent, 2, '.', ''), '0'), '.');
    }

    /**
     * Works out what a prune would delete, and whether the guard allows it.
     * Read-only: nothing is deleted here - see deleteAssets().
     *
     * @param array<int, true> $presentHostIds Qualys host ID => true, for every
     *        host seen in this run's completed pulls (see the class docblock)
     * @return array{
     *   local_count: int,
     *   missing: array<int, array{id: int|string, qualys_host_id: int|string, hostname: ?string, ip_address: ?string}>,
     *   guard_reasons: string[]
     * }
     */
    public static function plan(\PDO $pdo, array $presentHostIds, float $maxRemovalPercent): array
    {
        $localAssets = $pdo->query('SELECT id, qualys_host_id, hostname, ip_address FROM assets ORDER BY hostname, ip_address')->fetchAll();

        $missing = [];
        foreach ($localAssets as $asset) {
            if (!isset($presentHostIds[(int)$asset['qualys_host_id']])) {
                $missing[] = $asset;
            }
        }

        $localCount = count($localAssets);
        $guardReasons = [];
        if ($localCount > 0 && $presentHostIds === []) {
            $guardReasons[] = "Qualys returned no hosts at all while {$localCount} asset(s) are stored locally - that points at an account, licence or scope problem rather than a decommissioned estate";
        }
        if ($localCount > 0 && count($missing) * 100 > $maxRemovalPercent * $localCount) {
            $guardReasons[] = sprintf(
                '%d of %d local asset(s) (%.0f%%) would be deleted, more than the %s%% allowed by qualys.reconcile_max_removal_percent',
                count($missing), $localCount, count($missing) * 100 / $localCount, self::formatPercent($maxRemovalPercent)
            );
        }

        return [
            'local_count'   => $localCount,
            'missing'       => $missing,
            'guard_reasons' => $guardReasons,
        ];
    }

    /**
     * Deletes the given assets (rows as returned in plan()'s 'missing'); tags,
     * detections, snapshots and tombstones go with them via ON DELETE CASCADE.
     * Only call this once the caller has acted on plan()'s guard_reasons.
     *
     * @param array<int, array{id: int|string}> $assets
     * @return int rows actually deleted (fewer than asked if another job got there first)
     */
    public static function deleteAssets(\PDO $pdo, array $assets): int
    {
        if ($assets === []) {
            return 0;
        }
        $ids = array_map('intval', array_column($assets, 'id'));
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $pdo->prepare("DELETE FROM assets WHERE id IN ($placeholders)");
        $stmt->execute($ids);
        return $stmt->rowCount();
    }
}
