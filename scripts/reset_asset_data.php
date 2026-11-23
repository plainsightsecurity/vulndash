#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Clears out local asset/detection/tag data after the Qualys platform
 * migration (qg3 -> qg1), so the next reconcile_asset_inventory.php /
 * sync_host_detections.php run repopulates everything cleanly against the
 * new subscription rather than mixing old-platform rows with new ones.
 *
 * Why this can't just be "TRUNCATE assets": several tables key off local
 * assets.id via foreign keys, and one (hidden_issues) references asset_id
 * with NO foreign key at all - see the per-table notes below. Getting the
 * order and the FK behaviour wrong either leaves orphaned rows behind or
 * throws on a table MySQL won't let you TRUNCATE while it's referenced.
 * This script handles each table deliberately rather than relying on
 * TRUNCATE + FOREIGN_KEY_CHECKS=0.
 *
 * What gets deleted when you run with --confirm:
 *   - hidden_issues   : only rows with a non-NULL asset_id (asset-scoped
 *                        hides). Global qid-only hides (asset_id IS NULL)
 *                        are untouched - they're not asset data. There's
 *                        no FK from hidden_issues.asset_id to assets, so
 *                        these would otherwise silently point at a
 *                        deleted (or worse, later a REUSED) asset id -
 *                        deleted explicitly here rather than left to rot.
 *   - assets          : every row. Cascades automatically (per
 *                        install_schema.sql's ON DELETE CASCADE) to:
 *                          - asset_tags
 *                          - host_detections
 *                          - asset_vuln_snapshot
 *                          - detection_resolutions
 *                        and SETS NULL (not delete) on:
 *                          - agent_uninstall_queue.asset_id
 *   - tags            : see --wipe-tags below. Default behaviour is NOT
 *                        to delete tags - see rationale below.
 *
 * What's deliberately left alone:
 *   - knowledge_base, kb_cve, qid_exploit, cisa_kev, epss_scores: this is
 *     the global vulnerability catalogue, not asset data. It's
 *     subscription-independent (same QIDs mean the same thing on any
 *     Qualys platform) and already backfilled - wiping it would force a
 *     full KB backfill again for no reason, and this app already has
 *     hard evidence of very tight KB call budgets on this account.
 *   - custom_remediations: qid-scoped admin notes, not tied to any asset
 *     or platform - wiping these would just lose Mark's own writing for
 *     no reason connected to the migration.
 *   - qualys_api_call_log, sync_log: historical audit trail. Left alone
 *     so the API usage page and sync status strip keep their history
 *     rather than looking like the app has never run.
 *   - sync_state: checked directly against every script that writes to
 *     it (sync_knowledge_base.php, sync_host_detections.php) - the only
 *     cursor stored is 'knowledge_base_incremental' (KB is untouched, so
 *     this should stay valid) and 'host_detections_rr' (which API
 *     version's turn it is next - unrelated to local data). Neither
 *     needs resetting for a clean asset restart.
 *
 * --wipe-tags (tags/user_tags): OFF by default because tags.name and
 *     user_tags (which client account sees which tag) represent Mark's
 *     own client-scoping decisions in the admin UI, not anything
 *     platform-specific - re-typing every client's tag assignment after
 *     a migration would be real, avoidable manual work. The DEFAULT
 *     behaviour instead resets every tag's qualys_tag_id back to NULL
 *     (i.e. "pending", matching the exact state UserRepository::
 *     resolveSyncedTagId() already knows how to handle for a
 *     name-created-ahead-of-the-Qualys-tag row) - tag NAMES and
 *     user_tags client associations survive untouched, and the next
 *     reconcile run re-resolves each name against the new platform's
 *     tag IDs automatically. tags.qualys_tag_id has a UNIQUE key, but
 *     MySQL/MariaDB unique indexes permit any number of NULLs, so
 *     setting many rows to NULL at once is safe.
 *     Pass --wipe-tags if the tag NAMES themselves also need to change
 *     for the new platform (not just their Qualys IDs) - this hard-
 *     deletes every row in tags, which cascades to asset_tags (already
 *     empty from the asset wipe) and user_tags (client scoping is lost
 *     and must be re-assigned from Manage Users afterwards).
 *
 * --clear-uninstall-queue: OFF by default. agent_uninstall_queue rows
 *     left over from the old platform have their asset_id set to NULL
 *     by the FK (not deleted), but keep their old-platform
 *     qualys_host_id/qualys_asset_id, which mean nothing on the new
 *     subscription. They're harmless (process_agent_uninstalls.php only
 *     acts on 'pending'/'processing' rows, and nothing will re-target
 *     them), but pass this flag to delete them outright if you'd rather
 *     not see stale entries.
 *
 * DRY RUN BY DEFAULT: prints exactly what would be deleted/changed and
 * writes nothing unless you pass --confirm.
 *
 * Usage:
 *   php scripts/reset_asset_data.php                                  # dry run
 *   php scripts/reset_asset_data.php --confirm                        # execute
 *   php scripts/reset_asset_data.php --confirm --wipe-tags            # also hard-delete tags/user_tags
 *   php scripts/reset_asset_data.php --confirm --clear-uninstall-queue
 */

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Database;

$confirm             = in_array('--confirm', $argv, true);
$wipeTags            = in_array('--wipe-tags', $argv, true);
$clearUninstallQueue = in_array('--clear-uninstall-queue', $argv, true);

$pdo = Database::getConnection();

fwrite(STDOUT, "==========================================================\n");
fwrite(STDOUT, "  Reset local asset / detection / tag data\n");
fwrite(STDOUT, "----------------------------------------------------------\n");
fwrite(STDOUT, "  Tags mode         : " . ($wipeTags ? 'WIPE (delete tags + user_tags)' : 'RESET (keep names/user_tags, clear qualys_tag_id)') . "\n");
fwrite(STDOUT, "  Uninstall queue   : " . ($clearUninstallQueue ? 'DELETE stale rows' : 'leave (asset_id -> NULL via FK)') . "\n");
fwrite(STDOUT, "  Mode              : " . ($confirm ? 'CONFIRM (will write)' : 'DRY RUN (no changes)') . "\n");
fwrite(STDOUT, "==========================================================\n\n");

/**
 * @return array<string, int>
 */
function currentCounts(\PDO $pdo): array
{
    $counts = [];
    $counts['assets']                       = (int)$pdo->query('SELECT COUNT(*) FROM assets')->fetchColumn();
    $counts['host_detections']              = (int)$pdo->query('SELECT COUNT(*) FROM host_detections')->fetchColumn();
    $counts['asset_tags']                   = (int)$pdo->query('SELECT COUNT(*) FROM asset_tags')->fetchColumn();
    $counts['asset_vuln_snapshot']          = (int)$pdo->query('SELECT COUNT(*) FROM asset_vuln_snapshot')->fetchColumn();
    $counts['detection_resolutions']        = (int)$pdo->query('SELECT COUNT(*) FROM detection_resolutions')->fetchColumn();
    $counts['hidden_issues (asset-scoped)'] = (int)$pdo->query('SELECT COUNT(*) FROM hidden_issues WHERE asset_id IS NOT NULL')->fetchColumn();
    $counts['hidden_issues (global, kept)'] = (int)$pdo->query('SELECT COUNT(*) FROM hidden_issues WHERE asset_id IS NULL')->fetchColumn();
    $counts['agent_uninstall_queue']        = (int)$pdo->query('SELECT COUNT(*) FROM agent_uninstall_queue')->fetchColumn();
    $counts['tags (total)']                 = (int)$pdo->query('SELECT COUNT(*) FROM tags')->fetchColumn();
    $counts['tags (resolved to a platform)'] = (int)$pdo->query('SELECT COUNT(*) FROM tags WHERE qualys_tag_id IS NOT NULL')->fetchColumn();
    $counts['tags (pending)']               = (int)$pdo->query('SELECT COUNT(*) FROM tags WHERE qualys_tag_id IS NULL')->fetchColumn();
    $counts['user_tags (client scoping)']   = (int)$pdo->query('SELECT COUNT(*) FROM user_tags')->fetchColumn();

    return $counts;
}

function printCounts(array $counts): void
{
    $width = max(array_map('strlen', array_keys($counts)));
    foreach ($counts as $label => $count) {
        fwrite(STDOUT, sprintf("  %-{$width}s : %d\n", $label, $count));
    }
}

fwrite(STDOUT, "Current state:\n");
printCounts(currentCounts($pdo));

if (!$confirm) {
    fwrite(STDOUT, "\nDRY RUN - nothing changed.\n");
    fwrite(STDOUT, "Would delete: hidden_issues (asset-scoped), assets and everything that cascades\n");
    fwrite(STDOUT, "from it (host_detections, asset_tags, asset_vuln_snapshot, detection_resolutions).\n");
    fwrite(STDOUT, $wipeTags
        ? "Would DELETE all rows from tags (cascades to user_tags - client tag assignments are lost).\n"
        : "Would reset tags.qualys_tag_id to NULL on every tag (names and user_tags untouched).\n");
    fwrite(STDOUT, $clearUninstallQueue
        ? "Would DELETE all rows from agent_uninstall_queue.\n"
        : "agent_uninstall_queue rows are left in place (asset_id -> NULL automatically via FK).\n");
    fwrite(STDOUT, "\nRe-run with --confirm to execute" . ($wipeTags ? '' : ' (add --wipe-tags to also hard-delete tags/user_tags)') . ".\n");
    exit(0);
}

$pdo->beginTransaction();
try {
    if ($clearUninstallQueue) {
        $pdo->exec('DELETE FROM agent_uninstall_queue');
    }

    // No FK from hidden_issues.asset_id to assets - clear the asset-scoped
    // rows explicitly so none are left pointing at a now-nonexistent (or,
    // worse, later a reused) local asset id. Global qid-only hides
    // (asset_id IS NULL) are untouched.
    $pdo->exec('DELETE FROM hidden_issues WHERE asset_id IS NOT NULL');

    // Cascades to asset_tags, host_detections, asset_vuln_snapshot,
    // detection_resolutions; SETS NULL on any remaining
    // agent_uninstall_queue.asset_id (per install_schema.sql's FKs).
    $pdo->exec('DELETE FROM assets');

    if ($wipeTags) {
        // Cascades to user_tags - client tag assignments are lost and
        // must be re-set from Manage Users afterwards.
        $pdo->exec('DELETE FROM tags');
    } else {
        // Keep tag names and user_tags client scoping; just mark every
        // tag as unresolved again so the next reconcile run re-links it
        // to the new platform's tag id by name.
        $pdo->exec('UPDATE tags SET qualys_tag_id = NULL');
    }

    $pdo->commit();
} catch (\Throwable $e) {
    $pdo->rollBack();
    fwrite(STDERR, "\nFailed, rolled back: {$e->getMessage()}\n");
    exit(1);
}

fwrite(STDOUT, "\nDone. New state:\n");
printCounts(currentCounts($pdo));
fwrite(STDOUT, "\nNext: once Qualys confirms KnowledgeBase access is enabled, run\n");
fwrite(STDOUT, "reconcile_asset_inventory.php (without --confirm first, as usual) to repopulate.\n");
exit(0);
