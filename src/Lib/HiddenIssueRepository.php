<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Hide/unhide rules for suppressing individual findings from the dashboard,
 * vulnerability list, and stat cards - a personal display preference, not to
 * be confused with CustomRemediationRepository, which is a QID-wide
 * admin-only override of the remediation text everyone sees.
 *
 * Every hide is scoped to the account that made it (hidden_issues.user_id):
 * it only ever changes what that one account sees, whether that account is
 * an admin or a client, and never leaks into any other account's view. This
 * replaced an earlier design where a QID could be hidden platform-wide for
 * every account at once - see database/migrations/
 * 2026-08-scope-hidden-issues-per-user.sql for that migration.
 *
 * Two shapes of hide, both keyed by (user_id, qid):
 *
 *   - Asset-scoped (asset_id set, tag_id always NULL): hides this QID on one
 *     specific asset, for this account only. The narrowest possible scope.
 *
 *   - "Mine"-scoped (asset_id NULL): hides this QID across every asset this
 *     account can see, further narrowed by tag_id:
 *       - tag_id set: only on assets carrying that tag. This is a property
 *         of which assets are tagged, resolved fresh on every read against
 *         current tag membership - NOT a property of whatever tag the
 *         account's session filter happens to be showing at read time. So a
 *         hide made while looking at "Tag: ClientA" keeps suppressing the
 *         finding on ClientA's assets even after switching the dashboard's
 *         Tags dropdown to a different tag or to "All tags" - it "belongs"
 *         to those assets, not to that moment's dropdown state. See
 *         VulnerabilityRepository::hiddenMatchWhere(), the one place this
 *         matching rule is implemented on the read side.
 *       - tag_id NULL: every asset the account can see, full stop - set
 *         when the account had "All tags" selected at the moment they hid
 *         it, which is genuinely as broad as a hide can go while still
 *         being scoped to just this one account.
 *
 * This class only ever writes/removes hide rows and reads back which rules
 * currently apply to one detection (stateFor()); VulnerabilityRepository
 * owns the read-side matching logic used everywhere else (counts, lists,
 * exports).
 */
class HiddenIssueRepository
{
    /**
     * Hides a QID on one specific asset, for one account. Idempotent - if
     * this exact rule already exists, this just refreshes hidden_by.
     */
    public static function hideAsset(int $qid, int $assetId, int $userId): void
    {
        $stmt = Database::getConnection()->prepare(
            'INSERT INTO hidden_issues (user_id, qid, asset_id, tag_id, hidden_by)
             VALUES (:user_id, :qid, :asset_id, NULL, :hidden_by)
             ON DUPLICATE KEY UPDATE hidden_by = VALUES(hidden_by)'
        );
        $stmt->execute(['user_id' => $userId, 'qid' => $qid, 'asset_id' => $assetId, 'hidden_by' => $userId]);
    }

    /**
     * Hides a QID across every one of this account's own assets - narrowed
     * to just those carrying $tagId if given, or truly all of them if
     * $tagId is null. Idempotent per (account, QID, tag).
     */
    public static function hideMine(int $qid, ?int $tagId, int $userId): void
    {
        // asset_id NULL => asset_scope 0; tag_id NULL => tag_scope 0 (see
        // the generated columns in the schema), so this collapses repeat
        // hides of the same (account, QID, tag) onto one row.
        $stmt = Database::getConnection()->prepare(
            'INSERT INTO hidden_issues (user_id, qid, asset_id, tag_id, hidden_by)
             VALUES (:user_id, :qid, NULL, :tag_id, :hidden_by)
             ON DUPLICATE KEY UPDATE hidden_by = VALUES(hidden_by)'
        );
        $stmt->execute(['user_id' => $userId, 'qid' => $qid, 'tag_id' => $tagId, 'hidden_by' => $userId]);
    }

    /** Removes this account's asset-scoped hide for a QID (a no-op if there wasn't one). */
    public static function unhideAsset(int $qid, int $assetId, int $userId): void
    {
        Database::getConnection()
            ->prepare('DELETE FROM hidden_issues WHERE user_id = :user_id AND qid = :qid AND asset_id = :asset_id')
            ->execute(['user_id' => $userId, 'qid' => $qid, 'asset_id' => $assetId]);
    }

    /**
     * Removes this account's "mine" hide for a QID at the given tag scope
     * (null = the "all tags" rule, otherwise that one tag's rule). A no-op
     * if there wasn't one.
     */
    public static function unhideMine(int $qid, ?int $tagId, int $userId): void
    {
        $pdo = Database::getConnection();
        if ($tagId === null) {
            $pdo->prepare(
                'DELETE FROM hidden_issues
                 WHERE user_id = :user_id AND qid = :qid AND asset_id IS NULL AND tag_id IS NULL'
            )->execute(['user_id' => $userId, 'qid' => $qid]);
            return;
        }
        $pdo->prepare(
            'DELETE FROM hidden_issues
             WHERE user_id = :user_id AND qid = :qid AND asset_id IS NULL AND tag_id = :tag_id'
        )->execute(['user_id' => $userId, 'qid' => $qid, 'tag_id' => $tagId]);
    }

    /**
     * Every hide rule this account currently has in effect for one specific
     * detection (a QID on one asset) - drives the "Hidden" badge and the
     * Hide/Unhide menu on the detail page. More than one rule can apply at
     * once (e.g. an asset-scoped hide AND a "mine, tag X" hide where this
     * asset also happens to carry tag X) - each is surfaced separately so
     * the account can unhide exactly the rule(s) they want, individually.
     *
     * @return array{
     *   asset: bool,
     *   mineAllTags: bool,
     *   mineByTag: array<int, array{tag_id: int, name: string}>
     * }
     */
    public static function stateFor(int $qid, int $assetId, int $userId): array
    {
        $pdo = Database::getConnection();

        $assetStmt = $pdo->prepare(
            'SELECT 1 FROM hidden_issues WHERE user_id = :user_id AND qid = :qid AND asset_id = :asset_id LIMIT 1'
        );
        $assetStmt->execute(['user_id' => $userId, 'qid' => $qid, 'asset_id' => $assetId]);
        $hasAsset = (bool)$assetStmt->fetchColumn();

        $allTagsStmt = $pdo->prepare(
            'SELECT 1 FROM hidden_issues
             WHERE user_id = :user_id AND qid = :qid AND asset_id IS NULL AND tag_id IS NULL LIMIT 1'
        );
        $allTagsStmt->execute(['user_id' => $userId, 'qid' => $qid]);
        $hasMineAllTags = (bool)$allTagsStmt->fetchColumn();

        // Tags THIS asset actually carries that also have a matching "mine"
        // hide row for this account and QID - the same breadth match
        // VulnerabilityRepository::hiddenMatchWhere() applies on every other
        // read, resolved here to named rows so the UI can offer an unhide
        // button per tag rather than one opaque "hidden somehow" state.
        $byTagStmt = $pdo->prepare(
            'SELECT t.id AS tag_id, t.name
             FROM hidden_issues hi
             JOIN asset_tags at ON at.tag_id = hi.tag_id AND at.asset_id = :asset_id
             JOIN tags t ON t.id = hi.tag_id
             WHERE hi.user_id = :user_id AND hi.qid = :qid AND hi.asset_id IS NULL AND hi.tag_id IS NOT NULL
             ORDER BY t.name'
        );
        $byTagStmt->execute(['asset_id' => $assetId, 'user_id' => $userId, 'qid' => $qid]);

        return [
            'asset'       => $hasAsset,
            'mineAllTags' => $hasMineAllTags,
            'mineByTag'   => $byTagStmt->fetchAll(),
        ];
    }
}
