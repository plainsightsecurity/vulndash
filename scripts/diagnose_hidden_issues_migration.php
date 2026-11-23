#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Run this BEFORE database/migrations/2026-08-scope-hidden-issues-per-user.sql.
 *
 * That migration rescopes hidden_issues from a single platform-wide hide to
 * a per-account one, attributing every existing row to whichever account's
 * hidden_by column already names (the account that actually clicked "hide"
 * or "hide globally" under the old design). This script shows exactly what
 * that backfill will produce, and - the one thing that can make the
 * migration fail - flags any row whose hidden_by is NULL, meaning the
 * account that set it has since been deleted and there is no account left
 * to attribute it to.
 *
 * READ-ONLY. No --confirm, no write path of any kind.
 *
 * Usage:
 *   php scripts/diagnose_hidden_issues_migration.php
 */

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Database;

$pdo = Database::getConnection();

fwrite(STDOUT, "[READ-ONLY - this script never writes anything]\n\n");

$total = (int)$pdo->query('SELECT COUNT(*) FROM hidden_issues')->fetchColumn();
fwrite(STDOUT, "Total hidden_issues rows: {$total}\n");

if ($total === 0) {
    fwrite(STDOUT, "Nothing to migrate - the migration will be a no-op structural change only.\n");
    exit(0);
}

$rows = $pdo->query("
    SELECT hi.id, hi.qid, hi.asset_id, hi.hidden_by, hi.created_at,
           u.username AS hidden_by_username, u.is_admin AS hidden_by_is_admin,
           kb.title
    FROM hidden_issues hi
    LEFT JOIN users u ON u.id = hi.hidden_by
    LEFT JOIN knowledge_base kb ON kb.qid = hi.qid
    ORDER BY hi.id
")->fetchAll();

$orphans = array_filter($rows, static fn ($r) => $r['hidden_by'] === null);

fwrite(STDOUT, "\n--- Every row, and which account the migration will attribute it to ---\n");
foreach ($rows as $r) {
    $scope = $r['asset_id'] === null ? 'GLOBAL (every asset)' : 'asset #' . $r['asset_id'] . ' only';
    $owner = $r['hidden_by'] === null
        ? '*** NO OWNER - hidden_by is NULL, account was deleted ***'
        : $r['hidden_by_username'] . ' (id ' . $r['hidden_by'] . ($r['hidden_by_is_admin'] ? ', admin' : ', client') . ')';
    fwrite(STDOUT, sprintf(
        "  #%d  QID %d (%s)  %s  set %s  -> will become owned by: %s\n",
        $r['id'],
        $r['qid'],
        $r['title'] ?? 'unknown QID',
        $scope,
        $r['created_at'],
        $owner
    ));
}

fwrite(STDOUT, "\n--- Verdict ---\n");
if (empty($orphans)) {
    fwrite(STDOUT, "All {$total} row(s) have a live owning account. The migration can run as-is.\n");
    fwrite(STDOUT, "Every row above will keep suppressing that QID, but only for the account it's now attributed to -\n");
    fwrite(STDOUT, "no other account's view changes as a result of running the migration itself.\n");
} else {
    $n = count($orphans);
    fwrite(STDOUT, "{$n} row(s) have NO owning account (hidden_by is NULL) and will make the migration fail at\n");
    fwrite(STDOUT, "the 'ALTER TABLE ... MODIFY COLUMN user_id ... NOT NULL' step. Resolve these first, either by:\n");
    fwrite(STDOUT, "  - manually UPDATE-ing hidden_by to a specific account's id for each orphaned row, or\n");
    fwrite(STDOUT, "  - DELETE-ing the orphaned row(s) if the hide is no longer wanted,\n");
    fwrite(STDOUT, "then re-run this script to confirm zero remain before applying the migration.\n\n");
    fwrite(STDOUT, "Orphaned row id(s): " . implode(', ', array_column($orphans, 'id')) . "\n");
}
