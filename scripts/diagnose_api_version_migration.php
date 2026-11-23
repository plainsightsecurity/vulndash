#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Run this BEFORE database/migrations/2026-10-add-api-version-to-call-log.sql.
 *
 * That migration adds a nullable api_version column and an index to
 * qualys_api_call_log. It's purely additive - no existing row is changed or
 * removed - so the only real questions are whether it's already been applied
 * (it's idempotent either way) and how big the table is, since adding the
 * index means MySQL reads every row once. This script answers both, and shows
 * what the API usage page's new per-version panel will start from.
 *
 * READ-ONLY. No --confirm, no write path of any kind.
 *
 * Usage:
 *   php scripts/diagnose_api_version_migration.php
 */

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Database;

$pdo = Database::getConnection();

fwrite(STDOUT, "[READ-ONLY - this script never writes anything]\n\n");

$colExists = (int)$pdo->query("
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'qualys_api_call_log' AND COLUMN_NAME = 'api_version'
")->fetchColumn() > 0;
$idxExists = (int)$pdo->query("
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'qualys_api_call_log' AND INDEX_NAME = 'idx_api_version_called_at'
")->fetchColumn() > 0;

fwrite(STDOUT, 'Column api_version:               ' . ($colExists ? 'ALREADY PRESENT - that step will be a no-op' : 'missing - will be added') . "\n");
fwrite(STDOUT, 'Index idx_api_version_called_at:  ' . ($idxExists ? 'ALREADY PRESENT - that step will be a no-op' : 'missing - will be added') . "\n\n");

$stats = $pdo->query('SELECT COUNT(*) AS n, MIN(called_at) AS first_call, MAX(called_at) AS last_call FROM qualys_api_call_log')->fetch();
$sizeMb = $pdo->query("
    SELECT ROUND((DATA_LENGTH + INDEX_LENGTH) / 1048576, 1)
    FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'qualys_api_call_log'
")->fetchColumn();

fwrite(STDOUT, "qualys_api_call_log: {$stats['n']} row(s), ~{$sizeMb} MB"
    . ($stats['n'] > 0 ? ", spanning {$stats['first_call']} .. {$stats['last_call']}" : '') . "\n");
fwrite(STDOUT, "MySQL version: " . $pdo->query('SELECT VERSION()')->fetchColumn() . "\n");
fwrite(STDOUT, "(Adding the column is a metadata-only change on MySQL 8.0.29+; the index build reads\n");
fwrite(STDOUT, " every row once but runs online - at this table size it should take seconds, not minutes.)\n\n");

if ($colExists) {
    $byVersion = $pdo->query('
        SELECT COALESCE(api_version, \'(not recorded)\') AS v, COUNT(*) AS n
        FROM qualys_api_call_log
        GROUP BY api_version
        ORDER BY api_version
    ')->fetchAll();
    fwrite(STDOUT, "Rows by api_version so far:\n");
    foreach ($byVersion as $row) {
        fwrite(STDOUT, "  {$row['v']}: {$row['n']}\n");
    }
} else {
    fwrite(STDOUT, "After the migration, all {$stats['n']} existing row(s) will show as \"not recorded\" on the\n");
    fwrite(STDOUT, "per-version panel - the version was never stored, so there's nothing to backfill from.\n");
    fwrite(STDOUT, "Per-version figures fill in from the first sync after the new code is deployed, and\n");
    fwrite(STDOUT, "give a complete rolling-24h picture one day later.\n");
}

fwrite(STDOUT, "\n--- Verdict ---\n");
fwrite(STDOUT, ($colExists && $idxExists)
    ? "Already fully applied. Running the migration again is harmless.\n"
    : "Safe to apply: additive only, nothing existing is changed or removed.\n");
