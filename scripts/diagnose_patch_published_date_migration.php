#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Read-only pre-migration diagnostic for
 * database/migrations/2026-11-add-patch-published-date.sql.
 *
 * The migration itself only adds a nullable column, so it can't damage
 * anything. What's consequential is the behaviour change that ships with
 * it: the CE+ patch clock (src/Lib/CePlusDeadline.php) starts counting from
 * the vendor's patch date, and stops showing a clock at all for a QID
 * Qualys marks PATCHABLE 0. This reports what that will change on this
 * data before it's deployed, so nothing about it is a surprise:
 *
 *   - which open CE+ failures will LOSE their clock (patchable = 0) - their
 *     CE+ failure status itself is unchanged, only the countdown goes;
 *   - how many distinct QIDs on open detections a backfill would fetch, and
 *     roughly how many KnowledgeBase API calls that costs.
 *
 * Makes no API calls and writes nothing. Safe to run before and after the
 * migration.
 *
 * Usage:
 *   php scripts/diagnose_patch_published_date_migration.php
 */

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Database;

// Matches scripts/backfill_patch_published_date.php's default --batch-size.
const BACKFILL_DEFAULT_BATCH_SIZE = 100;

$pdo = Database::getConnection();

$colExists = (int)$pdo->query("
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'knowledge_base' AND COLUMN_NAME = 'patch_published_date'
")->fetchColumn() === 1;

fwrite(STDOUT, "knowledge_base.patch_published_date: " . ($colExists ? "PRESENT (migration already applied)" : "absent (migration not yet applied)") . "\n");
fwrite(STDOUT, "knowledge_base rows: " . number_format((int)$pdo->query('SELECT COUNT(*) FROM knowledge_base')->fetchColumn()) . "\n\n");

// Same "open" definition the dashboard uses (VulnerabilityRepository::BASE_DETECTION_FILTER).
$open = "hd.status != 'Fixed' AND hd.effective_cvss_score > 0.0";

$ceFail = (int)$pdo->query("SELECT COUNT(*) FROM host_detections hd WHERE {$open} AND hd.is_ce_plus_fail = 1")->fetchColumn();
$losing = $pdo->query("
    SELECT kb.qid, kb.title, COUNT(*) AS detections
    FROM host_detections hd JOIN knowledge_base kb ON kb.qid = hd.qid
    WHERE {$open} AND hd.is_ce_plus_fail = 1 AND kb.patchable = 0
    GROUP BY kb.qid, kb.title
    ORDER BY detections DESC, kb.qid
")->fetchAll();
$losingDetections = array_sum(array_map(static fn(array $r): int => (int)$r['detections'], $losing));

fwrite(STDOUT, "Open CE+ failures: {$ceFail}\n");
fwrite(STDOUT, "  of which on a QID Qualys marks PATCHABLE 0 (no vendor patch) - will show NO patch clock: {$losingDetections}"
    . ($losing === [] ? "\n" : " across " . count($losing) . " QID(s):\n"));
foreach (array_slice($losing, 0, 20) as $r) {
    fwrite(STDOUT, sprintf("    QID %-8d x%-3d %s\n", (int)$r['qid'], (int)$r['detections'], mb_substr((string)$r['title'], 0, 90)));
}
if (count($losing) > 20) {
    fwrite(STDOUT, '    ... and ' . (count($losing) - 20) . " more\n");
}
fwrite(STDOUT, "  (They stay CE+ failures - end-of-life software is typically unpatchable and still fails CE+. Only the countdown is removed, since there's no patch to be late applying.)\n\n");

$candidatesSql = $colExists
    ? "SELECT COUNT(DISTINCT hd.qid) FROM host_detections hd JOIN knowledge_base kb ON kb.qid = hd.qid WHERE {$open} AND kb.patchable = 1 AND kb.patch_published_date IS NULL"
    : "SELECT COUNT(DISTINCT hd.qid) FROM host_detections hd JOIN knowledge_base kb ON kb.qid = hd.qid WHERE {$open} AND kb.patchable = 1";
$candidates = (int)$pdo->query($candidatesSql)->fetchColumn();
$calls = (int)ceil($candidates / BACKFILL_DEFAULT_BATCH_SIZE);

fwrite(STDOUT, "Backfill (scripts/backfill_patch_published_date.php):\n");
fwrite(STDOUT, "  distinct patchable QIDs on open detections still without a patch date: {$candidates}\n");
fwrite(STDOUT, "  KnowledgeBase API calls needed at the default batch size of " . BACKFILL_DEFAULT_BATCH_SIZE . ": {$calls}\n");
fwrite(STDOUT, "  Optional - without it, each QID picks the date up through the normal KB sync the next time Qualys modifies it, and the clock falls back to the published date until then.\n");
