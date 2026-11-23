#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Read-only pre-migration diagnostic for
 * database/migrations/2026-11-add-tag-ce-assessment-date.sql.
 *
 * The migration only adds a nullable column, so it can't damage anything.
 * What matters is that the CE+ readiness page (public/ce_readiness.php)
 * reads that column and errors until the migration has run - so this says
 * whether it's applied yet, and gives a preview of what the page will show
 * (platform-wide, the admin "All tags" view): how many active hosts would
 * fail CE+ today, how many are only at risk, and how many hidden findings
 * the page counts that the dashboard cards leave out.
 *
 * Makes no API calls and writes nothing. Safe to run before and after the
 * migration.
 *
 * Usage:
 *   php scripts/diagnose_tag_ce_assessment_date_migration.php
 */

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\CePlusDeadline;
use VulnDash\Lib\CePlusReadiness;
use VulnDash\Lib\Database;

$pdo = Database::getConnection();

$colExists = (int)$pdo->query("
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tags' AND COLUMN_NAME = 'ce_assessment_date'
")->fetchColumn() === 1;

fwrite(STDOUT, "tags.ce_assessment_date: " . ($colExists ? "PRESENT (migration already applied)" : "absent (migration not yet applied - /ce_readiness will error until it is)") . "\n");
fwrite(STDOUT, "tags rows: " . number_format((int)$pdo->query('SELECT COUNT(*) FROM tags')->fetchColumn()) . "\n");
if ($colExists) {
    $dated = (int)$pdo->query('SELECT COUNT(*) FROM tags WHERE ce_assessment_date IS NOT NULL')->fetchColumn();
    fwrite(STDOUT, "  with an assessment date set: {$dated}\n");
}
fwrite(STDOUT, "\n");

// Same "open" definition as VulnerabilityRepository::BASE_DETECTION_FILTER,
// and the same clock rule as CePlusDeadline / CePlusReadiness - no-fix
// (PATCHABLE 0) findings don't count towards a host's status, except
// end-of-life ones, which always fail whatever their score. Agent-uninstall
// suppression is not applied here, so this can be a few hosts higher than the
// page's admin view.
$open  = "hd.status != 'Fixed' AND hd.effective_cvss_score > 0.0";
$clock = CePlusDeadline::CLOCK_START_SQL;
$eol   = CePlusReadiness::EOL_TITLE_SQL;
$stmt = $pdo->prepare("
    SELECT
        SUM(CASE WHEN h.blocking > 0 THEN 1 ELSE 0 END) AS failing,
        SUM(CASE WHEN h.blocking = 0 AND h.ce_total > 0 THEN 1 ELSE 0 END) AS at_risk,
        SUM(CASE WHEN h.blocking = 0 AND h.ce_total = 0 THEN 1 ELSE 0 END) AS passing,
        COUNT(*) AS hosts
    FROM (
        SELECT a.id,
               SUM(CASE WHEN hd.id IS NOT NULL AND NOT {$eol} AND kb.patchable <> 0 THEN 1 ELSE 0 END) AS ce_total,
               SUM(CASE WHEN hd.id IS NOT NULL AND ({$eol} OR (kb.patchable <> 0 AND ({$clock} IS NULL OR {$clock} < :cutoff))) THEN 1 ELSE 0 END) AS blocking
        FROM assets a
        LEFT JOIN (host_detections hd JOIN knowledge_base kb ON kb.qid = hd.qid)
               ON hd.asset_id = a.id AND {$open} AND (hd.is_ce_plus_fail = 1 OR {$eol})
        WHERE a.is_active = 1
        GROUP BY a.id
    ) h
");
$stmt->execute(['cutoff' => CePlusDeadline::overdueCutoffUtc()]);
$r = $stmt->fetch();

$hidden = (int)$pdo->query("
    SELECT COUNT(DISTINCT hd.id) FROM host_detections hd
    JOIN assets a ON a.id = hd.asset_id AND a.is_active = 1
    JOIN hidden_issues hi ON hi.qid = hd.qid
    WHERE {$open} AND hd.is_ce_plus_fail = 1
")->fetchColumn();

fwrite(STDOUT, "Preview of /ce_readiness (all active hosts, today):\n");
fwrite(STDOUT, "  hosts   : " . (int)$r['hosts'] . "\n");
fwrite(STDOUT, "  failing : " . (int)$r['failing'] . "  (end-of-life software, an overdue CE+ finding, or one with no usable date)\n");
fwrite(STDOUT, "  at risk : " . (int)$r['at_risk'] . "  (CE+ findings, all still inside the 14-day window)\n");
fwrite(STDOUT, "  passing : " . (int)$r['passing'] . "\n");
fwrite(STDOUT, "  open CE+ findings on active hosts whose QID someone has hidden: {$hidden} - the readiness page counts these; the dashboard cards don't\n");
