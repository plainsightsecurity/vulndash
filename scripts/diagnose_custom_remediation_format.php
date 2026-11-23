#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Run this BEFORE database/migrations/2026-10-add-custom-remediation-format.sql.
 *
 * That migration adds custom_remediations.content_format, defaulting every
 * existing row to 'text'. It changes no remediation text, so the questions
 * here are: is it already applied, how many overrides exist, and do any of
 * them already contain HTML-looking markup? Such a row would be marked 'text'
 * and so shown escaped (tags visible as literal text) until an admin opens
 * it in the new editor and saves - worth knowing before deploying, since
 * the plain <textarea> never rendered HTML, so any markup in there was typed
 * or pasted as-is.
 *
 * READ-ONLY. No --confirm, no write path of any kind.
 *
 * Usage:
 *   php scripts/diagnose_custom_remediation_format.php
 */

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Database;

$pdo = Database::getConnection();

fwrite(STDOUT, "[READ-ONLY - this script never writes anything]\n\n");

$colExists = (int)$pdo->query("
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'custom_remediations' AND COLUMN_NAME = 'content_format'
")->fetchColumn() > 0;

fwrite(STDOUT, 'Column content_format: ' . ($colExists ? 'ALREADY PRESENT - the migration will be a no-op' : 'missing - will be added') . "\n\n");

$rows = $pdo->query('
    SELECT cr.qid, kb.title, cr.updated_at, CHAR_LENGTH(cr.remediation) AS chars, cr.remediation'
    . ($colExists ? ', cr.content_format' : '') . '
    FROM custom_remediations cr
    LEFT JOIN knowledge_base kb ON kb.qid = cr.qid
    ORDER BY cr.qid
')->fetchAll();

fwrite(STDOUT, 'Custom remediation overrides: ' . count($rows) . "\n");

if ($rows === []) {
    fwrite(STDOUT, "\n--- Verdict ---\nNothing to consider: no overrides exist yet. Safe to apply.\n");
    exit(0);
}

$looksHtml = 0;
fwrite(STDOUT, "\n");
foreach ($rows as $row) {
    // Heuristic only, for this report - the app itself never guesses, it goes
    // by content_format. An opening/closing tag name is a strong signal; a lone
    // "<" (e.g. "versions < 2.0") is not.
    $hasMarkup = preg_match('#</?[a-z][a-z0-9]*[\s>/]#i', (string)$row['remediation']) === 1;
    if ($hasMarkup) {
        $looksHtml++;
    }
    $preview = preg_replace('/\s+/', ' ', mb_substr((string)$row['remediation'], 0, 70));
    fwrite(STDOUT, sprintf(
        "  QID %-8d %-6s %5d chars  updated %s%s\n      %s\n      \"%s%s\"\n",
        (int)$row['qid'],
        $colExists ? '[' . $row['content_format'] . ']' : '',
        (int)$row['chars'],
        (string)$row['updated_at'],
        $hasMarkup ? '  ** contains HTML-looking markup **' : '',
        mb_substr((string)($row['title'] ?? '(no KB title)'), 0, 80),
        $preview,
        (int)$row['chars'] > 70 ? '...' : ''
    ));
}

fwrite(STDOUT, "\n--- Verdict ---\n");
if ($colExists) {
    fwrite(STDOUT, "Already applied. Running the migration again is harmless.\n");
} else {
    fwrite(STDOUT, 'Safe to apply: additive only. All ' . count($rows) . " existing override(s) will be marked 'text' and\n");
    fwrite(STDOUT, "display exactly as they do now. Each becomes 'html' the next time it is saved in the editor.\n");
}
if ($looksHtml > 0) {
    fwrite(STDOUT, "\n{$looksHtml} override(s) contain HTML-looking markup. As 'text' rows they keep showing that\n");
    fwrite(STDOUT, "markup as literal text (as they do today). Opening one in the editor will also show the tags as\n");
    fwrite(STDOUT, "text - delete them there, or re-enter the content with the editor's formatting, then save.\n");
}
