#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Read-only diagnostic for "this QID is in Qualys's KnowledgeBase (e.g. per
 * their weekly new-QID email) but doesn't appear in our local knowledge_base
 * table".
 *
 * Queries Qualys directly for exactly the QID(s) given, via the ids= filter
 * on the KnowledgeBase Download API - a genuinely different, much narrower
 * query shape than sync_knowledge_base.php's own last_modified_after sweep,
 * specifically so this can answer one question cleanly: does Qualys's API
 * have this QID right now, independent of whatever the broad incremental
 * sync did or didn't pick up. This does NOT write anything to the database
 * unless --fix is given; it only reads. It DOES make one real Qualys API
 * call, so it costs one unit against your rate limit like any other sync
 * run.
 *
 * What to look for in the output for the QID that's missing locally:
 *
 *   - If Qualys does NOT return it at all: these API credentials don't see
 *     this QID right now, full stop - worth double-checking against
 *     Qualys's own KnowledgeBase UI directly (the weekly email announces
 *     what's been added platform-wide; a specific subscription's API access
 *     to a given QID can still depend on licensing/module scope). Nothing
 *     downstream of the API call can fix this - the data has to actually
 *     arrive here first.
 *
 *   - If Qualys DOES return it, but "Locally stored" says NOT FOUND: Qualys
 *     has the data right now, so this is a real gap in
 *     sync_knowledge_base.php's own sweep, not a Qualys-side visibility
 *     issue - worth chasing further (see that script's docblock: unlike
 *     fetchHostDetections()/fetchHostList(), fetchKnowledgeBaseChunk() has
 *     no truncation/completeness check at all, and Qualys's KnowledgeBase
 *     Download endpoint's own docs don't confirm one way or the other
 *     whether - or how - it truncates a large response). --fix below will
 *     upsert this specific QID immediately using the exact same upsert
 *     sync_knowledge_base.php itself uses, without needing to wait for or
 *     debug the broader sweep first.
 *
 *   - If Qualys returns it AND it's already stored locally: this QID is
 *     fine - useful as a control check against one from the same email that
 *     DID make it through, to confirm this script itself is behaving
 *     correctly before trusting its verdict on the QID that's actually
 *     missing.
 *
 * Usage:
 *   php scripts/diagnose_kb.php --qid=106301
 *   php scripts/diagnose_kb.php --qid=106301,106335,106333   # comma-separated, one API call either way
 *   php scripts/diagnose_kb.php --qid=106301 --fix           # also upserts any QID confirmed present on
 *                                                             # Qualys but missing locally, right now
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;
use VulnDash\Lib\Database;
use VulnDash\Scripts\QualysApiClient;

$options = getopt('', ['qid:', 'fix']);
if (!isset($options['qid']) || trim((string)$options['qid']) === '') {
    fwrite(STDERR, "Usage: php scripts/diagnose_kb.php --qid=<qid[,qid,...]> [--fix]\n");
    exit(1);
}
$requestedQids = array_values(array_filter(array_map(
    static fn(string $q): int => (int)trim($q),
    explode(',', (string)$options['qid'])
)));
$doFix = array_key_exists('fix', $options);

$client = new QualysApiClient(
    (string)Config::get('qualys.api_base_url'),
    (string)Config::get('qualys.username'),
    (string)Config::get('qualys.password'),
    (string)(Config::get('qualys.api_version') ?? '4.0')
);

$pdo = Database::getConnection();

// Wrapped in try/finally purely so the API call log below still gets
// persisted if something throws partway through - same reasoning as
// scripts/diagnose_tags.php, no catch here on purpose for the same reason.
try {

$localLookup = $pdo->prepare('
    SELECT title, severity_level, published_datetime, qualys_last_modified, cached_at, updated_at
    FROM knowledge_base WHERE qid = :qid
');

// Only prepared/used when --fix is given. Must list every key
// QualysApiClient::parseKnowledgeBaseFile() yields - see its docblock.
$upsert = $pdo->prepare('
    INSERT INTO knowledge_base
        (qid, title, severity_level, category, cvss_base, cvss_vector, cvss3_base, cvss3_vector,
         cve_ids, vendor_reference, patchable, pci_flag, diagnosis, consequence, solution,
         published_datetime, patch_published_date, qualys_last_modified)
    VALUES
        (:qid, :title, :severity_level, :category, :cvss_base, :cvss_vector, :cvss3_base, :cvss3_vector,
         :cve_ids, :vendor_reference, :patchable, :pci_flag, :diagnosis, :consequence, :solution,
         :published_datetime, :patch_published_date, :qualys_last_modified)
    ON DUPLICATE KEY UPDATE
        title = VALUES(title), severity_level = VALUES(severity_level), category = VALUES(category),
        cvss_base = VALUES(cvss_base), cvss_vector = VALUES(cvss_vector),
        cvss3_base = VALUES(cvss3_base), cvss3_vector = VALUES(cvss3_vector),
        cve_ids = VALUES(cve_ids), vendor_reference = VALUES(vendor_reference),
        patchable = VALUES(patchable), pci_flag = VALUES(pci_flag),
        diagnosis = VALUES(diagnosis), consequence = VALUES(consequence), solution = VALUES(solution),
        published_datetime = VALUES(published_datetime), patch_published_date = VALUES(patch_published_date),
        qualys_last_modified = VALUES(qualys_last_modified)
');

fwrite(STDOUT, 'Querying Qualys directly for QID(s): ' . implode(', ', $requestedQids) . "\n");
if ($doFix) {
    fwrite(STDOUT, "--fix given: any QID Qualys confirms but this table doesn't have will be upserted now.\n");
}
fwrite(STDOUT, "\n");

$fromQualys = [];
foreach ($client->fetchKnowledgeBaseByIds($requestedQids) as $vuln) {
    $fromQualys[(int)$vuln['qid']] = $vuln;
}

$fixedCount = 0;
foreach ($requestedQids as $qid) {
    fwrite(STDOUT, "=== QID {$qid} ===\n");

    if (!isset($fromQualys[$qid])) {
        fwrite(STDOUT, "  Qualys says right now: NOT returned by the API for this QID at all.\n");
    } else {
        $v = $fromQualys[$qid];
        fwrite(STDOUT, "  Qualys says right now:\n");
        fwrite(STDOUT, "    title=\"{$v['title']}\"\n");
        fwrite(STDOUT, "    severity={$v['severity_level']}  published={$v['published_datetime']}  last_modified={$v['qualys_last_modified']}\n");
    }

    $localLookup->execute(['qid' => $qid]);
    $localRow = $localLookup->fetch();

    if ($localRow === false) {
        fwrite(STDOUT, "  Locally stored: NOT FOUND in the knowledge_base table.\n");
    } else {
        fwrite(STDOUT, "  Locally stored:\n");
        fwrite(STDOUT, "    title=\"{$localRow['title']}\"\n");
        fwrite(STDOUT, "    severity={$localRow['severity_level']}  published={$localRow['published_datetime']}  last_modified={$localRow['qualys_last_modified']}\n");
        fwrite(STDOUT, "    cached_at={$localRow['cached_at']}  updated_at={$localRow['updated_at']}\n");
    }

    if (isset($fromQualys[$qid]) && $localRow === false) {
        fwrite(STDOUT, "  *** GAP: Qualys has this QID right now, but it's missing locally - a real sync gap, not a Qualys-side visibility issue. ***\n");
        if ($doFix) {
            $upsert->execute($fromQualys[$qid]);
            $fixedCount++;
            fwrite(STDOUT, "  --fix: upserted QID {$qid} into knowledge_base now.\n");
        }
    } elseif (!isset($fromQualys[$qid]) && $localRow === false) {
        fwrite(STDOUT, "  Neither Qualys nor the local table has this QID - not visible to these API credentials right now.\n");
    } elseif (isset($fromQualys[$qid]) && $localRow !== false) {
        fwrite(STDOUT, "  OK - present both on Qualys and locally.\n");
    }

    fwrite(STDOUT, "\n");
}

if ($doFix) {
    fwrite(STDOUT, "--fix: {$fixedCount} QID(s) upserted.\n");
}

fwrite(STDOUT, 'Qualys API calls made this run: ' . count($client->getCallLog()) . "\n");

$rateInfo = $client->getLastRateLimitInfo();
if ($rateInfo !== null && $rateInfo['remaining'] !== null) {
    fwrite(STDOUT, "Qualys API calls remaining: {$rateInfo['remaining']}" . ($rateInfo['limit'] !== null ? "/{$rateInfo['limit']}" : '') . ($rateInfo['window_sec'] !== null ? " (per {$rateInfo['window_sec']}s window)" : '') . "\n");
}
} finally {
    try {
        ApiCallLogRepository::recordCalls($client->getCallLog());
    } catch (\Throwable $logError) {
        fwrite(STDERR, 'Warning: failed to persist API call log: ' . $logError->getMessage() . "\n");
    }
}
