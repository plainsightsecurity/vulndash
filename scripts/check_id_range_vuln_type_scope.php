#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * One-off, disposable check: does fetchKnowledgeBaseByIdRange() (the
 * id_min/id_max call reconcile_kb_by_id.php's whole walk depends on)
 * actually return known Information Gathered QIDs, or does that
 * parameter combination implicitly exclude them the way the walk's
 * "375,019 total seen" (matching the UI's Vulnerability-only count, not
 * the ~429K local total) suggests?
 *
 * QID 6 ("DNS Host Name") is a confirmed, definitely-real, definitely-
 * Information-Gathered QID (see diagnose_kb_raw.php's actual output for
 * it earlier) - if a narrow id_min/id_max range containing it comes back
 * without QID 6, that's direct confirmation this parameter combination
 * can't see that content type at all, meaning reconcile_kb_by_id.php's
 * completeness guarantee only ever covered the Vulnerability/Potential
 * Vulnerability subset, not the full local dataset.
 *
 * Read-only, no upserts, one small API call.
 *
 * Usage:
 *   php scripts/check_id_range_vuln_type_scope.php
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;
use VulnDash\Scripts\QualysApiClient;

$client = new QualysApiClient(
    (string)Config::get('qualys.api_base_url'),
    (string)Config::get('qualys.username'),
    (string)Config::get('qualys.password'),
    (string)(Config::get('qualys.api_version') ?? '4.0')
);

try {
    fwrite(STDOUT, "Querying id_min=1, id_max=20 (contains QID 6, a known Information Gathered entry)...\n\n");

    $foundQids = [];
    foreach ($client->fetchKnowledgeBaseByIdRange(1, 20) as $vuln) {
        $foundQids[] = $vuln['qid'];
    }

    fwrite(STDOUT, 'QIDs returned: ' . implode(', ', $foundQids) . "\n\n");

    if (in_array(6, $foundQids, true)) {
        fwrite(STDOUT, "QID 6 WAS returned - id_min/id_max does NOT exclude Information Gathered entries. The count discrepancy has some other explanation - worth digging further rather than assuming VULN_TYPE scoping.\n");
    } else {
        fwrite(STDOUT, "QID 6 was NOT returned, despite being within this range and definitely existing (confirmed via diagnose_kb_raw.php earlier).\n");
        fwrite(STDOUT, "This confirms it: id_min/id_max implicitly excludes Information Gathered content. reconcile_kb_by_id.php's completeness guarantee only covers the Vulnerability/Potential Vulnerability subset (~375K), not the full local dataset (~429K).\n");
    }
} finally {
    try {
        ApiCallLogRepository::recordCalls($client->getCallLog());
    } catch (\Throwable $logError) {
        fwrite(STDERR, 'Warning: failed to persist API call log: ' . $logError->getMessage() . "\n");
    }
}
