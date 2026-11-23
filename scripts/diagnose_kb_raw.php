#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Read-only diagnostic: shows EVERY top-level field Qualys's KnowledgeBase
 * Download API actually returns for the given QID(s), not just the subset
 * parseKnowledgeBaseFile() maps into this app's schema.
 *
 * Added 2026-07 specifically to check what field (VULN_TYPE, or whatever
 * it's actually called) distinguishes real vulnerabilities from
 * Information Gathered / Potential Vulnerability / Practice entries -
 * this app doesn't capture or store that distinction anywhere today, so
 * the only way to know what it actually looks like is to look at a real
 * response directly rather than guess from a proxy like severity_level.
 *
 * Deliberately does NOT reuse fetchKnowledgeBaseByIds() -
 * parseKnowledgeBaseFile() only ever yields the specific fields this app
 * already knows to look for, so anything not already mapped (which is
 * exactly what's in question here) would never reach this script at all.
 * Uses fetchKnowledgeBaseRawXmlByIds() instead, added alongside this
 * script for exactly this purpose, to see the response untouched.
 *
 * Does not touch the database and does not upsert anything - purely
 * prints what Qualys sends back. Long free-text fields (DIAGNOSIS,
 * CONSEQUENCE, SOLUTION, VENDOR_REFERENCE_LIST) are truncated for
 * readability; every other top-level field is shown in full so nothing
 * relevant to this question gets hidden.
 *
 * --api-version (added 2026-11-04): Qualys counts calls per endpoint PER API
 * version (see QualysApiClient::budgetKeyForUrl()), so when the configured
 * version's KnowledgeBase budget is exhausted - usually by the KB sync -
 * a one-off diagnostic can run against another version's independent
 * counter instead of waiting for the window to roll over. Defaults to
 * qualys.api_version, exactly as before. First needed to check whether
 * PATCH_PUBLISHED_DATE is populated on this subscription (a candidate start
 * date for the CE+ patch clock - see src/Lib/CePlusDeadline.php).
 *
 * Usage:
 *   php scripts/diagnose_kb_raw.php --qid=6
 *   php scripts/diagnose_kb_raw.php --qid=6,9,90004,730600   # comma-separated, one API call either way
 *   php scripts/diagnose_kb_raw.php --qid=6 --api-version=5.0
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;
use VulnDash\Scripts\QualysApiClient;

$usage = "Usage: php scripts/diagnose_kb_raw.php --qid=<qid[,qid,...]> [--api-version=<e.g. 5.0>]\n";

$options = getopt('', ['qid:', 'api-version:']);
if (!isset($options['qid']) || trim((string)$options['qid']) === '') {
    fwrite(STDERR, $usage);
    exit(1);
}
$requestedQids = array_values(array_filter(array_map(
    static fn(string $q): int => (int)trim($q),
    explode(',', (string)$options['qid'])
)));

// Checked strictly because it becomes part of the request path (/api/<v>/).
$apiVersion = isset($options['api-version'])
    ? trim((string)$options['api-version'])
    : (string)(Config::get('qualys.api_version') ?? '4.0');
if (preg_match('/^\d+\.\d+$/', $apiVersion) !== 1) {
    fwrite(STDERR, "--api-version must look like 4.0 or 5.0 (got " . var_export($apiVersion, true) . ").\n" . $usage);
    exit(1);
}

$client = new QualysApiClient(
    (string)Config::get('qualys.api_base_url'),
    (string)Config::get('qualys.username'),
    (string)Config::get('qualys.password'),
    $apiVersion
);

$LONG_FIELDS = ['DIAGNOSIS', 'CONSEQUENCE', 'SOLUTION', 'VENDOR_REFERENCE_LIST', 'COMPLIANCE_LIST', 'THREAT_INTELLIGENCE'];
$TRUNCATE_AT = 120;

// Set rather than exit()ing inside the catch: exit() skips the finally below,
// which would silently drop the API call log.
$exitCode = 0;

try {
    fwrite(STDOUT, 'Querying Qualys directly (/api/' . $apiVersion . '/) for QID(s): ' . implode(', ', $requestedQids) . "\n\n");

    $rawXml = $client->fetchKnowledgeBaseRawXmlByIds($requestedQids);
    if (trim($rawXml) === '') {
        fwrite(STDOUT, "Empty response - Qualys returned nothing for these QIDs (see diagnose_kb.php for the usual not-found-vs-gap distinction).\n");
    } else {
        // A version that doesn't exist for this endpoint (e.g. --api-version=1.0)
        // gets an HTML error page back, not XML - parsed quietly so that's one
        // readable line instead of a screen of libxml warnings and a fatal.
        $prevLibxml = libxml_use_internal_errors(true);
        $xml = simplexml_load_string($rawXml);
        libxml_clear_errors();
        libxml_use_internal_errors($prevLibxml);
        if ($xml === false) {
            $snippet = trim((string)preg_replace('/\s+/', ' ', strip_tags(mb_substr($rawXml, 0, 600))));
            throw new \RuntimeException(
                "Qualys's response on /api/{$apiVersion}/ wasn't XML - most likely that API version doesn't exist for the KnowledgeBase endpoint. "
                . 'Start of response: ' . mb_substr($snippet, 0, 160)
            );
        }
        $vulns = $xml->xpath('//VULN') ?: [];

        if ($vulns === []) {
            fwrite(STDOUT, "No <VULN> elements found in the response - none of these QIDs are recognised by Qualys right now.\n");
        }

        foreach ($vulns as $vuln) {
            $qid = (string)$vuln->QID;
            fwrite(STDOUT, "=== QID {$qid} ===\n");
            foreach ($vuln->children() as $name => $value) {
                if (in_array($name, $LONG_FIELDS, true)) {
                    $text = trim((string)$value);
                    $shown = mb_strlen($text) > $TRUNCATE_AT ? mb_substr($text, 0, $TRUNCATE_AT) . '...(truncated)' : $text;
                    fwrite(STDOUT, "  {$name} (truncated): {$shown}\n");
                    continue;
                }
                // Nested elements (CVE_LIST, VENDOR_REFERENCE_LIST, CVSS, etc.)
                // print their own child count rather than a raw SimpleXML
                // object stringification, which is usually empty/unhelpful
                // for anything with sub-structure.
                if ($value->count() > 0) {
                    fwrite(STDOUT, "  {$name}: (nested, " . $value->count() . " child element(s))\n");
                    continue;
                }
                fwrite(STDOUT, "  {$name}: " . trim((string)$value) . "\n");
            }
            fwrite(STDOUT, "\n");
        }
    }

    fwrite(STDOUT, 'Qualys API calls made this run: ' . count($client->getCallLog()) . "\n");
    $rateInfo = $client->getLastRateLimitInfo();
    if ($rateInfo !== null && $rateInfo['remaining'] !== null) {
        fwrite(STDOUT, "Qualys API calls remaining on /api/{$apiVersion}/: {$rateInfo['remaining']}" . ($rateInfo['limit'] !== null ? "/{$rateInfo['limit']}" : '') . ($rateInfo['window_sec'] !== null ? " (per {$rateInfo['window_sec']}s window)" : '') . "\n");
    }
} catch (\RuntimeException $e) {
    // Rate-limit/budget refusals, auth failures and Qualys error bodies all
    // arrive as RuntimeException with a readable message - print that, not a
    // stack trace.
    fwrite(STDERR, "Not completed: {$e->getMessage()}\n");
    if (!isset($options['api-version'])) {
        fwrite(STDERR, "If this is the KnowledgeBase budget, another API version has its own counter - e.g. add --api-version=5.0\n");
    }
    $exitCode = 1;
} finally {
    try {
        ApiCallLogRepository::recordCalls($client->getCallLog());
    } catch (\Throwable $logError) {
        fwrite(STDERR, 'Warning: failed to persist API call log: ' . $logError->getMessage() . "\n");
    }
}

exit($exitCode);
