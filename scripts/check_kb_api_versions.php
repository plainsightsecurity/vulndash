#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * One-off, disposable check: does the KnowledgeBase Download endpoint
 * actually work on /api/2.0/ and /api/3.0/ for this subscription, or has
 * it been retired (like Host List Detection was, per the EOS note in
 * src/config/config.php) alongside the move to 4.0?
 *
 * Added 2026-07 specifically to answer "is it worth round-robining across
 * API versions to get 3x the hourly call budget for the KB rescan" -
 * rather than guessing, or building the round-robin logic first and
 * finding out the hard way. Read-only (fetchKnowledgeBaseByIds() never
 * writes), makes at most 2 real API calls (one per older version tested),
 * and doesn't touch sync_knowledge_base.php's lock file or sync_state, so
 * it's safe to run in a separate terminal alongside an in-progress rescan
 * without any interference either way.
 *
 * Delete this file once you have your answer - it's not meant to become
 * a permanent part of the app.
 *
 * Usage:
 *   php scripts/check_kb_api_versions.php
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\Config;
use VulnDash\Scripts\QualysApiClient;

// A QID already confirmed present in both Qualys and your local table -
// see the very first diagnose_kb.php run in this investigation. Any QID
// you know for certain is real would do; this one's just already proven.
const KNOWN_GOOD_QID = 106335;

foreach (['2.0', '3.0'] as $version) {
    fwrite(STDOUT, "=== Testing KnowledgeBase Download on /api/{$version}/ ===\n");
    try {
        $client = new QualysApiClient(
            (string)Config::get('qualys.api_base_url'),
            (string)Config::get('qualys.username'),
            (string)Config::get('qualys.password'),
            $version
        );

        $found = false;
        foreach ($client->fetchKnowledgeBaseByIds([KNOWN_GOOD_QID]) as $vuln) {
            $found = true;
            fwrite(STDOUT, "  WORKS - got QID {$vuln['qid']}: \"{$vuln['title']}\"\n");
        }
        if (!$found) {
            fwrite(STDOUT, "  Call succeeded but returned no data for QID " . KNOWN_GOOD_QID . " - unexpected since this QID is known-good; worth a closer look before trusting this version.\n");
        }

        $rateInfo = $client->getLastRateLimitInfo();
        if ($rateInfo !== null && $rateInfo['remaining'] !== null) {
            fwrite(STDOUT, "  Rate limit on this version right now: {$rateInfo['remaining']}" . ($rateInfo['limit'] !== null ? "/{$rateInfo['limit']}" : '') . "\n");
        }
    } catch (\Throwable $e) {
        fwrite(STDOUT, "  FAILED: " . $e->getMessage() . "\n");
        fwrite(STDOUT, "  (an EOS/deprecation error here means this version is a dead end for KB on this subscription - not worth building round-robin logic around it)\n");
    }
    fwrite(STDOUT, "\n");
}
