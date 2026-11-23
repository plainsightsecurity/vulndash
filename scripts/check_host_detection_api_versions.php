#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * One-off, disposable check: does Host List Detection actually work on
 * /api/3.0/ for this subscription, or is it a dead end the same way
 * /api/2.0/ already is (per the EOS note in src/config/config.php)?
 *
 * /api/2.0/ is retested here too, purely to confirm that EOS is still in
 * effect rather than assuming a past observation still holds forever -
 * cheap to check both while we're at it.
 *
 * Added 2026-07 as the direct answer to "can sync_host_detections.php
 * round-robin across API versions the way sync_knowledge_base.php does" -
 * rather than guessing, or building round-robin logic first and finding
 * out the hard way. Read-only (fetchHostDetections() never writes), and
 * deliberately forces pageSize=1 so each test costs the smallest possible
 * single page rather than a full host sweep - doesn't touch
 * sync_host_detections.php's lock file or sync_state, so it's safe to run
 * in a separate terminal without any interference either way.
 *
 * Delete this file once you have your answer - it's not meant to become
 * a permanent part of the app.
 *
 * Usage:
 *   php scripts/check_host_detection_api_versions.php
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\Config;
use VulnDash\Scripts\QualysApiClient;

foreach (['2.0', '3.0'] as $version) {
    fwrite(STDOUT, "=== Testing Host List Detection on /api/{$version}/ ===\n");
    try {
        $client = new QualysApiClient(
            (string)Config::get('qualys.api_base_url'),
            (string)Config::get('qualys.username'),
            (string)Config::get('qualys.password'),
            $version
        );

        $found = false;
        foreach ($client->fetchHostDetections(null, 1) as $host) {
            $found = true;
            fwrite(STDOUT, "  WORKS - got a host: {$host['hostname']} ({$host['ip']})\n");
            break; // pageSize=1 already bounds this, but stop reading immediately regardless
        }
        if (!$found) {
            fwrite(STDOUT, "  Call succeeded but returned no hosts at all - unexpected if this account has any scanned assets; worth a closer look before trusting this version.\n");
        }

        $rateInfo = $client->getLastRateLimitInfo();
        if ($rateInfo !== null && $rateInfo['remaining'] !== null) {
            fwrite(STDOUT, "  Rate limit on this version right now: {$rateInfo['remaining']}" . ($rateInfo['limit'] !== null ? "/{$rateInfo['limit']}" : '') . ($rateInfo['window_sec'] !== null ? " (per {$rateInfo['window_sec']}s window)" : '') . "\n");
        }
    } catch (\Throwable $e) {
        fwrite(STDOUT, "  FAILED: " . $e->getMessage() . "\n");
        fwrite(STDOUT, "  (an EOS/deprecation error here means this version is a dead end for Host List Detection on this subscription - matches the existing 2.0 note in config.php if this is 2.0, or extends it to 3.0 too if it is)\n");
    }
    fwrite(STDOUT, "\n");
}

fwrite(STDOUT, "Note: this deliberately does not test /api/4.0/ - that's already the confirmed, currently-used baseline for this endpoint, so there's nothing to learn by re-testing it here.\n");
