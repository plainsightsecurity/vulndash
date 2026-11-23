#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Read-only check, to run BEFORE setting qualys.show_asset_id => true:
 * do both host pulls accept show_asset_id=1 on every API version they
 * rotate across, and is the <ASSET_ID> they return the same AssetView id
 * this app already holds in assets.qualys_asset_id (resolved through the
 * Host Asset search by scripts/resolve_asset_ids.php and the queue
 * workers)?
 *
 * Why both questions matter: the syncs round-robin each pull across several
 * API versions, and an unsupported parameter fails the whole pull - so one
 * version rejecting it would fail a quarter of the hourly syncs. And the id
 * is what the on-demand scan and uninstall APIs target, so a wrong one
 * would aim those at the wrong agent (the tagName guard limits the damage,
 * but doesn't make it right).
 *
 * Costs ONE call per endpoint per version (a full, single-page pull while
 * the estate fits in qualys.host_page_size) - by default 2 endpoints x the
 * versions in qualys.host_detection_api_versions and
 * qualys.reconcile_api_versions, each on its own counter. Writes nothing to
 * assets, sync_state or sync_log; the calls are recorded in
 * qualys_api_call_log like any other. Doesn't take the sync lock, so it's
 * safe alongside cron - but keep it away from :18 and :40 so it doesn't
 * compete with the jobs for the same counters.
 *
 * Usage:
 *   php scripts/check_asset_id_from_host_pulls.php
 *   php scripts/check_asset_id_from_host_pulls.php --versions=5.0,4.0
 *   php scripts/check_asset_id_from_host_pulls.php --endpoint=host_list   # or detection, or both (default)
 *
 * Run as www-data (sudo -u www-data php ...) so the call-budget state file
 * in /tmp stays owned by the cron user.
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;
use VulnDash\Lib\Database;
use VulnDash\Scripts\QualysApiClient;

$versions = null;
$endpoint = 'both';
foreach (array_slice($argv, 1) as $arg) {
    if (preg_match('/^--versions=(.+)$/', $arg, $m)) {
        $versions = array_values(array_filter(array_map('trim', explode(',', $m[1])), static fn(string $v): bool => $v !== ''));
    } elseif (preg_match('/^--endpoint=(host_list|detection|both)$/', $arg, $m)) {
        $endpoint = $m[1];
    } else {
        fwrite(STDERR, "Unknown option: {$arg}\n");
        exit(2);
    }
}

if ($versions === null) {
    $configured = array_merge(
        (array)(Config::get('qualys.host_detection_api_versions') ?? []),
        (array)(Config::get('qualys.reconcile_api_versions') ?? [])
    );
    $versions = array_values(array_unique(array_filter(array_map(static fn($v): string => trim((string)$v), $configured), static fn(string $v): bool => $v !== '')));
    if ($versions === []) {
        $versions = [(string)(Config::get('qualys.api_version') ?? '4.0')];
    }
}

$endpoints = $endpoint === 'both' ? ['host_list', 'detection'] : [$endpoint];
$labels = ['host_list' => 'Host List', 'detection' => 'Host List Detection'];

$pdo = Database::getConnection();
$stored = [];
foreach ($pdo->query('SELECT qualys_host_id, qualys_asset_id, hostname, ip_address FROM assets') as $row) {
    $stored[(int)$row['qualys_host_id']] = $row;
}
$storedWithId = count(array_filter($stored, static fn(array $r): bool => $r['qualys_asset_id'] !== null));

fwrite(STDOUT, "==========================================================\n");
fwrite(STDOUT, "  AssetView id from the host pulls (show_asset_id=1)\n");
fwrite(STDOUT, "----------------------------------------------------------\n");
fwrite(STDOUT, '  Versions  : ' . implode(', ', $versions) . "\n");
fwrite(STDOUT, '  Endpoints : ' . implode(', ', array_map(static fn(string $e): string => $labels[$e], $endpoints)) . "\n");
fwrite(STDOUT, '  Calls     : ' . (count($versions) * count($endpoints)) . " (one per endpoint per version, while the estate fits in one page)\n");
fwrite(STDOUT, "  Local     : " . count($stored) . " asset(s), {$storedWithId} with a stored qualys_asset_id to compare against\n");
fwrite(STDOUT, "  Mode      : READ-ONLY (nothing written)\n");
fwrite(STDOUT, "==========================================================\n\n");

$failed = [];          // "label on /api/v/" => error
$mismatches = [];      // human-readable lines
$missingAny = 0;
$fillable = [];        // qualys_host_id => asset id seen
$seenByHost = [];      // qualys_host_id => [asset_id => ["label v", ...]]
$clients = [];
$exitCode = 0;

try {
    foreach ($versions as $version) {
        $client = new QualysApiClient(
            (string)Config::get('qualys.api_base_url'),
            (string)Config::get('qualys.username'),
            (string)Config::get('qualys.password'),
            $version,
            Config::get('qualys.agent_scope_tag') !== null ? (string)Config::get('qualys.agent_scope_tag') : null,
            is_array(Config::get('qualys.excluded_tags')) ? Config::get('qualys.excluded_tags') : null
        );
        $client->setShowAssetId(true);
        $clients[] = $client;

        foreach ($endpoints as $ep) {
            $where = "{$labels[$ep]} on /api/{$version}/";
            fwrite(STDOUT, "=== {$where} ===\n");

            $counts = ['hosts' => 0, 'with_id' => 0, 'match' => 0, 'fill' => 0, 'differs' => 0, 'not_stored' => 0, 'missing' => 0];
            try {
                $hosts = $ep === 'host_list' ? $client->fetchHostList() : $client->fetchHostDetections();
                foreach ($hosts as $host) {
                    $counts['hosts']++;
                    $hostId = (int)$host['id'];
                    $assetId = $host['asset_id'] ?? null;
                    $label = (string)($host['hostname'] ?: ($host['ip'] ?: "Qualys host ID {$hostId}"));

                    if ($assetId === null) {
                        $counts['missing']++;
                        continue;
                    }
                    $counts['with_id']++;
                    $seenByHost[$hostId][$assetId][] = "{$labels[$ep]} {$version}";

                    if (!isset($stored[$hostId])) {
                        $counts['not_stored']++;
                    } elseif ($stored[$hostId]['qualys_asset_id'] === null) {
                        $counts['fill']++;
                        $fillable[$hostId] = $assetId;
                    } elseif ((int)$stored[$hostId]['qualys_asset_id'] === $assetId) {
                        $counts['match']++;
                    } else {
                        $counts['differs']++;
                        $mismatches[] = "{$label} (host {$hostId}): {$where} says {$assetId}, stored is {$stored[$hostId]['qualys_asset_id']}";
                    }
                }

                $missingAny += $counts['missing'];
                fwrite(STDOUT, "  Accepted. {$counts['hosts']} host(s), {$counts['with_id']} carrying ASSET_ID\n");
                fwrite(STDOUT, "    matches stored id     : {$counts['match']}\n");
                fwrite(STDOUT, "    stored id empty (fill): {$counts['fill']}\n");
                fwrite(STDOUT, "    DIFFERS from stored   : {$counts['differs']}\n");
                fwrite(STDOUT, "    not stored locally    : {$counts['not_stored']}\n");
                fwrite(STDOUT, "    no ASSET_ID returned  : {$counts['missing']}\n");
                if ($counts['hosts'] > 0 && $counts['with_id'] === 0) {
                    fwrite(STDOUT, "    (accepted the parameter but returned no ASSET_ID at all - treat this version as not supporting it)\n");
                    $failed[$where] = 'parameter accepted but no ASSET_ID returned';
                }
            } catch (\Throwable $e) {
                $failed[$where] = $e->getMessage();
                fwrite(STDOUT, "  FAILED: {$e->getMessage()}\n");
            }

            $rate = $client->getLastRateLimitInfo();
            if ($rate !== null && $rate['remaining'] !== null) {
                fwrite(STDOUT, "  Calls remaining on this endpoint and version: {$rate['remaining']}" . ($rate['limit'] !== null ? "/{$rate['limit']}" : '') . "\n");
            }
            fwrite(STDOUT, "\n");
        }
    }

    // The same host should carry the same id whichever endpoint or version
    // reported it - if not, at least one of them can't be trusted.
    $inconsistent = [];
    foreach ($seenByHost as $hostId => $ids) {
        if (count($ids) > 1) {
            $parts = [];
            foreach ($ids as $aid => $sources) {
                $parts[] = "{$aid} (" . implode(', ', $sources) . ')';
            }
            $inconsistent[] = "host {$hostId}: " . implode(' vs ', $parts);
        }
    }

    fwrite(STDOUT, "----------------------------------------------------------\n");
    foreach ($mismatches as $line) {
        fwrite(STDOUT, "  MISMATCH: {$line}\n");
    }
    foreach ($inconsistent as $line) {
        fwrite(STDOUT, "  INCONSISTENT between pulls: {$line}\n");
    }
    $matched = 0;
    foreach ($seenByHost as $hostId => $ids) {
        if (isset($stored[$hostId]) && $stored[$hostId]['qualys_asset_id'] !== null && isset($ids[(int)$stored[$hostId]['qualys_asset_id']])) {
            $matched++;
        }
    }

    if ($failed !== []) {
        fwrite(STDOUT, "VERDICT: NOT READY - show_asset_id was refused or ignored on:\n");
        foreach ($failed as $where => $why) {
            fwrite(STDOUT, "    {$where}: {$why}\n");
        }
        fwrite(STDOUT, "  Leave qualys.show_asset_id off, or drop those versions from the rotation lists first. Paste this output.\n");
        $exitCode = 1;
    } elseif ($mismatches !== [] || $inconsistent !== []) {
        fwrite(STDOUT, "VERDICT: NOT READY - ASSET_ID disagrees with the stored ids or between pulls (see above). Leave qualys.show_asset_id off and paste this output.\n");
        $exitCode = 1;
    } elseif ($matched === 0) {
        fwrite(STDOUT, "VERDICT: INCONCLUSIVE - every pull accepted the parameter, but no host had a stored qualys_asset_id to compare against.\n");
        fwrite(STDOUT, "  Run scripts/resolve_asset_ids.php (dry run) and compare its pairs with the ASSET_IDs above, or --confirm it and re-run this.\n");
        $exitCode = 1;
    } else {
        fwrite(STDOUT, "VERDICT: READY - every pull accepted show_asset_id, and all {$matched} host(s) with a stored id matched.\n");
        if ($fillable !== []) {
            fwrite(STDOUT, '  ' . count($fillable) . " host(s) with no stored id would be filled by the next sync.\n");
        }
        if ($missingAny > 0) {
            fwrite(STDOUT, "  {$missingAny} host result(s) came back without an ASSET_ID - those keep using the Host Asset search fallback.\n");
        }
        fwrite(STDOUT, "  Set 'show_asset_id' => true in the qualys block of src/config/config.php.\n");
    }
} finally {
    foreach ($clients as $c) {
        try {
            ApiCallLogRepository::recordCalls($c->getCallLog());
        } catch (\Throwable $logError) {
            fwrite(STDERR, 'Warning: failed to persist API call log: ' . $logError->getMessage() . "\n");
        }
    }
}

exit($exitCode);
