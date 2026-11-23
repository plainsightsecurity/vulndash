#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Read-only diagnostic for "a tag/asset isn't showing up in the dashboard"
 * OR "a host's hostname/IP/DNS/OS in the dashboard doesn't match Qualys".
 *
 * Pulls hosts straight from Qualys's Host List Detection API - a full,
 * UNFILTERED pull (no vm_scan_since) so nothing is hidden by the normal
 * incremental sync window - and for each host, prints exactly what tags
 * Qualys returned for it right now, side by side with what's currently
 * stored locally (assets + asset_tags). It also now prints the live
 * hostname/IP/DNS name/OS/tracking method/last scan date Qualys just
 * returned next to the same fields as currently stored locally, and flags
 * a mismatch explicitly - added 2026-07 specifically to diagnose a host
 * that's been renamed on the Qualys side and doesn't seem to be picking up
 * the new hostname on the dashboard. This does NOT write anything to the
 * database unless --full is given; it only reads. It DOES make one real
 * Qualys API call, so it costs one unit against your rate limit like any
 * other sync run (see the docblock in scripts/lib/QualysApiClient.php for
 * your subscription's limits).
 *
 * What to look for in the output for the host/tag/hostname that's wrong on
 * the dashboard:
 *
 *   - If the host doesn't appear in this script's output AT ALL: Qualys's
 *     API isn't returning it to these credentials, full stop - this is a
 *     Qualys-side visibility/permission issue (check the API user's
 *     assigned Asset Groups / Business Unit / Unit Manager scope in
 *     Qualys's own user administration), not a bug in this app. Nothing
 *     downstream of the API call can fix this - the data has to actually
 *     arrive here first.
 *
 *   - If the host appears and "Qualys says right now" already shows the
 *     OLD/wrong hostname (i.e. no *** MISMATCH *** line, but the value
 *     itself is stale): this app is faithfully reporting what Qualys's
 *     Host List Detection API is currently returning - the rename hasn't
 *     propagated into that API's HOSTNAME/DNS_DATA/NETBIOS fields yet on
 *     Qualys's own side. This is common with Cloud Agent: the agent's
 *     continuous system-profile sync (what you may be seeing as "still on
 *     Qualys" with the new name, e.g. in Asset View/Global IT Asset
 *     Inventory) runs on a different schedule than the VM module's asset
 *     record that Host List Detection reads from, and the two can
 *     genuinely disagree for a while. Nothing downstream of the API
 *     response can fix this either - re-run this script later, or trigger
 *     a fresh agent reassessment in Qualys, to see if it's caught up.
 *
 *   - If the host appears and "Qualys says right now" already shows the
 *     NEW/correct hostname but a *** MISMATCH *** line shows the locally
 *     stored value is still the old one: Qualys already has the current
 *     data, so this IS a sync gap on this app's side. For tags, that's the
 *     normal incremental sync (scripts/sync_host_detections.php) not
 *     having picked it up yet - most likely because this host's last scan
 *     predates the last successful sync run, so the vm_scan_since filter
 *     is skipping it. For hostname/IP/DNS/OS specifically, the normal
 *     incremental sync has that exact same blind spot (a rename with no
 *     accompanying scan never reaches it), which is precisely why
 *     scripts/reconcile_asset_inventory.php exists and is supposed to be
 *     running hourly with --confirm to catch it - if you're seeing this
 *     mismatch, check that job is actually succeeding (crontab entry,
 *     /var/log/vulndash/asset_inventory_reconcile.log) rather than
 *     assuming it isn't running at all; as of 2026-07 it isn't wired into
 *     sync_log, so its health doesn't show on the dashboard's admin sync
 *     panel and a silent failure there wouldn't be visible any other way.
 *     Either way, --full below (or reconcile_asset_inventory.php
 *     --confirm) will fix this specific host immediately.
 *
 *   - If the host, its tags, and its hostname/IP/DNS/OS all appear
 *     correctly under BOTH "Qualys says right now" and "Locally stored":
 *     the data is syncing fine, and whatever's wrong is in how the
 *     dashboard queries/displays it instead - a real bug, and a different
 *     conversation.
 *
 * Usage:
 *   php scripts/diagnose_tags.php                  # every host Qualys returns
 *   php scripts/diagnose_tags.php --host=<substring of hostname or IP>
 *   php scripts/diagnose_tags.php --full            # also run sync_host_detections.php's
 *                                                    # own upsert logic against this same
 *                                                    # unfiltered pull, so a host missed by
 *                                                    # the incremental window gets caught up
 *                                                    # immediately instead of waiting for
 *                                                    # its next scan. Safe to run any time -
 *                                                    # it's the same upsert logic the normal
 *                                                    # cron job uses, just without the
 *                                                    # vm_scan_since filter for this one run.
 *   php scripts/diagnose_tags.php --page-size=2     # forces a tiny truncation_limit so
 *                                                    # Qualys actually truncates the response
 *                                                    # and this has to follow its own
 *                                                    # multi-page continuation loop for real,
 *                                                    # instead of getting everything back in
 *                                                    # one page the way this subscription's
 *                                                    # current host count normally would. The
 *                                                    # host count/list printed at the end
 *                                                    # should still match a normal run with no
 *                                                    # --page-size given - if it doesn't,
 *                                                    # something's wrong with the pagination
 *                                                    # loop itself (QualysApiClient.php's
 *                                                    # extractContinuationUrl()), not with
 *                                                    # anything downstream of it. Combine with
 *                                                    # --host to keep the output readable
 *                                                    # while still forcing several real pages
 *                                                    # along the way. Read-only either way,
 *                                                    # same as any other run of this script -
 *                                                    # --page-size doesn't write anything on
 *                                                    # its own, only --full does that.
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;
use VulnDash\Lib\CvssCalculator;
use VulnDash\Lib\Database;
use VulnDash\Lib\TagScopeClassifier;
use VulnDash\Lib\UserRepository;
use VulnDash\Lib\VulnerabilityRepository;
use VulnDash\Scripts\QualysApiClient;

$options = getopt('', ['host::', 'full', 'page-size::']);
$hostFilter = $options['host'] ?? null;
$doFull = array_key_exists('full', $options);
$pageSize = isset($options['page-size']) ? (int)$options['page-size'] : null;

$client = new QualysApiClient(
    (string)Config::get('qualys.api_base_url'),
    (string)Config::get('qualys.username'),
    (string)Config::get('qualys.password'),
    (string)(Config::get('qualys.api_version') ?? '4.0')
);

$pdo = Database::getConnection();

// The rest of this script's body is wrapped in try/finally purely so the
// API call log below still gets persisted if something throws partway
// through (a network error mid-pull, say) - there's no catch here because
// this is a manual diagnostic tool, and PHP's own default fatal-error
// output (stack trace to stderr, non-zero exit) is exactly the right
// behaviour for that; nothing about failure handling itself is changing.
try {

$localAssetLookup = $pdo->prepare('
    SELECT id, hostname, ip_address, dns_name, os, tracking_method, last_scan_date, updated_at
    FROM assets WHERE qualys_host_id = :qhid
');
$localTagsLookup = $pdo->prepare('
    SELECT t.qualys_tag_id, t.name
    FROM asset_tags at JOIN tags t ON t.id = at.tag_id
    WHERE at.asset_id = :asset_id
    ORDER BY t.name
');

// Only prepared/used when --full is passed.
$assetUpsert = $pdo->prepare('
    INSERT INTO assets (qualys_host_id, hostname, ip_address, dns_name, os, tracking_method, last_scan_date)
    VALUES (:qualys_host_id, :hostname, :ip_address, :dns_name, :os, :tracking_method, :last_scan_date)
    ON DUPLICATE KEY UPDATE
        hostname = VALUES(hostname), ip_address = VALUES(ip_address), dns_name = VALUES(dns_name),
        os = VALUES(os), tracking_method = VALUES(tracking_method), last_scan_date = VALUES(last_scan_date)
');
// Tag resolution (including pending-tag promotion) goes through
// UserRepository::resolveSyncedTagId() so --full stays byte-for-byte
// identical to the normal cron sync - see that method for the order.
// Tags pass through TagScopeClassifier first, as in HostSyncWriter, or
// --full would put asset-group/IP-range tags straight back on agent hosts.
$tagScope = new TagScopeClassifier($pdo, fn(array $ids): array => $client->searchTagsByIds($ids));
$assetTagsDelete = $pdo->prepare('DELETE FROM asset_tags WHERE asset_id = :asset_id');
$assetTagInsert = $pdo->prepare('INSERT IGNORE INTO asset_tags (asset_id, tag_id) VALUES (:asset_id, :tag_id)');
$kbLookup = $pdo->prepare('SELECT title, severity_level, cvss_base, cvss3_base FROM knowledge_base WHERE qid = :qid');
$detectionUpsert = $pdo->prepare('
    INSERT INTO host_detections
        (asset_id, qid, status, port, protocol, is_ssl, first_found, last_found, last_fixed,
         times_found, effective_cvss_score, effective_cvss_source, is_ce_plus_fail, results)
    VALUES
        (:asset_id, :qid, :status, :port, :protocol, :is_ssl, :first_found, :last_found, :last_fixed,
         :times_found, :effective_cvss_score, :effective_cvss_source, :is_ce_plus_fail, :results)
    ON DUPLICATE KEY UPDATE
        status = VALUES(status), last_found = VALUES(last_found), last_fixed = VALUES(last_fixed),
        times_found = VALUES(times_found), effective_cvss_score = VALUES(effective_cvss_score),
        effective_cvss_source = VALUES(effective_cvss_source), is_ce_plus_fail = VALUES(is_ce_plus_fail),
        results = VALUES(results)
');
// Same reconciliation this script's docblock promises: --full uses the
// identical upsert (and now removal) logic as the normal cron job - see
// sync_host_detections.php's docblock for exactly why detections Qualys
// stops reporting for a host are deleted, not just marked Fixed.
$localDetectionsLookup = $pdo->prepare('SELECT id, qid, port_dedup_key FROM host_detections WHERE asset_id = :asset_id');

fwrite(STDOUT, "Pulling ALL hosts from Qualys (no incremental filter) - this may take a moment...\n");
if ($doFull) {
    fwrite(STDOUT, "--full given: also upserting locally (assets, tags, asset_tags, detections) as this runs.\n");
}
if ($pageSize !== null) {
    fwrite(STDOUT, "--page-size={$pageSize} given: forcing this truncation_limit to deliberately exercise the multi-page continuation loop.\n");
}
fwrite(STDOUT, "\n");

$hostCount = 0;
$matchedCount = 0;

foreach ($client->fetchHostDetections(null, $pageSize) as $host) {
    $hostCount++;
    $hostname = $host['hostname'] ?? $host['ip'] ?? "(no hostname/IP - Qualys host ID {$host['id']})";

    if ($hostFilter !== null
        && stripos($hostname, $hostFilter) === false
        && stripos((string)($host['ip'] ?? ''), $hostFilter) === false
    ) {
        continue;
    }
    $matchedCount++;

    fwrite(STDOUT, "=== {$hostname} (Qualys host ID {$host['id']}) ===\n");
    fwrite(STDOUT, "  Qualys says right now:\n");
    fwrite(STDOUT, "    hostname=\"" . ($host['hostname'] ?? '(none)') . "\"  ip=\"" . ($host['ip'] ?? '(none)') . "\"  dns=\"" . ($host['dns'] ?? '(none)') . "\"\n");
    fwrite(STDOUT, "    os=\"" . ($host['os'] ?? '(none)') . "\"  tracking_method=\"" . ($host['tracking_method'] ?? '(none)') . "\"  last_scan=" . ($host['last_scan_date'] ?? '(not reported)') . "\n");
    fwrite(STDOUT, "  Tags from Qualys API just now:\n");
    if (empty($host['tags'])) {
        fwrite(STDOUT, "    (none returned by the API for this host)\n");
    } else {
        foreach ($host['tags'] as $tag) {
            fwrite(STDOUT, "    - qualys_tag_id={$tag['qualys_tag_id']}  name=\"{$tag['name']}\"\n");
        }
    }

    $localAssetLookup->execute(['qhid' => $host['id']]);
    $localRow = $localAssetLookup->fetch();

    if ($localRow === false) {
        fwrite(STDOUT, "  Locally stored: NOT FOUND in the assets table.\n");
    } else {
        $localAssetId = (int)$localRow['id'];
        fwrite(STDOUT, "  Locally stored: assets.id = {$localAssetId}  (row last updated {$localRow['updated_at']})\n");
        fwrite(STDOUT, "    hostname=\"" . ($localRow['hostname'] ?? '(none)') . "\"  ip=\"" . ($localRow['ip_address'] ?? '(none)') . "\"  dns=\"" . ($localRow['dns_name'] ?? '(none)') . "\"\n");
        fwrite(STDOUT, "    os=\"" . ($localRow['os'] ?? '(none)') . "\"  tracking_method=\"" . ($localRow['tracking_method'] ?? '(none)') . "\"  last_scan=" . ($localRow['last_scan_date'] ?? '(none)') . "\n");

        // Flags exactly what's out of step between what Qualys just
        // returned and what's sitting in the assets table right now - see
        // this script's docblock for what each combination of "matches" /
        // "mismatch" means for where the problem actually is.
        $fieldMismatches = [];
        if ((string)($host['hostname'] ?? '') !== (string)($localRow['hostname'] ?? '')) {
            $fieldMismatches[] = 'hostname';
        }
        if ((string)($host['ip'] ?? '') !== (string)($localRow['ip_address'] ?? '')) {
            $fieldMismatches[] = 'ip';
        }
        if ((string)($host['dns'] ?? '') !== (string)($localRow['dns_name'] ?? '')) {
            $fieldMismatches[] = 'dns';
        }
        if (empty($fieldMismatches)) {
            fwrite(STDOUT, "    (hostname/ip/dns match what Qualys just returned)\n");
        } else {
            fwrite(STDOUT, "    *** MISMATCH on " . implode(', ', $fieldMismatches) . " - Qualys has different data than what's stored locally ***\n");
        }

        $localTagsLookup->execute(['asset_id' => $localAssetId]);
        $localTags = $localTagsLookup->fetchAll();
        if (empty($localTags)) {
            fwrite(STDOUT, "    Locally stored tags: (none in asset_tags)\n");
        } else {
            foreach ($localTags as $lt) {
                fwrite(STDOUT, "    Locally stored tag: qualys_tag_id={$lt['qualys_tag_id']}  name=\"{$lt['name']}\"\n");
            }
        }
    }

    fwrite(STDOUT, "  Detections in this API response: " . count($host['detections'] ?? []) . "\n");

    if ($doFull) {
        $assetUpsert->execute([
            'qualys_host_id'  => $host['id'],
            'hostname'        => $host['hostname'] ?? null,
            'ip_address'      => $host['ip'] ?? null,
            'dns_name'        => $host['dns'] ?? null,
            'os'              => $host['os'] ?? null,
            'tracking_method' => $host['tracking_method'] ?? null,
            'last_scan_date'  => $host['last_scan_date'] ?? null,
        ]);
        $localAssetLookup->execute(['qhid' => $host['id']]);
        $assetId = (int)$localAssetLookup->fetchColumn();

        $scopingTags = $tagScope->scopingTags($host['tags'] ?? []);
        $assetTagsDelete->execute(['asset_id' => $assetId]);
        foreach ($scopingTags as $tag) {
            $tagId = UserRepository::resolveSyncedTagId($pdo, $tag['qualys_tag_id'], $tag['name']);
            $assetTagInsert->execute(['asset_id' => $assetId, 'tag_id' => $tagId]);
        }

        $detectionsWritten = 0;
        foreach ($host['detections'] ?? [] as $detection) {
            $kbLookup->execute(['qid' => $detection['qid']]);
            $kb = $kbLookup->fetch();
            if (!$kb) {
                continue; // not in the local KB cache yet - same skip rule as the normal sync
            }
            $cvss = CvssCalculator::calculate(
                $kb['cvss3_base'] !== null ? (float)$kb['cvss3_base'] : null,
                $kb['cvss_base'] !== null ? (float)$kb['cvss_base'] : null,
                (int)$kb['severity_level'],
                (string)$kb['title']
            );
            $detectionUpsert->execute([
                'asset_id'              => $assetId,
                'qid'                   => $detection['qid'],
                'status'                => $detection['status'] ?? 'Active',
                'port'                  => $detection['port'] ?? null,
                'protocol'              => $detection['protocol'] ?? null,
                'is_ssl'                => !empty($detection['ssl']) ? 1 : 0,
                'first_found'           => $detection['first_found'] ?? null,
                'last_found'            => $detection['last_found'] ?? null,
                'last_fixed'            => $detection['last_fixed'] ?? null,
                'times_found'           => $detection['times_found'] ?? 1,
                'effective_cvss_score'  => $cvss['score'],
                'effective_cvss_source' => $cvss['source'],
                'is_ce_plus_fail'       => $cvss['is_ce_plus_fail'] ? 1 : 0,
                'results'               => $detection['results'] ?? null,
            ]);
            $detectionsWritten++;
        }

        // Same reconciliation as the normal cron job - see
        // sync_host_detections.php's docblock. Built from the full reported
        // list (including QIDs skipped above for a missing KB entry), so a
        // detection Qualys is still reporting is never wrongly removed just
        // because its KB row hasn't synced yet.
        $reportedKeys = [];
        foreach ($host['detections'] ?? [] as $detection) {
            $portDedupKey = $detection['port'] !== null ? (int)$detection['port'] : 4294967295;
            $reportedKeys["{$detection['qid']}:{$portDedupKey}"] = true;
        }
        $localDetectionsLookup->execute(['asset_id' => $assetId]);
        $idsToRemove = [];
        foreach ($localDetectionsLookup->fetchAll() as $row) {
            $key = "{$row['qid']}:{$row['port_dedup_key']}";
            if (!isset($reportedKeys[$key])) {
                $idsToRemove[] = (int)$row['id'];
            }
        }
        $detectionsRemoved = 0;
        if (!empty($idsToRemove)) {
            $placeholders = implode(',', array_fill(0, count($idsToRemove), '?'));
            $pdo->prepare("DELETE FROM host_detections WHERE id IN ($placeholders)")->execute($idsToRemove);
            $detectionsRemoved = count($idsToRemove);
        }

        fwrite(STDOUT, "  --full: upserted asset id={$assetId}, {$detectionsWritten} detection(s) written (others skipped - QID not yet in local knowledge_base), {$detectionsRemoved} removed (no longer reported by Qualys).\n");
    }

    fwrite(STDOUT, "\n");
}

if ($doFull) {
    // Same snapshot refresh the normal cron job does - see
    // VulnerabilityRepository::snapshotOpenCounts()'s docblock. Only makes
    // sense to run this when --full actually wrote data above; a plain
    // diagnostic (non---full) run doesn't touch the database at all, so
    // there'd be nothing new to snapshot.
    $snapshotCount = VulnerabilityRepository::snapshotOpenCounts();
    fwrite(STDOUT, "--full: refreshed today's vulnerability posture snapshot for {$snapshotCount} asset(s).\n");
}

fwrite(STDOUT, "Done - Qualys returned {$hostCount} host(s) total"
    . ($hostFilter !== null ? ", {$matchedCount} matching '{$hostFilter}'" : '') . ".\n");
if ($doFull) {
    fwrite(STDOUT, $tagScope->logLine());
}
fwrite(STDOUT, "Qualys API calls made this run: " . count($client->getCallLog()) . ($pageSize !== null ? " (forced truncation_limit={$pageSize} - more than 1 here confirms the continuation loop actually followed multiple pages, not just that it returned the right host count by coincidence)" : '') . "\n");

if ($hostFilter !== null && $matchedCount === 0) {
    fwrite(STDOUT, "\nNo host matched '{$hostFilter}' in the API response at all - see the docblock at the\n"
        . "top of this script for what that means (most likely a Qualys-side visibility/\n"
        . "permission issue with the API credentials in src/config/config.php).\n");
}
} finally {
    try {
        ApiCallLogRepository::recordCalls($client->getCallLog());
    } catch (\Throwable $logError) {
        fwrite(STDERR, 'Warning: failed to persist API call log: ' . $logError->getMessage() . "\n");
    }
}
