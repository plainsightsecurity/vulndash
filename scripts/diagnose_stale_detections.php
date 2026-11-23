#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Answers one question and nothing else: for a vulnerability still showing on
 * the dashboard that you know was fixed days ago, is Qualys STILL REPORTING it,
 * or is this codebase FAILING TO REMOVE it?
 *
 * Those two causes look identical from the dashboard and have completely
 * different fixes, so this compares the two sides directly rather than
 * inferring from local data alone: it makes the same full, unfiltered Host
 * List Detection pull that scripts/reconcile_asset_inventory.php makes hourly,
 * and diffs exactly what Qualys returns against exactly what's in
 * host_detections right now.
 *
 * READ-ONLY. There is no --confirm and no write path of any kind - not to
 * host_detections, not to assets, not to sync_log. It costs one full Qualys
 * pull (the same call the hourly reconcile already makes), so it's cheap
 * against the API budget but not free.
 *
 * WHAT THE VERDICTS MEAN
 *
 *   "Qualys still reports it as open" - Qualys is the source. The detection
 *   came back in this pull with status New/Active/Re-Opened, so every sync is
 *   correctly keeping a row Qualys insists is live. Almost always this is the
 *   Cloud Agent not having re-assessed the host since the fix (check the
 *   host's last_scan_date in the output - if it predates the remediation,
 *   Qualys simply hasn't looked yet), or the fix not satisfying the QID's
 *   actual detection logic. Nothing in this codebase can or should remove it:
 *   deleting a finding Qualys still reports would be inventing data.
 *
 *   "Qualys reports it as Fixed" - also Qualys-side, but harmless: the row is
 *   stored with status='Fixed' and every read path already excludes those
 *   (VulnerabilityRepository::BASE_DETECTION_FILTER), so it is NOT what you're
 *   seeing on the dashboard. Listed only so the counts add up.
 *
 *   "STALE - Qualys did not return it" - this codebase is the source. Qualys
 *   returned this host in the pull but not this detection, so the reconcile
 *   step should have deleted it and written a remediation tombstone. A nonzero
 *   count here is a real bug worth reporting, not an operational quirk.
 *
 *   "STALE - host now has zero open detections" - this codebase is the
 *   source, and it's the subtle one. Qualys's Host List Detection endpoint
 *   never returns a host with nothing to report, so a host whose LAST finding
 *   was fixed drops out of the detection pull entirely while still appearing
 *   in the plain Host List pull. That kept the asset alive but meant its
 *   detections were never reconciled - they froze at whatever they were.
 *   Fixed 2026-07-23 by having the reconcile's zero-detection pass clear them;
 *   a nonzero count here means that fix hasn't been deployed or hasn't run
 *   yet, and the next --confirm run will clear it.
 *
 *   "host in neither pull" - the whole host is gone from Qualys, or has left
 *   the qualys.agent_scope_tag scope. The hourly reconcile deletes those
 *   assets outright, so this should be empty in steady state.
 *
 * Note the status filter question this also settles: fetchHostDetections()
 * sends no `status` parameter, so Qualys applies its own default. If the
 * "Fixed" line below is nonzero, that default includes Fixed on this
 * subscription; if it's always zero, it doesn't, and a remediated QID simply
 * vanishes from the pull instead.
 *
 * Usage:
 *   php scripts/diagnose_stale_detections.php                    # summary + every problem row
 *   php scripts/diagnose_stale_detections.php --qid=91234        # detail for one QID
 *   php scripts/diagnose_stale_detections.php --host=hostname    # detail for one host (substring match)
 *   php scripts/diagnose_stale_detections.php --all              # detail for every local detection
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\Config;
use VulnDash\Lib\Database;
use VulnDash\Scripts\QualysApiClient;

$options   = getopt('', ['qid::', 'host::', 'all']);
$filterQid = isset($options['qid']) ? (int)$options['qid'] : null;
$filterHost = isset($options['host']) ? (string)$options['host'] : null;
$showAll   = array_key_exists('all', $options);

$agentScopeTag = Config::get('qualys.agent_scope_tag') !== null ? (string)Config::get('qualys.agent_scope_tag') : null;
$excludedTags  = is_array(Config::get('qualys.excluded_tags')) ? Config::get('qualys.excluded_tags') : null;

$client = new QualysApiClient(
    (string)Config::get('qualys.api_base_url'),
    (string)Config::get('qualys.username'),
    (string)Config::get('qualys.password'),
    (string)(Config::get('qualys.api_version') ?? '4.0'),
    $agentScopeTag,
    $excludedTags
);

$pdo = Database::getConnection();

fwrite(STDOUT, "[READ-ONLY - this script never writes anything]\n");
if ($agentScopeTag !== null) {
    fwrite(STDOUT, "[scoped to Qualys tag \"{$agentScopeTag}\" - the same scope the hourly reconcile uses]\n");
}
fwrite(STDOUT, "Pulling every host from Qualys (full, unfiltered - the same two calls reconcile_asset_inventory.php makes)...\n");

// What Qualys says right now: host id => "qid:portdedupkey" => status.
$qualysDetections = [];
$qualysHosts = [];
foreach ($client->fetchHostDetections(null) as $host) {
    $hostId = (int)$host['id'];
    $qualysHosts[$hostId] = $host['hostname'] ?? ($host['ip'] ?? '(unnamed)');
    $qualysDetections[$hostId] = [];
    foreach ($host['detections'] ?? [] as $detection) {
        $portDedupKey = $detection['port'] !== null ? (int)$detection['port'] : 4294967295;
        $qualysDetections[$hostId]["{$detection['qid']}:{$portDedupKey}"] = (string)($detection['status'] ?? 'Active');
    }
}

// The plain Host List pull as well, and for the same reason reconcile makes
// it: a host with zero open detections is absent from the detection pull
// above but present here. Without this second call, "no detections returned"
// and "host gone from Qualys" are indistinguishable - which is exactly the
// confusion this script exists to remove.
$hostListIds = [];
foreach ($client->fetchHostList() as $host) {
    $hostListIds[(int)$host['id']] = true;
}

fwrite(STDOUT, sprintf(
    "Qualys returned %d host(s) with detections (%d detection(s) total), and %d host(s) from the plain host list.\n\n",
    count($qualysHosts),
    array_sum(array_map('count', $qualysDetections)),
    count($hostListIds)
));

// What we're storing right now. No status filter here on purpose - the point
// is to see everything, including the Fixed rows the dashboard already hides.
$sql = '
    SELECT hd.qid, hd.status, hd.detection_type, hd.port_dedup_key, hd.last_found, hd.updated_at,
           hd.effective_cvss_score, a.qualys_host_id, a.hostname, a.last_scan_date
    FROM host_detections hd
    JOIN assets a ON a.id = hd.asset_id
';
$conditions = [];
$params = [];
if ($filterQid !== null) {
    $conditions[] = 'hd.qid = :qid';
    $params['qid'] = $filterQid;
}
if ($filterHost !== null) {
    $conditions[] = 'a.hostname LIKE :hostname';
    $params['hostname'] = '%' . $filterHost . '%';
}
if ($conditions !== []) {
    $sql .= ' WHERE ' . implode(' AND ', $conditions);
}
$sql .= ' ORDER BY a.hostname, hd.qid';

$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$localRows = $stmt->fetchAll();

$counts = ['open' => 0, 'fixed' => 0, 'stale' => 0, 'zero_detection' => 0, 'no_host' => 0];
$problemLines = [];
$detailLines = [];

foreach ($localRows as $row) {
    $hostId = (int)$row['qualys_host_id'];
    $key = "{$row['qid']}:{$row['port_dedup_key']}";
    $shownOnDashboard = $row['status'] !== 'Fixed' && (float)$row['effective_cvss_score'] > 0.0;

    if (!array_key_exists($hostId, $qualysDetections)) {
        if (isset($hostListIds[$hostId])) {
            $verdict = 'STALE - host is live in Qualys with zero open detections, so this was fixed';
            $counts['zero_detection']++;
        } else {
            $verdict = 'host in neither pull - gone from Qualys, or out of the agent scope tag';
            $counts['no_host']++;
        }
        $isProblem = true;
    } elseif (!array_key_exists($key, $qualysDetections[$hostId])) {
        $verdict = 'STALE - Qualys did not return it (this codebase should have removed it)';
        $counts['stale']++;
        $isProblem = true;
    } elseif ($qualysDetections[$hostId][$key] === 'Fixed') {
        $verdict = 'Qualys reports it as Fixed (already hidden from the dashboard)';
        $counts['fixed']++;
        $isProblem = false;
    } else {
        $verdict = 'Qualys still reports it as open (status ' . $qualysDetections[$hostId][$key] . ')';
        $counts['open']++;
        $isProblem = false;
    }

    $line = sprintf(
        "  QID %-8s %-28s  local status=%-9s last_found=%-19s host last_scan=%-19s  on dashboard=%-3s  -> %s",
        $row['qid'],
        substr((string)($row['hostname'] ?? '(no hostname)'), 0, 28),
        $row['status'],
        (string)($row['last_found'] ?? '(none)'),
        (string)($row['last_scan_date'] ?? '(none)'),
        $shownOnDashboard ? 'YES' : 'no',
        $verdict
    );

    $detailLines[] = $line;
    if ($isProblem) {
        $problemLines[] = $line;
    }
}

// Anything Qualys returned that we have no row for. Usually a QID not yet in
// the local knowledge_base cache (both sync jobs deliberately skip those until
// sync_knowledge_base.php catches up), so this is informational, not a fault.
$missingLocally = 0;
$localKeys = [];
foreach ($localRows as $row) {
    $localKeys[(int)$row['qualys_host_id'] . '|' . $row['qid'] . ':' . $row['port_dedup_key']] = true;
}
if ($filterQid === null && $filterHost === null) {
    foreach ($qualysDetections as $hostId => $keys) {
        foreach ($keys as $key => $status) {
            if ($status !== 'Fixed' && !isset($localKeys[$hostId . '|' . $key])) {
                $missingLocally++;
            }
        }
    }
}

$show = $showAll ? $detailLines : $problemLines;
if ($show !== []) {
    fwrite(STDOUT, ($showAll ? "Every local detection:\n" : "Detections needing attention:\n"));
    foreach ($show as $line) {
        fwrite(STDOUT, $line . "\n");
    }
    fwrite(STDOUT, "\n");
} elseif (!$showAll) {
    fwrite(STDOUT, "No stale or orphaned local detections found.\n\n");
}

fwrite(STDOUT, "Summary of " . count($localRows) . " local detection(s):\n");
fwrite(STDOUT, sprintf("  %5d  Qualys still reports as open   -> Qualys-side: the agent has not cleared these yet\n", $counts['open']));
fwrite(STDOUT, sprintf("  %5d  Qualys reports as Fixed        -> stored, but already excluded from every dashboard view\n", $counts['fixed']));
fwrite(STDOUT, sprintf("  %5d  STALE, not returned by Qualys  -> codebase-side: these should have been deleted\n", $counts['stale']));
fwrite(STDOUT, sprintf("  %5d  STALE, host now has none open  -> codebase-side: last finding on the host was fixed\n", $counts['zero_detection']));
fwrite(STDOUT, sprintf("  %5d  host in neither pull           -> host is out of scope or gone from Qualys\n", $counts['no_host']));
if ($filterQid === null && $filterHost === null) {
    fwrite(STDOUT, sprintf("  %5d  open in Qualys but not stored locally (usually a QID not yet in the local knowledge_base)\n", $missingLocally));
}

fwrite(STDOUT, "\n");
if ($counts['stale'] > 0 || $counts['zero_detection'] > 0) {
    fwrite(STDOUT, "VERDICT: at least some of what you're seeing is this codebase failing to remove detections Qualys has stopped reporting. The rows listed above are the evidence.\n");
    if ($counts['zero_detection'] > 0) {
        fwrite(STDOUT, "         The \"host now has none open\" rows are hosts whose last finding was fixed. Deploy the 2026-07-23 reconcile fix if you haven't, then let one --confirm run clear them.\n");
    }
} elseif ($counts['open'] > 0) {
    fwrite(STDOUT, "VERDICT: nothing stale locally. Every detection on the dashboard came back in this pull, so Qualys is still reporting them as open - compare each host's last_scan_date above against when you applied the fix.\n");
} else {
    fwrite(STDOUT, "VERDICT: nothing stale and nothing open - the local picture matches Qualys exactly.\n");
}

exit(0);
