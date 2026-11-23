#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Walks the ENTIRE Qualys KnowledgeBase by QID number, in fixed-width
 * numeric batches (id_min/id_max - real, documented parameters for this
 * endpoint, distinct from the ids= discrete-list filter
 * diagnose_kb.php/fetchKnowledgeBaseByIds() use), cross-referencing every
 * QID Qualys returns against the local knowledge_base table.
 *
 * Added 2026-07 as a check that's completely independent of every
 * date-based sweep this app otherwise relies on
 * (sync_knowledge_base.php's last_modified_after/published_after
 * chunking, and every --rescan-since/--rescan-until run). That
 * independence is the whole point: a QID with a null, malformed, or
 * otherwise-odd date field - or one that fell through some date-filter
 * edge case none of this year's incidents happened to expose - would be
 * invisible to every check built so far, no matter how thoroughly that
 * date-based machinery gets verified. This sidesteps dates entirely and
 * asks Qualys directly "what QIDs exist in this number range", which
 * either confirms nothing's missing or finds exactly what still is.
 *
 * Uses the same defence as sync_knowledge_base.php's safety net, just on
 * numbers instead of time: each batch is treated as possibly incomplete
 * if it returns qualys.kb_max_records_per_window records or more, and
 * gets split in half and re-verified rather than trusted - because QID
 * assignment isn't dense (most numbers in any given range won't
 * correspond to a real QID at all), a batch that returns far more
 * records than its neighbours is exactly the same kind of signal a dense
 * date-window burst was.
 *
 * This is a one-off audit, not a recurring sync - it doesn't persist a
 * cursor or touch sync_state/sync_log. If it gets interrupted, use
 * --start to resume from roughly where it left off (the last "ID range:"
 * line printed) rather than needing to walk the whole space again -
 * upserts are idempotent either way, so restarting from further back
 * than necessary is wasteful, not harmful.
 *
 * Read-only by default; --fix upserts anything found on Qualys but
 * missing locally, using the same upsert sync_knowledge_base.php itself
 * uses.
 *
 * Round-robins across API versions (qualys.kb_api_versions, same config
 * key and same reasoning as sync_knowledge_base.php - see that file's
 * docblock) for the same reason it's worth doing here too: this script's
 * own walk is comfortably the most API-call-hungry thing in this app (a
 * full run at default settings is roughly (--end / kb_id_range_batch_width)
 * calls - about 600 at the 3,000,000 default, more with a higher --end),
 * so spreading it across each version's own independent hourly counter
 * matters more here than almost anywhere else in this codebase. Same
 * fallback behaviour too: a call on the round-robin-picked version that
 * fails before returning anything retries once on the primary version
 * before actually giving up, so one version having a bad day (or being
 * retired outright, as already happened once to this subscription's
 * access on a different endpoint) degrades to "this run used the primary
 * client a bit more", not a failed walk.
 *
 * This walks all the way to --end (default a generous 3,000,000 ceiling)
 * by default - it does NOT stop early just because it's seen a long
 * stretch of empty batches. That was this script's first design, until
 * testing it against a deliberately gap-heavy synthetic dataset showed
 * exactly the failure mode it was risking for real: a real QID sitting
 * beyond a wide-but-legitimate empty stretch (there's no way to rule out
 * Qualys having gaps of this kind between different eras/categories of
 * QID assignment) would have been silently missed, which is precisely
 * the class of problem this whole script exists to catch - an
 * optimization that trades away the one guarantee that was the entire
 * point isn't a good trade. Pass --stop-after-empty=N to opt into
 * early-stopping anyway (e.g. for a quick repeat check after a first full
 * walk has already confirmed where the real data ends) - off by default.
 *
 * Usage:
 *   php scripts/reconcile_kb_by_id.php               # report only, QID 1 through the hard ceiling (--end)
 *   php scripts/reconcile_kb_by_id.php --fix         # also upsert anything found missing
 *   php scripts/reconcile_kb_by_id.php --start=500000 --fix
 *                                                     # resume from a specific QID instead of 1
 *   php scripts/reconcile_kb_by_id.php --end=2000000  # override the hard ceiling (default 3,000,000)
 *   php scripts/reconcile_kb_by_id.php --stop-after-empty=200
 *                                                     # opt-in speed optimization: stop once 200
 *                                                     # consecutive batches (200 * kb_id_range_batch_width
 *                                                     # numbers wide) come back empty, rather than walking
 *                                                     # all the way to --end regardless. Only use this once
 *                                                     # you're confident there's nothing real beyond that
 *                                                     # stretch - e.g. a repeat run after a first full walk
 *                                                     # (the default, no flag needed) has already mapped out
 *                                                     # where the real data actually ends.
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;
use VulnDash\Lib\Database;
use VulnDash\Scripts\QualysApiClient;

$options = getopt('', ['fix', 'start::', 'end::', 'stop-after-empty::']);
$doFix = array_key_exists('fix', $options);
$startId = isset($options['start']) ? max(1, (int)$options['start']) : 1;
$endId = isset($options['end']) ? (int)$options['end'] : (int)(Config::get('qualys.kb_id_range_hard_ceiling') ?? 3_000_000);
// null (the default) means "never stop early" - see this file's own
// docblock above for why that's the safe default, not an oversight.
$stopAfterEmpty = isset($options['stop-after-empty']) ? (int)$options['stop-after-empty'] : null;

$clientPool = [];
$apiVersions = Config::get('qualys.kb_api_versions') ?? ['2.0', '3.0', '4.0'];
$primaryVersion = (string)(Config::get('qualys.api_version') ?? '4.0');

foreach ($apiVersions as $version) {
    $clientPool[$version] = new QualysApiClient(
        (string)Config::get('qualys.api_base_url'),
        (string)Config::get('qualys.username'),
        (string)Config::get('qualys.password'),
        (string)$version
    );
}
// The one version everything falls back to on failure - see the
// round-robin note in this file's own docblock above.
$client = $clientPool[$primaryVersion] ?? reset($clientPool);

$rrIndex = 0;
/**
 * Picks the next client in the pool, round-robin, cycling through every
 * configured API version in turn - same mechanism as
 * sync_knowledge_base.php's own $pickClient.
 */
$pickClient = function () use (&$rrIndex, $clientPool): QualysApiClient {
    $versions = array_keys($clientPool);
    $picked = $clientPool[$versions[$rrIndex % count($versions)]];
    $rrIndex++;
    return $picked;
};

$pdo = Database::getConnection();

try {

// Must list every key QualysApiClient::parseKnowledgeBaseFile() yields -
// see its docblock.
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

$maxRecordsPerWindow = (int)(Config::get('qualys.kb_max_records_per_window') ?? 1000);
$batchWidth = (int)(Config::get('qualys.kb_id_range_batch_width') ?? 5000);

$gapsFound = [];
$totalGqidsSeen = 0;

/**
 * Fetches one [idMin, idMax] batch from a specific client, applying the
 * same early-exit-past-threshold logic this script has always used (read
 * only up to $maxRecordsPerWindow rows before giving up on this batch as
 * a whole, to bound memory/parse cost the same way
 * sync_knowledge_base.php's own safety net does).
 *
 * @return array{0: array<int, array<string, mixed>>, 1: bool} [rows, exceeded]
 */
$fetchBatch = function (QualysApiClient $c, int $idMin, int $idMax) use ($maxRecordsPerWindow): array {
    $rows = [];
    $count = 0;
    $exceeded = false;
    foreach ($c->fetchKnowledgeBaseByIdRange($idMin, $idMax) as $vuln) {
        $count++;
        if ($count >= $maxRecordsPerWindow) {
            $exceeded = true;
            break;
        }
        $rows[] = $vuln;
    }
    return [$rows, $exceeded];
};

/**
 * Same shape as sync_knowledge_base.php's syncWindowWithSafetyNet(), just
 * bisecting a numeric [idMin, idMax] range instead of a time window -
 * see this file's own docblock for why. Cross-references every QID
 * Qualys returns against the local table in one bulk query per resolved
 * (non-bisected) batch, rather than one query per QID.
 *
 * Round-robins which API version fetches each batch (see $pickClient),
 * falling back to the primary version once if the picked one fails -
 * safe to retry whole because, unlike sync_knowledge_base.php's
 * streaming windows, $fetchBatch fully buffers a batch in memory before
 * returning anything, so a failure partway through never leaves a
 * partially-upserted batch behind to risk duplicating.
 *
 * @return int total QIDs Qualys actually has in this range
 */
$processIdRange = function (int $idMin, int $idMax, int $depth = 0) use (
    &$processIdRange, $pickClient, $client, $fetchBatch, $pdo, $upsert, $maxRecordsPerWindow, $doFix, &$gapsFound
): int {
    $indent = str_repeat('  ', $depth);
    fwrite(STDOUT, "{$indent}ID range: {$idMin}-{$idMax}\n");

    $picked = $pickClient();
    try {
        [$rows, $exceeded] = $fetchBatch($picked, $idMin, $idMax);
    } catch (\Throwable $e) {
        if ($picked === $client) {
            throw $e;
        }
        fwrite(STDOUT, "{$indent}  (a call on this range's assigned API version failed - {$e->getMessage()} - retrying this same range on the primary version instead)\n");
        [$rows, $exceeded] = $fetchBatch($client, $idMin, $idMax);
    }

    if ($exceeded) {
        if ($idMax <= $idMin) {
            // A single QID number cannot correspond to more than one KB
            // entry - QID is documented as the KnowledgeBase's unique
            // key - so hitting the threshold here would mean something
            // is genuinely wrong (not just "dense"), worth stopping for
            // rather than guessing past.
            throw new \RuntimeException(
                "QID {$idMin} alone appears to return {$maxRecordsPerWindow}+ records, which should be " .
                "impossible (QID is meant to be a unique key) - stopping rather than guessing what's going on."
            );
        }
        $mid = $idMin + intdiv($idMax - $idMin, 2);
        fwrite(STDOUT, "{$indent}  {$maxRecordsPerWindow}+ found - not trusting this as complete, splitting and re-verifying both halves.\n");
        $left = $processIdRange($idMin, $mid, $depth + 1);
        $right = $processIdRange($mid + 1, $idMax, $depth + 1);
        return $left + $right;
    }

    if (empty($rows)) {
        fwrite(STDOUT, "{$indent}  -> 0 record(s)\n");
        return 0;
    }
    fwrite(STDOUT, "{$indent}  -> " . count($rows) . " record(s)\n");

    $qids = array_map(static fn($v) => (int)$v['qid'], $rows);
    $placeholders = implode(',', array_fill(0, count($qids), '?'));
    $stmt = $pdo->prepare("SELECT qid FROM knowledge_base WHERE qid IN ({$placeholders})");
    $stmt->execute($qids);
    $existing = array_flip(array_map('intval', $stmt->fetchAll(\PDO::FETCH_COLUMN)));

    foreach ($rows as $vuln) {
        if (!isset($existing[(int)$vuln['qid']])) {
            $gapsFound[] = (int)$vuln['qid'];
            fwrite(STDOUT, "{$indent}  *** GAP: QID {$vuln['qid']} (\"{$vuln['title']}\") is on Qualys but missing locally ***\n");
            if ($doFix) {
                $upsert->execute($vuln);
                fwrite(STDOUT, "{$indent}    --fix: upserted.\n");
            }
        }
    }

    return count($rows);
};

fwrite(STDOUT, "Walking QIDs {$startId} to {$endId} (batch width {$batchWidth}" . ($stopAfterEmpty !== null ? ", stopping early after {$stopAfterEmpty} consecutive empty batches" : ', walking the full range - no early stop') . ")" . ($doFix ? " - --fix given, will upsert any gap found" : ' - report only, pass --fix to also upsert') . "\n\n");

$idMin = $startId;
$consecutiveEmpty = 0;
$lastCheckedId = $startId - 1;

while ($idMin <= $endId && ($stopAfterEmpty === null || $consecutiveEmpty < $stopAfterEmpty)) {
    $idMax = min($idMin + $batchWidth - 1, $endId);
    $seen = $processIdRange($idMin, $idMax);
    $totalGqidsSeen += $seen;
    $consecutiveEmpty = $seen === 0 ? $consecutiveEmpty + 1 : 0;
    $lastCheckedId = $idMax;
    $idMin = $idMax + 1;
}

$stoppedReason = ($stopAfterEmpty !== null && $consecutiveEmpty >= $stopAfterEmpty)
    ? "{$stopAfterEmpty} consecutive empty batches (--stop-after-empty was given - this is an opt-in optimization, not a guarantee nothing real lies beyond this point)"
    : "reached the end of the walked range ({$endId})";

fwrite(STDOUT, "\nStopped: {$stoppedReason}. Last ID range checked ended at {$lastCheckedId}.\n");
fwrite(STDOUT, "Total QIDs seen from Qualys across this walk: {$totalGqidsSeen}\n");
fwrite(STDOUT, "Gaps found: " . count($gapsFound) . ($doFix ? ' (all upserted)' : (count($gapsFound) > 0 ? ' - re-run with --fix to upsert these' : '')) . "\n");
if (!empty($gapsFound)) {
    fwrite(STDOUT, '  QIDs: ' . implode(', ', $gapsFound) . "\n");
}

foreach ($clientPool as $version => $c) {
    $rateInfo = $c->getLastRateLimitInfo();
    if ($rateInfo !== null && $rateInfo['remaining'] !== null) {
        fwrite(STDOUT, "Qualys API calls remaining on /api/{$version}/: {$rateInfo['remaining']}" . ($rateInfo['limit'] !== null ? "/{$rateInfo['limit']}" : '') . ($rateInfo['window_sec'] !== null ? " (per {$rateInfo['window_sec']}s window)" : '') . "\n");
    }
}
$totalCallsThisRun = array_sum(array_map(fn($c) => count($c->getCallLog()), $clientPool));
fwrite(STDOUT, "Qualys API calls made this run (all versions combined): {$totalCallsThisRun}\n");
} finally {
    if (!empty($clientPool)) {
        try {
            $allCalls = array_merge(...array_values(array_map(fn($c) => $c->getCallLog(), $clientPool)));
            ApiCallLogRepository::recordCalls($allCalls);
        } catch (\Throwable $logError) {
            fwrite(STDERR, 'Warning: failed to persist API call log: ' . $logError->getMessage() . "\n");
        }
    }
}
