#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Read-only diagnostic: find the highest QID Qualys's KnowledgeBase
 * actually has right now, and compare it against the highest QID in the
 * local knowledge_base table.
 *
 * Why this exists: Qualys's KnowledgeBase Download API has no "give me the
 * max QID" call - no aggregate, no reliable descending-sort-and-limit-1,
 * and (confirmed the hard way elsewhere in this app) it silently truncates
 * large responses with no pagination signal, so you can't just pull "the
 * last record" either. The only QID-number levers the endpoint gives are
 * ids=, id_min= and id_max= (see QualysApiClient::fetchKnowledgeBaseByIdRange()).
 *
 * So this finds the ceiling by bisection instead. It binary-searches for
 * the largest threshold T for which a [T, ceiling] range query still
 * returns at least one QID: that boundary IS the max QID. It's the cheap
 * way to answer "where does the real data actually end" before deciding
 * how high to set reconcile_kb_by_id.php's --end (or its
 * qualys.kb_id_range_hard_ceiling default) - a full reconcile walk is
 * ~600 calls, this is ~log2(ceiling) calls, about 22 at the 3,000,000
 * default.
 *
 * Robust to that silent truncation, by design: the existence test only
 * needs *some* row back from a non-empty range (a truncated response is
 * still non-empty), and the reported max is taken from QIDs actually seen,
 * never guessed - so each successful probe's highest-seen QID is a real
 * QID and a valid lower bound. Standard binary search then drives the
 * probe threshold up until the window above it is genuinely empty; by that
 * point the window is tiny and well under any truncation limit, so the
 * highest QID it returns is the true maximum. Correctness doesn't depend
 * on the endpoint's truncation ordering (which Qualys doesn't document) -
 * worst case is a few extra calls, never a wrong answer.
 *
 * This NEVER writes anything - it's a pure read, on both sides (Qualys and
 * the local DB). It does make real Qualys API calls (~22 at defaults),
 * each costing one unit against your rate limit, so it's logged to
 * qualys_api_call_log like any other run.
 *
 * Reading the output:
 *   - Qualys max == local max: the local KB reaches all the way to the top
 *     of what Qualys currently has. Nothing is missing at the high end
 *     (this says nothing about gaps in the middle - that's what
 *     reconcile_kb_by_id.php is for).
 *   - Qualys max  > local max: Qualys has QID(s) above anything stored
 *     locally - a real high-end gap. reconcile_kb_by_id.php --fix (or
 *     diagnose_kb.php --qid=<n> --fix for a specific one) will pull them.
 *   - Qualys max  < local max: the local table holds a QID higher than
 *     anything Qualys returns now - expected and fine; the local DB
 *     intentionally retains historical/deprecated QIDs that Qualys has
 *     since dropped from its API (host_detections may still reference
 *     them - see the KnowledgeBase deprecation notes in the app's docs).
 *
 * Usage:
 *   php scripts/find_max_qid.php                 # bisect up to the hard ceiling (default 3,000,000)
 *   php scripts/find_max_qid.php --ceiling=5000000
 *                                                # search a higher range (costs ~1 extra call per doubling)
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;
use VulnDash\Lib\Database;
use VulnDash\Scripts\QualysApiClient;

$options = getopt('', ['ceiling::']);
$ceiling = isset($options['ceiling'])
    ? (int)$options['ceiling']
    : (int)(Config::get('qualys.kb_id_range_hard_ceiling') ?? 3_000_000);

if ($ceiling < 1) {
    fwrite(STDERR, "Ceiling must be a positive integer (got {$ceiling}).\n");
    exit(1);
}

$client = new QualysApiClient(
    (string)Config::get('qualys.api_base_url'),
    (string)Config::get('qualys.username'),
    (string)Config::get('qualys.password'),
    (string)(Config::get('qualys.api_version') ?? '4.0')
);

$pdo = Database::getConnection();

// Wrapped in try/finally purely so the API call log below still gets
// persisted if something throws partway through - same reasoning as
// scripts/diagnose_kb.php, no catch here on purpose for the same reason.
try {

fwrite(STDOUT, "Bisecting Qualys's KnowledgeBase for the highest QID (searching QIDs 1 to {$ceiling}).\n");
fwrite(STDOUT, "This is read-only and makes roughly " . (int)ceil(log($ceiling, 2)) . " API calls.\n\n");

/**
 * Standard binary search for the boundary: the largest threshold for which
 * a [threshold, ceiling] range still contains at least one QID. That
 * boundary equals the maximum QID. $bestSeen tracks the highest QID
 * actually returned by any probe, so the reported value is always a real
 * QID Qualys handed back, never an inferred one - see this file's docblock
 * for why that stays correct even though the endpoint truncates silently.
 */
$lo = 1;
$hi = $ceiling;
$bestSeen = null;

while ($lo <= $hi) {
    $mid = $lo + intdiv($hi - $lo, 2);

    $count = 0;
    $maxInWindow = null;
    foreach ($client->fetchKnowledgeBaseByIdRange($mid, $ceiling) as $vuln) {
        $count++;
        $qid = (int)$vuln['qid'];
        if ($maxInWindow === null || $qid > $maxInWindow) {
            $maxInWindow = $qid;
        }
    }

    if ($count > 0) {
        if ($bestSeen === null || $maxInWindow > $bestSeen) {
            $bestSeen = $maxInWindow;
        }
        fwrite(STDOUT, "  QIDs >= {$mid}: {$count} returned, highest seen = {$maxInWindow}\n");
        // At least one QID at or above $mid - the max is >= $mid, keep going up.
        $lo = $mid + 1;
    } else {
        fwrite(STDOUT, "  QIDs >= {$mid}: none returned\n");
        // Nothing at or above $mid - the max (if any) is below it.
        $hi = $mid - 1;
    }
}

fwrite(STDOUT, "\n");

// Local high-water mark for comparison. MAX() over an empty table is NULL,
// handled below.
$localMax = $pdo->query('SELECT MAX(qid) FROM knowledge_base')->fetchColumn();
$localMax = $localMax !== null && $localMax !== false ? (int)$localMax : null;

if ($bestSeen === null) {
    fwrite(STDOUT, "Qualys returned no QIDs at all in 1..{$ceiling}.\n");
    fwrite(STDOUT, "That's unexpected for a working KnowledgeBase - check API access/entitlement\n");
    fwrite(STDOUT, "(a 403 usually means the KnowledgeBase entitlement or the API user's rights) rather than trusting this as a real 'empty' result.\n");
} else {
    fwrite(STDOUT, "Highest QID on Qualys right now: {$bestSeen}\n");
}

fwrite(STDOUT, 'Highest QID in local knowledge_base: ' . ($localMax !== null ? (string)$localMax : 'table is empty') . "\n");

if ($bestSeen !== null && $localMax !== null) {
    if ($bestSeen > $localMax) {
        $gap = $bestSeen - $localMax;
        fwrite(STDOUT, "\n*** Qualys's top QID is {$gap} higher than the local top - there's at least one QID above anything stored locally. ***\n");
        fwrite(STDOUT, "    Run reconcile_kb_by_id.php (optionally --start near {$localMax}) to find and --fix the high-end gap.\n");
    } elseif ($bestSeen < $localMax) {
        fwrite(STDOUT, "\nLocal top QID is higher than Qualys's - expected: the local table retains historical/deprecated QIDs Qualys has dropped from its API.\n");
    } else {
        fwrite(STDOUT, "\nLocal and Qualys top QIDs match - nothing missing at the high end (says nothing about mid-range gaps; that's reconcile_kb_by_id.php's job).\n");
    }
}

fwrite(STDOUT, "\nQualys API calls made this run: " . count($client->getCallLog()) . "\n");

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
