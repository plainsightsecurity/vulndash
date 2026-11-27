#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Optional one-off: fills knowledge_base.patch_published_date for the QIDs
 * that matter now - patchable QIDs on open detections - instead of waiting
 * for the normal KB sync to pick each one up the next time Qualys modifies
 * it. Until a QID has its patch date, the CE+ patch clock silently counts
 * from its published date (src/Lib/CePlusDeadline.php), so skipping this is
 * safe; it only makes the clock right sooner.
 *
 * Budget-safe by design (KnowledgeBase calls are scarce - 25 per version
 * per 24h on this subscription):
 *
 *   - DRY RUN BY DEFAULT. Without --confirm it makes no API calls and writes
 *     nothing; it only says how many QIDs need a date and how many calls
 *     that would take.
 *   - One call per --batch-size QIDs (default 100, ids= filter), and at most
 *     --max-calls calls per run (default 5). Re-run to continue: each run
 *     only selects QIDs still missing a date, so nothing is fetched twice.
 *   - --api-version picks which version's budget to spend (each has its own
 *     counter), e.g. one the routine sync doesn't use.
 *   - QualysApiClient's call reserve (qualys.min_calls_reserve) still
 *     applies, so this can't drain the last calls on a version. A refusal
 *     stops the run cleanly; batches already done are kept.
 *   - A QID Qualys returns without a patch date (or doesn't return at all)
 *     is remembered in sync_state ('patch_date_backfill_no_date') and not
 *     asked for again by later runs. The normal KB sync still updates it
 *     whenever Qualys changes it.
 *
 * Each returned QID is written with the same full upsert as
 * sync_knowledge_base.php, so the whole KB row is refreshed - including
 * patchable, which takes a QID out of the clock if Qualys now says no patch.
 * Shares the KB sync's lock file, so the two never run at the same time.
 *
 * Run the migration first (database/migrations/2026-11-add-patch-published-date.sql).
 *
 * Usage:
 *   php scripts/backfill_patch_published_date.php                         # dry run: counts only, no calls
 *   php scripts/backfill_patch_published_date.php --confirm               # fetch, up to 5 calls
 *   php scripts/backfill_patch_published_date.php --confirm --api-version=5.0 --max-calls=3
 *   php scripts/backfill_patch_published_date.php --confirm --batch-size=50
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;
use VulnDash\Lib\Database;
use VulnDash\Scripts\QualysApiClient;

const DEFAULT_BATCH_SIZE = 100;
const MAX_BATCH_SIZE = 500;
const DEFAULT_MAX_CALLS = 5;
const NO_DATE_STATE_KEY = 'patch_date_backfill_no_date';

$usage = "Usage: php scripts/backfill_patch_published_date.php [--confirm] [--api-version=<e.g. 5.0>] [--batch-size=<1-" . MAX_BATCH_SIZE . ">] [--max-calls=<n>]\n";

$options = getopt('', ['confirm', 'api-version:', 'batch-size:', 'max-calls:', 'help']);
if (isset($options['help'])) {
    fwrite(STDOUT, $usage);
    exit(0);
}
$confirm = array_key_exists('confirm', $options);

// Checked strictly because it becomes part of the request path (/api/<v>/).
$apiVersion = isset($options['api-version'])
    ? trim((string)$options['api-version'])
    : (string)(Config::get('qualys.api_version') ?? '4.0');
if (preg_match('/^\d+\.\d+$/', $apiVersion) !== 1) {
    fwrite(STDERR, "--api-version must look like 4.0 or 5.0 (got " . var_export($apiVersion, true) . ").\n" . $usage);
    exit(1);
}

$batchSize = isset($options['batch-size']) ? (int)$options['batch-size'] : DEFAULT_BATCH_SIZE;
if ($batchSize < 1 || $batchSize > MAX_BATCH_SIZE || (isset($options['batch-size']) && !ctype_digit(trim((string)$options['batch-size'])))) {
    fwrite(STDERR, "--batch-size must be a whole number from 1 to " . MAX_BATCH_SIZE . ".\n" . $usage);
    exit(1);
}

$maxCalls = isset($options['max-calls']) ? (int)$options['max-calls'] : DEFAULT_MAX_CALLS;
if ($maxCalls < 1 || (isset($options['max-calls']) && !ctype_digit(trim((string)$options['max-calls'])))) {
    fwrite(STDERR, "--max-calls must be a whole number of at least 1.\n" . $usage);
    exit(1);
}

$pdo = Database::getConnection();

$colExists = (int)$pdo->query("
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'knowledge_base' AND COLUMN_NAME = 'patch_published_date'
")->fetchColumn() === 1;
if (!$colExists) {
    fwrite(STDERR, "knowledge_base.patch_published_date doesn't exist yet - run database/migrations/2026-11-add-patch-published-date.sql first.\n");
    exit(1);
}

// QIDs earlier runs asked for and got no date back - not asked for again.
$noDateStmt = $pdo->prepare('SELECT state_json FROM sync_state WHERE sync_type = :type');
$noDateStmt->execute(['type' => NO_DATE_STATE_KEY]);
$noDateState = json_decode((string)$noDateStmt->fetchColumn(), true);
$noDateQids = [];
foreach ((is_array($noDateState) && is_array($noDateState['qids'] ?? null) ? $noDateState['qids'] : []) as $q) {
    $noDateQids[(int)$q] = true;
}

// Same "open" definition the dashboard uses (VulnerabilityRepository::BASE_DETECTION_FILTER).
// Ordered by most detections first, so a run capped by --max-calls fixes
// the clocks people see most.
$candidateRows = $pdo->query("
    SELECT hd.qid, COUNT(*) AS detections, MAX(hd.is_ce_plus_fail) AS any_ce_fail
    FROM host_detections hd
    JOIN knowledge_base kb ON kb.qid = hd.qid
    WHERE hd.status != 'Fixed' AND hd.effective_cvss_score > 0.0
      AND kb.patchable = 1 AND kb.patch_published_date IS NULL
    GROUP BY hd.qid
    ORDER BY any_ce_fail DESC, detections DESC, hd.qid
")->fetchAll();

$candidates = [];
$skippedKnown = 0;
foreach ($candidateRows as $r) {
    $qid = (int)$r['qid'];
    if (isset($noDateQids[$qid])) {
        $skippedKnown++;
        continue;
    }
    $candidates[] = $qid;
}

$batches = array_chunk($candidates, $batchSize);
$callsNeeded = count($batches);
$callsThisRun = min($callsNeeded, $maxCalls);

fwrite(STDOUT, "Patchable QIDs on open detections without a patch date: " . count($candidates) . "\n");
if ($skippedKnown > 0) {
    fwrite(STDOUT, "  (plus {$skippedKnown} already checked by an earlier run with no date from Qualys - not asked for again)\n");
}
fwrite(STDOUT, "KnowledgeBase calls needed at --batch-size={$batchSize}: {$callsNeeded}\n");
if ($callsNeeded === 0) {
    fwrite(STDOUT, "Nothing to do.\n");
    exit(0);
}
fwrite(STDOUT, "This run would make up to {$callsThisRun} call(s) on /api/{$apiVersion}/ (--max-calls={$maxCalls})"
    . ($callsNeeded > $callsThisRun ? '; re-run afterwards to continue with the rest' : '') . ".\n");

if (!$confirm) {
    fwrite(STDOUT, "\nDry run - no API calls made, nothing written. Add --confirm to fetch.\n");
    exit(0);
}

// Same lock as sync_knowledge_base.php: both write knowledge_base and spend
// the same KB budget, so they must not overlap.
$lockPath = sys_get_temp_dir() . '/vulndash_kb_sync.lock';
$lockHandle = \VulnDash\Lib\LockFile::open($lockPath);
if ($lockHandle === false) {
    fwrite(STDERR, "Could not open lock file {$lockPath} - check its ownership/permissions.\n");
    exit(1);
}
@chmod($lockPath, 0666);
if (!flock($lockHandle, LOCK_EX | LOCK_NB)) {
    fwrite(STDOUT, "A knowledge base sync is running right now - try again when it finishes.\n");
    fclose($lockHandle);
    exit(0);
}

$client = new QualysApiClient(
    (string)Config::get('qualys.api_base_url'),
    (string)Config::get('qualys.username'),
    (string)Config::get('qualys.password'),
    $apiVersion
);

// Must list every key QualysApiClient::parseKnowledgeBaseFile() yields -
// identical to sync_knowledge_base.php's upsert.
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

$saveNoDate = function () use ($pdo, &$noDateQids): void {
    $qids = array_keys($noDateQids);
    sort($qids);
    $pdo->prepare('
        INSERT INTO sync_state (sync_type, state_json) VALUES (:type, :state)
        ON DUPLICATE KEY UPDATE state_json = VALUES(state_json)
    ')->execute(['type' => NO_DATE_STATE_KEY, 'state' => json_encode(['qids' => $qids])]);
};

$filled = 0;
$nowUnpatchable = 0;
$noDateThisRun = 0;
$notReturned = 0;
$batchesDone = 0;

// Set rather than exit()ing inside the catch: exit() skips the finally below,
// which would drop the API call log and leave the lock held.
$exitCode = 0;

try {
    foreach (array_slice($batches, 0, $callsThisRun) as $i => $batch) {
        fwrite(STDOUT, sprintf("Call %d/%d: %d QID(s) (%d-%d)\n", $i + 1, $callsThisRun, count($batch), min($batch), max($batch)));

        // Buffered per batch (at most --batch-size rows), and written in one
        // transaction only once the whole response has parsed, so a call cut
        // off partway leaves that batch untouched for the next run.
        $returned = [];
        foreach ($client->fetchKnowledgeBaseByIds($batch) as $vuln) {
            $returned[(int)$vuln['qid']] = $vuln;
        }

        $pdo->beginTransaction();
        try {
            foreach ($batch as $qid) {
                if (!isset($returned[$qid])) {
                    $notReturned++;
                    $noDateQids[$qid] = true;
                    continue;
                }
                $vuln = $returned[$qid];
                $upsert->execute($vuln);
                if ($vuln['patch_published_date'] !== null) {
                    $filled++;
                } elseif ((int)$vuln['patchable'] === 0) {
                    // Now out of the candidate set by itself - no need to remember.
                    $nowUnpatchable++;
                } else {
                    $noDateThisRun++;
                    $noDateQids[$qid] = true;
                }
            }
            $saveNoDate();
            $pdo->commit();
        } catch (\Throwable $e) {
            $pdo->rollBack();
            throw $e;
        }
        $batchesDone++;
    }
} catch (\RuntimeException $e) {
    // Budget/reserve refusals, auth failures and Qualys error bodies all
    // arrive as RuntimeException with a readable message.
    fwrite(STDERR, "Stopped: {$e->getMessage()}\n");
    if (!isset($options['api-version'])) {
        fwrite(STDERR, "Another API version has its own KnowledgeBase budget - e.g. add --api-version=5.0\n");
    }
    $exitCode = 1;
} finally {
    try {
        ApiCallLogRepository::recordCalls($client->getCallLog());
    } catch (\Throwable $logError) {
        fwrite(STDERR, 'Warning: failed to persist API call log: ' . $logError->getMessage() . "\n");
    }
    flock($lockHandle, LOCK_UN);
    fclose($lockHandle);
}

$remaining = count($candidates) - array_sum(array_map('count', array_slice($batches, 0, $batchesDone)));
fwrite(STDOUT, "\nBatches completed: {$batchesDone}\n");
fwrite(STDOUT, "  patch date filled: {$filled}\n");
fwrite(STDOUT, "  Qualys now says not patchable (clock removed): {$nowUnpatchable}\n");
fwrite(STDOUT, "  patchable but no patch date from Qualys (published date stays the clock start): {$noDateThisRun}\n");
fwrite(STDOUT, "  not returned by Qualys: {$notReturned}\n");
fwrite(STDOUT, "QIDs still to do: {$remaining}" . ($remaining > 0 ? ' - re-run to continue' : '') . "\n");
fwrite(STDOUT, 'Qualys API calls made this run: ' . count($client->getCallLog()) . "\n");
$rateInfo = $client->getLastRateLimitInfo();
if ($rateInfo !== null && $rateInfo['remaining'] !== null) {
    fwrite(STDOUT, "Qualys API calls remaining on /api/{$apiVersion}/: {$rateInfo['remaining']}" . ($rateInfo['limit'] !== null ? "/{$rateInfo['limit']}" : '') . "\n");
}

exit($exitCode);
