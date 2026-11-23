#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * One-off, read-only check: does the KnowledgeBase endpoint apply
 * id_min/id_max and last_modified_after/before TOGETHER in one call?
 *
 * Why it matters (2026-11): a Qualys bulk update stamped 1900+ QIDs with
 * the same second, more than once. sync_knowledge_base.php can't split a
 * window below one second by time, so it keeps only the first
 * qualys.kb_max_records_per_window - 1 records of such a second and flags
 * it as unverified. The obvious way to finish those seconds is to split
 * them by QID range instead - but only if Qualys honours both filters at
 * once. If it silently ignored one, splitting by QID would either never
 * shrink the response (id range ignored) or pull in unrelated QIDs (date
 * ignored). Neither combination is covered by Qualys's docs for this
 * endpoint, so this checks it directly before anything is built on it.
 *
 * What it does:
 *   1. Finds the densest seconds in the LOCAL knowledge_base (by
 *      qualys_last_modified) - no API call - and picks one, or uses
 *      --second.
 *   2. Sends ONE call: that second as the last_modified window (the same
 *      shape the sync's 1-second leaf uses), plus an id range starting a
 *      few dozen QIDs below the highest QID we hold for that second and
 *      running well past it. Response order isn't documented, but if it
 *      follows QID order, any records the sync never got to are above
 *      that highest QID, so this range should also show whether any exist.
 *   3. Checks every returned record against both filters and says plainly
 *      whether the combination is usable.
 *
 * The call goes through the real QualysApiClient request path, so it is
 * logged to qualys_api_call_log and subject to the call reserve like any
 * other call. The client has no public method taking both filters, and
 * changing that shared class before knowing the answer is the wrong order,
 * so this reaches its private request/parse methods via reflection. That
 * is acceptable in a disposable check like this one, and not a pattern
 * for production code. If the combination works, the sync fix will add a
 * proper method.
 *
 * Every KB version is held at the reserve until calls free up, so to run
 * it before then, spend one reserve call deliberately:
 *   VULNDASH_IGNORE_CALL_RESERVE=1 php scripts/check_kb_id_date_combo.php --api-version=3.0
 *
 * Usage:
 *   php scripts/check_kb_id_date_combo.php [--api-version=X.Y] [--second=YYYY-MM-DDTHH:MM:SSZ] [--known=30] [--local-only]
 *     --api-version  which version's budget to spend (default: qualys.api_version)
 *     --second       the dense second to test (UTC); default: the densest local one
 *     --known        how many locally-held QIDs from that second the range includes (default 30)
 *     --local-only   show the local dense seconds and the query it would send, without calling Qualys
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;
use VulnDash\Lib\Database;
use VulnDash\Scripts\QualysApiClient;

$options = getopt('', ['api-version::', 'second::', 'known::', 'local-only']);
$apiVersion = isset($options['api-version']) && $options['api-version'] !== false && $options['api-version'] !== ''
    ? (string)$options['api-version']
    : (string)(Config::get('qualys.api_version') ?? '4.0');
$knownWanted = isset($options['known']) ? max(1, (int)$options['known']) : 30;
$localOnly = array_key_exists('local-only', $options);

$pdo = Database::getConnection();
$threshold = (int)(Config::get('qualys.kb_max_records_per_window') ?? 100);

// qualys_last_modified is stored as UTC (QualysApiClient::toMysqlDatetime()
// uses gmdate), so it is compared and printed as UTC throughout - not
// through the connection's Europe/London session zone.
$utc = new DateTimeZone('UTC');

// A capped 1-second leaf keeps threshold - 1 records, so a second holding
// at least that many locally is one the sync could not finish.
$denseFloor = max(1, $threshold - 1);
$denseStmt = $pdo->prepare('
    SELECT qualys_last_modified AS sec, COUNT(*) AS n
    FROM knowledge_base
    WHERE qualys_last_modified >= :since
    GROUP BY qualys_last_modified
    HAVING COUNT(*) >= :floor
    ORDER BY n DESC, sec DESC
    LIMIT 10
');
$denseStmt->execute([
    'since' => gmdate('Y-m-d H:i:s', time() - 30 * 86400),
    'floor' => $denseFloor,
]);
$denseRows = $denseStmt->fetchAll();

fwrite(STDOUT, "Local seconds (last 30 days) holding >= {$denseFloor} QIDs - i.e. ones the sync had to cap:\n");
if ($denseRows === []) {
    // Would mean the stored LAST_SERVICE_MODIFICATION_DATETIME isn't the
    // timestamp the last_modified filter matched on - itself worth knowing.
    fwrite(STDOUT, "  none - if the sync log shows UNVERIFIED COMPLETENESS seconds, the stored timestamps don't match them; paste this output.\n");
}
foreach ($denseRows as $row) {
    fwrite(STDOUT, "  {$row['sec']} UTC  {$row['n']} QID(s) held locally\n");
}
fwrite(STDOUT, "\n");

if (isset($options['second']) && $options['second'] !== false && $options['second'] !== '') {
    $second = (new DateTimeImmutable((string)$options['second']))->setTimezone($utc);
} elseif ($denseRows !== []) {
    $second = new DateTimeImmutable($denseRows[0]['sec'], $utc);
} else {
    fwrite(STDERR, "No dense second found locally and no --second given - nothing to test against.\n");
    exit(1);
}
$secondSql = $second->format('Y-m-d H:i:s');
$windowEnd = $second->modify('+1 second');

$localStmt = $pdo->prepare('SELECT qid FROM knowledge_base WHERE qualys_last_modified = :sec ORDER BY qid');
$localStmt->execute(['sec' => $secondSql]);
$localQids = array_map('intval', $localStmt->fetchAll(PDO::FETCH_COLUMN));
if ($localQids === []) {
    fwrite(STDERR, "No local QIDs are stamped {$secondSql} UTC - pick a second from the list above.\n");
    exit(1);
}

$idMin = $localQids[max(0, count($localQids) - $knownWanted)];
$idMax = $idMin + 10_000_000;
$knownInRange = array_values(array_filter($localQids, static fn(int $q): bool => $q >= $idMin && $q <= $idMax));
$localSet = array_fill_keys($localQids, true);

fwrite(STDOUT, "Testing second {$secondSql} UTC: " . count($localQids) . " QID(s) held locally, highest " . end($localQids) . ".\n");
fwrite(STDOUT, "One call on /api/{$apiVersion}/: last_modified_after={$second->format('Y-m-d\TH:i:s\Z')} last_modified_before={$windowEnd->format('Y-m-d\TH:i:s\Z')} id_min={$idMin} id_max={$idMax}\n");
fwrite(STDOUT, "If both filters apply: every record is stamped in that second and has a QID in range; the " . count($knownInRange) . " locally-held QIDs in range come back, plus any the sync never reached.\n\n");

if ($localOnly) {
    fwrite(STDOUT, "--local-only: not calling Qualys.\n");
    exit(0);
}

$client = new QualysApiClient(
    (string)Config::get('qualys.api_base_url'),
    (string)Config::get('qualys.username'),
    (string)Config::get('qualys.password'),
    $apiVersion
);

$exitCode = 0;
try {
    $request = new ReflectionMethod(QualysApiClient::class, 'requestToFile');
    $parse = new ReflectionMethod(QualysApiClient::class, 'parseKnowledgeBaseFile');

    $tmpFile = $request->invoke($client, '/fo/knowledge_base/vuln/', [
        'action'               => 'list',
        'details'              => 'All',
        'last_modified_after'  => $second->format('Y-m-d\TH:i:s\Z'),
        'last_modified_before' => $windowEnd->format('Y-m-d\TH:i:s\Z'),
        'id_min'               => $idMin,
        'id_max'               => $idMax,
    ]);

    $returned = 0;
    $outsideIds = [];
    $outsideTime = [];
    $knownBack = 0;
    $newQids = [];
    $windowStart = $second->format('Y-m-d H:i:s');
    $windowStop = $windowEnd->format('Y-m-d H:i:s');
    try {
        foreach ($parse->invoke($client, $tmpFile) as $vuln) {
            $returned++;
            $qid = (int)$vuln['qid'];
            if ($qid < $idMin || $qid > $idMax) {
                $outsideIds[] = $qid;
            }
            // Either bound may be inclusive (never confirmed), so the
            // second after counts as inside too.
            $stamp = $vuln['qualys_last_modified'];
            if ($stamp === null || $stamp < $windowStart || $stamp > $windowStop) {
                $outsideTime[] = $qid . ' @ ' . ($stamp ?? 'no date');
            }
            if ($qid >= $idMin && $qid <= $idMax) {
                if (isset($localSet[$qid])) {
                    $knownBack++;
                } else {
                    $newQids[] = $qid;
                }
            }
        }
    } finally {
        @unlink($tmpFile);
    }

    fwrite(STDOUT, "Returned: {$returned} record(s)\n");
    fwrite(STDOUT, "  QIDs outside id range:            " . count($outsideIds) . ($outsideIds !== [] ? ' (e.g. ' . implode(', ', array_slice($outsideIds, 0, 5)) . ')' : '') . "\n");
    fwrite(STDOUT, "  records stamped outside the second: " . count($outsideTime) . ($outsideTime !== [] ? ' (e.g. ' . implode(', ', array_slice($outsideTime, 0, 3)) . ')' : '') . "\n");
    fwrite(STDOUT, "  locally-held QIDs that came back:  {$knownBack} of " . count($knownInRange) . "\n");
    fwrite(STDOUT, "  QIDs in range we don't hold:       " . count($newQids) . ($newQids !== [] ? ' (e.g. ' . implode(', ', array_slice($newQids, 0, 5)) . ')' : '') . "\n\n");

    if ($outsideIds !== []) {
        fwrite(STDOUT, "VERDICT: NOT USABLE - id_min/id_max was ignored when sent with last_modified_*. Splitting a dense second by QID would never shrink it.\n");
    } elseif ($outsideTime !== []) {
        fwrite(STDOUT, "VERDICT: NOT USABLE AS-IS - records stamped outside the second came back, so last_modified_* was ignored when sent with id_min/id_max (or it filters on a different date than LAST_SERVICE_MODIFICATION_DATETIME). Paste this output before anything is built on it.\n");
    } elseif ($returned === 0 || $knownBack === 0) {
        fwrite(STDOUT, "VERDICT: INCONCLUSIVE - none of the locally-held QIDs came back, so this doesn't show the filters working together. Paste this output; the stored timestamp may not be the one the last_modified filter uses.\n");
    } elseif ($knownBack < count($knownInRange)) {
        fwrite(STDOUT, "VERDICT: PARTLY CONFIRMED - both filters held, but only {$knownBack} of " . count($knownInRange) . " locally-held QIDs came back. The missing ones were probably modified again since; paste this output before relying on it.\n");
    } else {
        fwrite(STDOUT, "VERDICT: USABLE - both filters applied together. A dense second can be split by QID range.\n");
        if ($newQids !== []) {
            fwrite(STDOUT, "  This range alone held " . count($newQids) . " QID(s) the sync never reached - the gap is real.\n");
        } else {
            fwrite(STDOUT, "  Nothing beyond what we hold came back in this range - this second may already be complete locally.\n");
        }
    }
} catch (Throwable $e) {
    $message = $e->getMessage();
    if (str_contains($message, 'call budget') || str_contains($message, 'rate limit')) {
        fwrite(STDOUT, "NOT SENT: {$message}\n");
        fwrite(STDOUT, "Re-run with VULNDASH_IGNORE_CALL_RESERVE=1 to spend one reserve call, or wait until calls free up.\n");
    } else {
        fwrite(STDOUT, "VERDICT: NOT USABLE - Qualys rejected or failed the combined call: {$message}\n");
    }
    $exitCode = 1;
} finally {
    try {
        ApiCallLogRepository::recordCalls($client->getCallLog());
    } catch (Throwable $logError) {
        fwrite(STDERR, 'Warning: failed to persist API call log: ' . $logError->getMessage() . "\n");
    }
}

exit($exitCode);
