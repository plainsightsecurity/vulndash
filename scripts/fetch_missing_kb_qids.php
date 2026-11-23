#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Fetches every QID on the missing-from-KB list (MissingKbQidRepository)
 * straight from Qualys by id, so a finding whose QID the KB sweep never
 * picked up reaches the dashboard without anyone acting on it.
 *
 * The host jobs add a QID to the list when an agent reports it and it has
 * no knowledge_base row (its detection is skipped until it does). This asks
 * for all of them in one KnowledgeBase call per 200 QIDs (ids=...), the
 * same targeted lookup diagnose_kb.php --qid makes, and upserts what comes
 * back. The skipped detections are then written by the next host job that
 * pulls their host - the 6-hourly reconcile pulls every host.
 *
 * A QID Qualys doesn't return is left on the list with the attempt
 * recorded, which turns the dashboard's Host detection card amber: waiting
 * won't fix that one (usually it isn't visible to this subscription, or
 * has been retired), so it needs a look. A failed CALL records nothing
 * against the QIDs - that's not Qualys refusing them - and is retried the
 * next day; the run exits 1 with the reason.
 *
 * Takes the KB sync's lock, so the two never call the KnowledgeBase
 * endpoint at the same time. Round-robins qualys.kb_api_versions across
 * runs (sync_state 'kb_missing_fetch_rr'), falling back to
 * qualys.api_version once if the picked version fails. Nothing on the
 * list means no call at all.
 *
 * Suggested cron entry (as www-data) - daily, after the 00:40 reconcile has
 * checked every host and before the 06:40 one writes the detections:
 *   25 1 * * * php /var/www/dashboard.plainsightsecurity.co.uk/scripts/fetch_missing_kb_qids.php >> /var/log/vulndash/kb_missing_fetch.log 2>&1
 *
 * Usage:
 *   php scripts/fetch_missing_kb_qids.php            # fetch and upsert
 *   php scripts/fetch_missing_kb_qids.php --dry-run  # list what would be asked for; no call, no writes
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;
use VulnDash\Lib\Database;
use VulnDash\Lib\KnowledgeBaseUpsert;
use VulnDash\Lib\MissingKbQidRepository;
use VulnDash\Scripts\QualysApiClient;

const BATCH_SIZE = 200;

$dryRun = in_array('--dry-run', $argv, true);

fwrite(STDOUT, '=== missing KB QID fetch (' . date('Y-m-d H:i:s') . ')' . ($dryRun ? ' DRY RUN' : '') . "\n");

$outstanding = MissingKbQidRepository::outstanding();
if ($outstanding === []) {
    fwrite(STDOUT, "Nothing outstanding - every QID agents have reported is in the local KB. No call made.\n");
    exit(0);
}

$qids = array_column($outstanding, 'qid');
fwrite(STDOUT, count($qids) . ' outstanding QID(s): ' . implode(', ', array_slice($qids, 0, 30)) . (count($qids) > 30 ? ', ...' : '') . "\n");

if ($dryRun) {
    fwrite(STDOUT, 'Would make ' . (int)ceil(count($qids) / BATCH_SIZE) . " KnowledgeBase call(s). DRY RUN - nothing sent, nothing written.\n");
    exit(0);
}

$lockPath = sys_get_temp_dir() . '/vulndash_kb_sync.lock';
$lockHandle = fopen($lockPath, 'c');
if ($lockHandle === false) {
    fwrite(STDERR, "Could not open lock file {$lockPath} - check its ownership/permissions.\n");
    exit(1);
}
@chmod($lockPath, 0666);
if (!flock($lockHandle, LOCK_EX | LOCK_NB)) {
    fwrite(STDOUT, "The KB sync is running - leaving this for tomorrow's run.\n");
    exit(0);
}

$pdo = Database::getConnection();
$clients = [];
$exitCode = 0;

try {
    $versions = array_values(array_filter(array_map(static fn($v): string => trim((string)$v), (array)(Config::get('qualys.kb_api_versions') ?? [])), static fn(string $v): bool => $v !== ''));
    $primary = (string)(Config::get('qualys.api_version') ?? '4.0');
    if ($versions === []) {
        $versions = [$primary];
    }

    $rrStmt = $pdo->prepare('SELECT state_json FROM sync_state WHERE sync_type = :type');
    $rrStmt->execute(['type' => 'kb_missing_fetch_rr']);
    $rr = json_decode((string)$rrStmt->fetchColumn(), true);
    $rrIndex = is_array($rr) ? max(0, (int)($rr['index'] ?? 0)) : 0;
    $picked = $versions[$rrIndex % count($versions)];
    // Advanced up front: "which version next", not a completeness cursor.
    $pdo->prepare('INSERT INTO sync_state (sync_type, state_json) VALUES (:type, :state) ON DUPLICATE KEY UPDATE state_json = VALUES(state_json)')
        ->execute(['type' => 'kb_missing_fetch_rr', 'state' => json_encode(['index' => $rrIndex + 1])]);

    $makeClient = function (string $version) use (&$clients): QualysApiClient {
        $client = new QualysApiClient(
            (string)Config::get('qualys.api_base_url'),
            (string)Config::get('qualys.username'),
            (string)Config::get('qualys.password'),
            $version
        );
        $clients[] = $client;
        return $client;
    };

    $upsert = KnowledgeBaseUpsert::prepare($pdo);
    $fetched = [];

    foreach (array_chunk($qids, BATCH_SIZE) as $batch) {
        $rows = null;
        foreach (array_values(array_unique([$picked, $primary])) as $i => $version) {
            try {
                fwrite(STDOUT, 'Asking Qualys for ' . count($batch) . " QID(s) on /api/{$version}/...\n");
                // Materialised before any write, so a failure part-way
                // through reading a response leaves nothing half-applied.
                $rows = iterator_to_array($makeClient($version)->fetchKnowledgeBaseByIds($batch), false);
                break;
            } catch (\Throwable $e) {
                fwrite(STDOUT, "  failed on /api/{$version}/: {$e->getMessage()}\n");
                if ($i === 0 && $version !== $primary) {
                    fwrite(STDOUT, "  retrying once on the primary version /api/{$primary}/\n");
                }
            }
        }
        if ($rows === null) {
            throw new \RuntimeException('Qualys KnowledgeBase lookup failed on every version tried - nothing recorded against the QIDs; tomorrow\'s run will retry.');
        }

        foreach ($rows as $row) {
            $upsert->execute($row);
            $fetched[(int)$row['qid']] = (string)$row['title'];
        }
    }

    $notReturned = array_values(array_filter($qids, static fn(int $q): bool => !isset($fetched[$q])));

    foreach ($fetched as $qid => $title) {
        fwrite(STDOUT, "  fetched {$qid}: {$title}\n");
    }
    foreach ($notReturned as $qid) {
        fwrite(STDOUT, "  NOT RETURNED by Qualys: {$qid}\n");
    }
    MissingKbQidRepository::markFetchAttempt($pdo, $notReturned, 'not returned by Qualys');
    // Drops everything now in knowledge_base from the list.
    $remaining = MissingKbQidRepository::record($pdo, []);

    fwrite(STDOUT, 'Done: ' . count($fetched) . ' fetched into the KB, ' . count($notReturned) . ' not returned by Qualys, '
        . count($remaining) . " still outstanding.\n");
    if ($fetched !== []) {
        fwrite(STDOUT, "  Their skipped detections are written by the next host job that pulls those hosts (the 6-hourly reconcile pulls every host).\n");
    }
    if ($notReturned !== []) {
        fwrite(STDOUT, '  Check the ones Qualys didn\'t return with: php scripts/diagnose_kb.php --qid=' . implode(',', array_slice($notReturned, 0, 50)) . "\n");
    }
} catch (\Throwable $e) {
    fwrite(STDERR, 'Missing KB QID fetch failed: ' . $e->getMessage() . "\n");
    $exitCode = 1;
} finally {
    foreach ($clients as $c) {
        try {
            ApiCallLogRepository::recordCalls($c->getCallLog());
        } catch (\Throwable $logError) {
            fwrite(STDERR, 'Warning: failed to persist API call log: ' . $logError->getMessage() . "\n");
        }
    }
    flock($lockHandle, LOCK_UN);
    fclose($lockHandle);
}

exit($exitCode);
