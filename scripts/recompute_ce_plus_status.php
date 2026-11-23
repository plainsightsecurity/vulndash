#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Re-derives host_detections.is_ce_plus_fail for every currently-stored
 * detection, using CvssCalculator against the KB data already cached
 * locally - no Qualys API call involved.
 *
 * WHY THIS EXISTS. CvssCalculator::calculate() picked up a zero-day
 * carve-out (2026-08-21): a QID whose KB title carries Qualys's "Zero Day" /
 * "ZeroDay" marker never counts as a CE+ failure, however high its CVSS
 * score, because there's no vendor fix yet to apply. That new logic only
 * runs at WRITE time though - inside HostSyncWriter::upsertDetections(),
 * called from sync_host_detections.php (incremental - only touches a host
 * that's had a fresh Qualys scan since the last successful run) and
 * reconcile_asset_inventory.php (full pull, hourly). A detection that was
 * written under the OLD logic and whose host hasn't been re-scanned/
 * re-pulled since this code was deployed keeps its stale is_ce_plus_fail
 * value until one of those next runs it - up to an hour, worst case, via
 * the hourly reconcile. This script closes that gap immediately by
 * recomputing every row's CE+ status right now, entirely from what's
 * already in the local database.
 *
 * Deliberately only touches is_ce_plus_fail, never effective_cvss_score/
 * effective_cvss_source - the zero-day carve-out doesn't change how the
 * score itself is derived, only whether that score counts as a CE+
 * failure, so those two columns can't have drifted and are left alone.
 *
 * Safe to re-run any time (e.g. after a future change to
 * CvssCalculator::isZeroDayTitle()'s pattern) - this always recomputes
 * every row fully from current KB data rather than incrementally patching,
 * so running it twice in a row is a no-op the second time.
 *
 * DRY RUN BY DEFAULT: prints exactly what would change and writes nothing
 * unless you pass --confirm. Processes in batches of 2000 (keyset
 * pagination on host_detections.id, not OFFSET) to stay light on memory
 * regardless of table size; each batch commits separately, so an
 * interruption partway through leaves already-processed rows corrected
 * and the rest untouched - just re-run to pick up where it left off (or
 * from the start; either is safe, see above).
 *
 * Usage:
 *   php scripts/recompute_ce_plus_status.php            # dry run
 *   php scripts/recompute_ce_plus_status.php --confirm   # apply
 */

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\CvssCalculator;
use VulnDash\Lib\Database;

$confirm   = in_array('--confirm', $argv, true);
$batchSize = 2000;
$previewCap = 25;

$pdo = Database::getConnection();

fwrite(STDOUT, "==========================================================\n");
fwrite(STDOUT, "  Recompute CE+ status (zero-day carve-out backfill)\n");
fwrite(STDOUT, "----------------------------------------------------------\n");
fwrite(STDOUT, "  Mode : " . ($confirm ? 'CONFIRM (will write)' : 'DRY RUN (no changes)') . "\n");
fwrite(STDOUT, "==========================================================\n\n");

$selectBatch = $pdo->prepare("
    SELECT hd.id, hd.qid, hd.is_ce_plus_fail, hd.effective_cvss_score, hd.effective_cvss_source,
           kb.title, kb.severity_level, kb.cvss_base, kb.cvss3_base,
           a.hostname, a.ip_address
    FROM host_detections hd
    JOIN knowledge_base kb ON kb.qid = hd.qid
    JOIN assets a ON a.id = hd.asset_id
    WHERE hd.id > :last_id
    ORDER BY hd.id
    LIMIT :batch_size
");

$updateStmt = $pdo->prepare('UPDATE host_detections SET is_ce_plus_fail = :is_ce_plus_fail WHERE id = :id');

$lastId = 0;
$examined = 0;
$suppressed = 0; // was Fail, now correctly Pass (zero-day, no fix yet)
$reinstated = 0; // was Pass, now correctly Fail (title no longer a zero-day - fix shipped)
/** @var array<int, array{qid:int, title:string, host:string, old:bool, new:bool}> */
$preview = [];

while (true) {
    $selectBatch->bindValue('last_id', $lastId, PDO::PARAM_INT);
    $selectBatch->bindValue('batch_size', $batchSize, PDO::PARAM_INT);
    $selectBatch->execute();
    $rows = $selectBatch->fetchAll();
    $selectBatch->closeCursor();

    if (empty($rows)) {
        break;
    }

    if ($confirm) {
        $pdo->beginTransaction();
    }

    try {
        foreach ($rows as $row) {
            $examined++;
            $lastId = (int)$row['id'];

            $cvss = CvssCalculator::calculate(
                $row['cvss3_base'] !== null ? (float)$row['cvss3_base'] : null,
                $row['cvss_base'] !== null ? (float)$row['cvss_base'] : null,
                (int)$row['severity_level'],
                (string)$row['title']
            );

            $oldFail = (bool)$row['is_ce_plus_fail'];
            $newFail = $cvss['is_ce_plus_fail'];

            if ($oldFail === $newFail) {
                continue;
            }

            if ($oldFail && !$newFail) {
                $suppressed++;
            } else {
                $reinstated++;
            }

            if (count($preview) < $previewCap) {
                $preview[] = [
                    'qid'   => (int)$row['qid'],
                    'title' => (string)$row['title'],
                    'host'  => (string)($row['hostname'] ?: $row['ip_address'] ?: 'unknown host'),
                    'old'   => $oldFail,
                    'new'   => $newFail,
                ];
            }

            if ($confirm) {
                $updateStmt->execute([
                    'is_ce_plus_fail' => $newFail ? 1 : 0,
                    'id'              => $row['id'],
                ]);
            }
        }

        if ($confirm) {
            $pdo->commit();
        }
    } catch (\Throwable $e) {
        if ($confirm && $pdo->inTransaction()) {
            $pdo->rollBack();
        }
        fwrite(STDERR, "\nFailed partway through (processed {$examined} row(s) before this batch failed): {$e->getMessage()}\n");
        fwrite(STDERR, "Already-committed batches are correct as applied - re-run to continue.\n");
        exit(1);
    }
}

fwrite(STDOUT, "Examined {$examined} detection(s).\n");
fwrite(STDOUT, "  Would suppress (Fail -> Pass, zero-day/no fix yet) : {$suppressed}\n");
fwrite(STDOUT, "  Would reinstate (Pass -> Fail, fix now shipped)    : {$reinstated}\n\n");

if (!empty($preview)) {
    $shown = count($preview);
    $total = $suppressed + $reinstated;
    fwrite(STDOUT, "Preview (first {$shown} of {$total} change" . ($total === 1 ? '' : 's') . "):\n");
    foreach ($preview as $p) {
        $direction = $p['old'] && !$p['new'] ? 'Fail -> Pass' : 'Pass -> Fail';
        fwrite(STDOUT, "  QID {$p['qid']}  [{$direction}]  {$p['host']}  \"{$p['title']}\"\n");
    }
    fwrite(STDOUT, "\n");
}

if (!$confirm) {
    if ($suppressed === 0 && $reinstated === 0) {
        fwrite(STDOUT, "DRY RUN - nothing to change; every row already matches the current logic.\n");
    } else {
        fwrite(STDOUT, "DRY RUN - nothing changed. Re-run with --confirm to apply.\n");
    }
    exit(0);
}

fwrite(STDOUT, "Done - {$suppressed} suppressed, {$reinstated} reinstated, applied immediately.\n");
exit(0);
