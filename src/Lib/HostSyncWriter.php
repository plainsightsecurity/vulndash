<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * The single write path for turning one host as Qualys reported it into
 * local rows: its asset row, its tags, its detections, and the removal (with
 * remediation tombstones) of detections Qualys no longer reports.
 *
 * WHY THIS EXISTS. scripts/sync_host_detections.php (incremental, frequent)
 * and scripts/reconcile_asset_inventory.php (full pull, hourly) both write
 * the same host data, and until 2026-07-23 each carried its own copy of the
 * SQL and the logic. Every copy is a chance to drift, and all three known
 * drifts were the same shape - the reconcile copy silently doing less than
 * the sync copy, on the job that in practice sees a new or changed host
 * FIRST:
 *
 *   1. Tags: reconcile looked a tag up by Qualys ID and INSERTed if absent,
 *      never matching a pending row by name. A tag pre-created for a client
 *      got a duplicate row instead of being promoted, permanently orphaning
 *      the pending row its accounts were assigned to (the "FaiceTechAgents"
 *      case). Fixed by routing to UserRepository::resolveSyncedTagId().
 *   2. detection_type: reconcile's upsert omitted the column entirely, so a
 *      detection first written by that script landed with NULL type and
 *      dropped out of the Confirmed/Potential/Info chips.
 *   3. Remediation tombstones: reconcile deleted no-longer-reported
 *      detections without writing detection_resolutions rows, and without a
 *      transaction. Since it pulls in full hourly while the sync only sees
 *      recently-assessed hosts, it was usually the first to observe a fix -
 *      so most remediations were being deleted with no record, undercounting
 *      the Trends "Resolved" figure.
 *
 * Each was found only by reading the two files side by side, months apart,
 * which is not a control. Consolidating here is: there is now one copy, and
 * a change to it necessarily applies to every caller. Same principle as
 * VulnerabilityRepository::buildTagScopeJoin() being the one choke point for
 * tag scoping, and UserRepository::resolveSyncedTagId() for tag resolution.
 *
 * Deliberately NOT absorbed into this class, because they are genuinely
 * per-script rather than shared: which hosts to pull and from which endpoint,
 * the incremental vs. full decision, deletion of assets missing from a full
 * pull, asset_vuln_snapshot, tombstone pruning, API call logging, locking and
 * sync_log. Those differ because the two jobs differ; the per-host write does
 * not, which is exactly why it belongs here and they don't.
 *
 * Statements are prepared once per instance and reused for every host, the
 * same prepare-once discipline both scripts applied inline before.
 */
class HostSyncWriter
{
    private \PDO $pdo;

    /** @var array<string, \PDOStatement> */
    private array $stmts;

    /** @var array<int, array<int, true>> qid => asset ids its detection was skipped on - see getSkippedQids() */
    private array $skippedQids = [];

    private TagScopeClassifier $tagScope;

    /**
     * $tagScope is required, not optional, so no caller can write asset_tags
     * without the asset-group/IP-range filter - see upsertAssetAndTags().
     */
    public function __construct(\PDO $pdo, TagScopeClassifier $tagScope)
    {
        $this->pdo = $pdo;
        $this->tagScope = $tagScope;

        $this->stmts = [
            // qualys_asset_id uses COALESCE so a pull that didn't carry the
            // AssetView id (qualys.show_asset_id off, or Qualys omitted it)
            // never wipes one already stored - by this sync or by
            // scripts/resolve_asset_ids.php / the queue workers' lookup.
            'assetUpsert' => $pdo->prepare('
                INSERT INTO assets (qualys_host_id, qualys_asset_id, hostname, ip_address, dns_name, os, tracking_method, last_scan_date)
                VALUES (:qualys_host_id, :qualys_asset_id, :hostname, :ip_address, :dns_name, :os, :tracking_method, :last_scan_date)
                ON DUPLICATE KEY UPDATE
                    qualys_asset_id = COALESCE(VALUES(qualys_asset_id), qualys_asset_id),
                    hostname = VALUES(hostname), ip_address = VALUES(ip_address), dns_name = VALUES(dns_name),
                    os = VALUES(os), tracking_method = VALUES(tracking_method), last_scan_date = VALUES(last_scan_date)
            '),
            'assetIdLookup'   => $pdo->prepare('SELECT id FROM assets WHERE qualys_host_id = :qualys_host_id'),
            'assetTagsDelete' => $pdo->prepare('DELETE FROM asset_tags WHERE asset_id = :asset_id'),
            'assetTagInsert'  => $pdo->prepare('INSERT IGNORE INTO asset_tags (asset_id, tag_id) VALUES (:asset_id, :tag_id)'),
            'kbLookup'        => $pdo->prepare('SELECT title, severity_level, cvss_base, cvss3_base FROM knowledge_base WHERE qid = :qid'),
            'detectionUpsert' => $pdo->prepare('
                INSERT INTO host_detections
                    (asset_id, qid, status, detection_type, port, protocol, is_ssl, first_found, last_found, last_fixed,
                     times_found, effective_cvss_score, effective_cvss_source, is_ce_plus_fail, results)
                VALUES
                    (:asset_id, :qid, :status, :detection_type, :port, :protocol, :is_ssl, :first_found, :last_found, :last_fixed,
                     :times_found, :effective_cvss_score, :effective_cvss_source, :is_ce_plus_fail, :results)
                ON DUPLICATE KEY UPDATE
                    status = VALUES(status), detection_type = VALUES(detection_type),
                    last_found = VALUES(last_found), last_fixed = VALUES(last_fixed),
                    times_found = VALUES(times_found), effective_cvss_score = VALUES(effective_cvss_score),
                    effective_cvss_source = VALUES(effective_cvss_source), is_ce_plus_fail = VALUES(is_ce_plus_fail),
                    results = VALUES(results)
            '),
            'localDetections' => $pdo->prepare('SELECT id, qid, port_dedup_key, effective_cvss_score FROM host_detections WHERE asset_id = :asset_id'),
            'resolutionInsert' => $pdo->prepare('INSERT INTO detection_resolutions (asset_id, qid, effective_cvss_score, resolved_at) VALUES (:asset_id, :qid, :effective_cvss_score, :resolved_at)'),
        ];
    }

    /**
     * Upserts one host's asset row and replaces its full tag set, returning
     * the local assets.id.
     *
     * Tags are deleted and re-added rather than merged, so a tag REMOVED on
     * the Qualys side disappears locally too. Resolution of each tag -
     * including promoting a pending row in place - is delegated to
     * UserRepository::resolveSyncedTagId() rather than reimplemented; see
     * that method for the ordering and for the duplicate-row failure it
     * exists to prevent.
     *
     * Safe to call for a host from any endpoint, including one carrying no
     * detection data at all (reconcile_asset_inventory.php's zero-detection
     * pass over the Host List endpoint).
     *
     * Only the tags TagScopeClassifier allows are written (2026-11): an
     * asset-group or IP-range tag reaches an agent host just because the
     * host's IP matches, and would otherwise scope all of that host's agent
     * findings. Filtered here, at the one write of asset_tags, rather than in
     * the six places that read it. Classification happens before anything is
     * written for the host, so a failed lookup leaves the host as it was.
     *
     * Also stores the host's AssetView id when the pull carried one
     * ($host['asset_id'], see QualysApiClient's "AssetView id from the host
     * pulls"), so a scan or uninstall request for it needs no lookup call.
     * Qualys is taken as the source of truth: a different id replaces the
     * stored one, a missing one leaves it alone.
     */
    public function upsertAssetAndTags(array $host): int
    {
        $scopingTags = $this->tagScope->scopingTags($host['tags'] ?? []);

        $this->stmts['assetUpsert']->execute([
            'qualys_host_id'  => $host['id'],
            'qualys_asset_id' => isset($host['asset_id']) && (int)$host['asset_id'] > 0 ? (int)$host['asset_id'] : null,
            'hostname'        => $host['hostname'] ?? null,
            'ip_address'      => $host['ip'] ?? null,
            'dns_name'        => $host['dns'] ?? null,
            'os'              => $host['os'] ?? null,
            'tracking_method' => $host['tracking_method'] ?? null,
            'last_scan_date'  => $host['last_scan_date'] ?? null,
        ]);

        $this->stmts['assetIdLookup']->execute(['qualys_host_id' => $host['id']]);
        $assetId = (int)$this->stmts['assetIdLookup']->fetchColumn();
        $this->stmts['assetIdLookup']->closeCursor();

        $this->stmts['assetTagsDelete']->execute(['asset_id' => $assetId]);
        foreach ($scopingTags as $tag) {
            $tagId = UserRepository::resolveSyncedTagId($this->pdo, $tag['qualys_tag_id'], $tag['name']);
            $this->stmts['assetTagInsert']->execute(['asset_id' => $assetId, 'tag_id' => $tagId]);
        }

        return $assetId;
    }

    /**
     * Upserts every detection Qualys reported for this host, returning how
     * many rows were written.
     *
     * A QID with no local knowledge_base row yet is SKIPPED, not written with
     * incomplete data - severity here is derived from the KB's CVSS scores
     * (CvssCalculator), so writing without it would mean a detection with no
     * usable severity. It gets picked up by whichever job runs after
     * sync_knowledge_base.php has caught up. Note that a skipped detection is
     * still counted as "reported" by reconcileDetections() below, so this
     * skip can never cause a live finding to be deleted as absent. The skip
     * is no longer silent: see getSkippedQids().
     *
     * The KB title is passed into CvssCalculator so a QID Qualys has marked
     * as a zero day (no vendor fix yet) is never written as a CE+ failure,
     * however high its CVSS score - see CvssCalculator's class docblock.
     * Because this re-evaluates the title on every sync, a QID that gets
     * renamed once a fix ships (Qualys drops the "Zero Day" wording) starts
     * counting as a normal CE+ failure again on its next sync pass, with no
     * other change needed.
     *
     * @param array $host one host as returned by QualysApiClient::fetchHostDetections()
     */
    public function upsertDetections(int $assetId, array $host): int
    {
        $written = 0;

        foreach ($host['detections'] ?? [] as $detection) {
            $this->stmts['kbLookup']->execute(['qid' => $detection['qid']]);
            $kb = $this->stmts['kbLookup']->fetch();
            $this->stmts['kbLookup']->closeCursor();

            if (!$kb) {
                $this->skippedQids[(int)$detection['qid']][$assetId] = true;
                continue;
            }

            $cvss = CvssCalculator::calculate(
                $kb['cvss3_base'] !== null ? (float)$kb['cvss3_base'] : null,
                $kb['cvss_base'] !== null ? (float)$kb['cvss_base'] : null,
                (int)$kb['severity_level'],
                (string)$kb['title']
            );

            $this->stmts['detectionUpsert']->execute([
                'asset_id'              => $assetId,
                'qid'                   => $detection['qid'],
                'status'                => $detection['status'] ?? 'Active',
                'detection_type'        => $detection['type'] ?? null,
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

            $written++;
        }

        return $written;
    }

    /**
     * Removes local detections for this host that Qualys did NOT just
     * report, writing one detection_resolutions tombstone per removal first.
     *
     * On this agent-only platform Qualys sends no Fixed status or fix date
     * for an agent-remediated QID - the detection simply stops being
     * reported - so "absent from a report that included this host" is the
     * only remediation signal there is, and resolved_at is when we observed
     * it gone. The tombstone captures the effective CVSS score because the
     * host_detections row it came from is about to be deleted and the Trends
     * "Recently resolved" list still needs the severity.
     *
     * Tombstone writes and the delete share one transaction, so a mid-way
     * failure can't leave a tombstone for a row that's still there, or a
     * deletion with no record of why.
     *
     * ONLY call this for a host whose payload came from the Host List
     * DETECTION endpoint. The "keep" set is built from that payload, so
     * calling it with a host from an endpoint that doesn't carry detections
     * would read as "Qualys reports nothing for this host" and delete every
     * live finding on it. For a host that genuinely has none left, use
     * removeAllDetections() - same outcome, but asked for explicitly.
     *
     * @return array{removed: int, resolutions: int}
     */
    public function reconcileDetections(int $assetId, array $host): array
    {
        // Built from every detection Qualys sent for this host - including
        // ones upsertDetections() skipped for a missing KB entry - so a
        // detection Qualys is still actively reporting is never removed here
        // just because its KB row hasn't synced yet. Only genuine absence
        // counts.
        $reportedKeys = [];
        foreach ($host['detections'] ?? [] as $detection) {
            $portDedupKey = $detection['port'] !== null ? (int)$detection['port'] : 4294967295;
            $reportedKeys["{$detection['qid']}:{$portDedupKey}"] = true;
        }

        return $this->removeDetectionsExcept($assetId, $reportedKeys);
    }

    /**
     * Removes EVERY local detection for this asset, with the same remediation
     * tombstones reconcileDetections() writes.
     *
     * This exists for one specific, verified situation, and the caller must
     * have established it before calling: the host is still live in Qualys but
     * has no open detections left at all. Qualys's Host List Detection
     * endpoint simply does not return a host with nothing to report (see
     * QualysApiClient::fetchHostList()'s docblock), so such a host vanishes
     * from the detection pull entirely while still appearing in the plain Host
     * List pull. "Absent from the detection pull, present in the host list"
     * is therefore a positive statement that everything on it has been fixed -
     * not missing data.
     *
     * Before this existed, that host sat in permanent limbo: never in the
     * detection pull so its detections were never reconciled, but never absent
     * from Qualys either so the asset was never deleted. Its findings froze at
     * whatever they were when it last had at least one open detection, and
     * remediating the LAST finding on a host meant that finding stayed on the
     * dashboard forever. Found 2026-07-23 on the host "storage", whose final
     * four QIDs had been fixed for days and were still showing.
     *
     * A separate method rather than reconcileDetections($assetId, []) on
     * purpose: an empty payload reaching that method by accident - a parse
     * failure, a truncated response, a host from an endpoint that carries no
     * detections - would wipe every live finding on the host. Deleting
     * everything should have to be asked for by name.
     *
     * @return array{removed: int, resolutions: int}
     */
    public function removeAllDetections(int $assetId): array
    {
        return $this->removeDetectionsExcept($assetId, []);
    }

    /**
     * Shared removal path: deletes every local detection for this asset whose
     * "qid:port_dedup_key" is not in $reportedKeys, writing one tombstone per
     * removal first, both inside one transaction.
     *
     * @param array<string, true> $reportedKeys
     * @return array{removed: int, resolutions: int}
     */
    private function removeDetectionsExcept(int $assetId, array $reportedKeys): array
    {
        $this->stmts['localDetections']->execute(['asset_id' => $assetId]);
        $idsToRemove = [];
        $removedDetections = [];
        foreach ($this->stmts['localDetections']->fetchAll() as $row) {
            $key = "{$row['qid']}:{$row['port_dedup_key']}";
            if (!isset($reportedKeys[$key])) {
                $idsToRemove[] = (int)$row['id'];
                $removedDetections[] = [
                    'qid'   => (int)$row['qid'],
                    'score' => $row['effective_cvss_score'] !== null ? (float)$row['effective_cvss_score'] : null,
                ];
            }
        }

        if (empty($idsToRemove)) {
            return ['removed' => 0, 'resolutions' => 0];
        }

        $resolvedAt = date('Y-m-d H:i:s');
        $ownsTransaction = !$this->pdo->inTransaction();
        if ($ownsTransaction) {
            $this->pdo->beginTransaction();
        }

        try {
            foreach ($removedDetections as $removed) {
                $this->stmts['resolutionInsert']->execute([
                    'asset_id'             => $assetId,
                    'qid'                  => $removed['qid'],
                    'effective_cvss_score' => $removed['score'],
                    'resolved_at'          => $resolvedAt,
                ]);
            }

            $placeholders = implode(',', array_fill(0, count($idsToRemove), '?'));
            $this->pdo->prepare("DELETE FROM host_detections WHERE id IN ($placeholders)")->execute($idsToRemove);

            if ($ownsTransaction) {
                $this->pdo->commit();
            }
        } catch (\Throwable $e) {
            if ($ownsTransaction && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }

        return ['removed' => count($idsToRemove), 'resolutions' => count($removedDetections)];
    }

    /**
     * Every QID whose detection upsertDetections() skipped for having no
     * knowledge_base row, across all hosts this instance has written, with
     * how many hosts each was on. The callers hand this to
     * MissingKbQidRepository::record() at the end of a run - a skipped QID
     * is a finding missing from the dashboard, so it must be visible.
     *
     * @return array<int, int> qid => host count, highest count first
     */
    public function getSkippedQids(): array
    {
        $out = array_map('count', $this->skippedQids);
        arsort($out);
        return $out;
    }

    /**
     * The whole per-host write in one call: asset, tags, detections, then
     * removal of anything no longer reported. This is what both sync jobs
     * use for a host from the Host List Detection endpoint - the ordering
     * matters (upsert before reconcile, so a detection reported this run is
     * present locally before absence is judged) and having it in one place
     * is the point of this class.
     *
     * Not for a host from the plain Host List endpoint - see
     * reconcileDetections()'s warning; call upsertAssetAndTags() alone for
     * those.
     *
     * @return array{asset_id: int, written: int, removed: int, resolutions: int}
     */
    public function writeHost(array $host): array
    {
        $assetId = $this->upsertAssetAndTags($host);
        $written = $this->upsertDetections($assetId, $host);
        $reconciled = $this->reconcileDetections($assetId, $host);

        return [
            'asset_id'    => $assetId,
            'written'     => $written,
            'removed'     => $reconciled['removed'],
            'resolutions' => $reconciled['resolutions'],
        ];
    }
}
