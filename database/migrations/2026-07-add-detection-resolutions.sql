-- Detection resolutions (remediation tombstones) (2026-07)
-- ---------------------------------------------------------------------------
-- Records when a detection is remediated, so the Trends page's "Resolved"
-- movement figure reflects reality on this agent-only platform.
--
-- Why this is needed: remediation here is NOT recorded as a status='Fixed'
-- row. The Cloud Agent simply stops reporting a QID once it's fixed, and
-- scripts/sync_host_detections.php then DELETES the local detection (it rewrites
-- each reported host's full detection list and removes anything Qualys no longer
-- lists - see that script's docblock). The host-detection API call also doesn't
-- request Fixed-status detections, so Qualys never sends them. The upshot was
-- that getMovementCounts()'s old "resolved = rows with status='Fixed' and a
-- recent last_fixed" could never be anything but 0: the posture trend line
-- (asset_vuln_snapshot, a daily open COUNT) correctly dropped when detections
-- were deleted, but the movement breakdown had no way to attribute that drop to
-- "Resolved".
--
-- This table is the missing signal: each time the sync deletes a no-longer-
-- reported detection, it first writes one small tombstone row here
-- (asset_id, qid, resolved_at = when we noticed it gone). getMovementCounts()
-- then counts "Resolved" from these rows, tag-scoped, within its window. It's a
-- deliberately tiny, append-only record - three columns, no vulnerability text -
-- and it is PRUNED on every sync run (sync.resolution_retention_days, default
-- 90) so it reaches a small steady state instead of growing forever. Nothing
-- reads a resolution older than the movement window (30 days), so the retention
-- default keeps a comfortable buffer over that and everything past it is dead
-- weight that the prune removes.
--
-- resolved_at is "when the sync observed the detection gone", not Qualys's exact
-- fix time (which we don't receive) - accurate enough for a rolling movement
-- window, and honest about what it means.
--
-- No qid foreign key: a resolution is a historical fact that shouldn't vanish
-- just because a QID's KnowledgeBase metadata later changes. The asset FK does
-- CASCADE, so removing an asset cleans up its resolutions (matching
-- asset_vuln_snapshot's fk_snapshot_asset). assets.id is a plain PK (not a
-- generated column), so the CASCADE restriction that blocks it elsewhere in
-- this schema doesn't apply here.
--
-- Apply once, after the core schema:
--   mysql -u root -p vulndash < database/migrations/2026-07-add-detection-resolutions.sql
--
-- Written for MySQL 8; CREATE TABLE IF NOT EXISTS is re-runnable as-is.

CREATE TABLE IF NOT EXISTS detection_resolutions (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    asset_id     INT UNSIGNED NOT NULL,
    qid          INT UNSIGNED NOT NULL,
    -- When the sync first observed this detection no longer reported by Qualys.
    resolved_at  DATETIME NOT NULL,
    -- (asset_id, resolved_at) serves the tag-scoped movement-window read (join
    -- on asset_id, filter resolved_at >= cutoff) and satisfies the FK's index
    -- requirement; the resolved_at-only index serves the retention prune
    -- (WHERE resolved_at < cutoff).
    INDEX idx_res_asset_date (asset_id, resolved_at),
    INDEX idx_res_date (resolved_at),
    CONSTRAINT fk_res_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
