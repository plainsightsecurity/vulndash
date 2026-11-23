-- ---------------------------------------------------------------------------
-- 2026-11: scan_request_queue - on-demand Cloud Agent vulnerability scans
--
-- One row per "scan this asset now" request from the Assets page. The cron
-- worker (scripts/process_scan_requests.php) sends every pending request to
-- Qualys in ONE bulk on-demand scan call
-- (POST /qps/rest/1.0/ods/ca/agentasset?scan=Vulnerability_Scan), at most
-- once per qualys.ods_min_interval_minutes, because that endpoint allows 25
-- calls per 24h and has no other API version to rotate across. Results come
-- back through the normal hourly host sync - nothing here reads them.
--
-- Same shape as agent_uninstall_queue, deliberately: the same AssetView id
-- (qualys_asset_id) targets both APIs, and the worker follows the same
-- claim / resolve / one-bulk-call / retry pattern. Unlike an uninstall, a
-- queued scan does NOT hide the asset anywhere.
--
-- active_dedup: one pending/processing request per host at a time, so
-- repeated clicks before the next send don't queue duplicates. It is NULL
-- for terminal rows, which MySQL's UNIQUE allows any number of, so history
-- is kept. No foreign key can sit on its base columns (MySQL 8 error 1215),
-- which is why the keys below are on asset_id and requested_by only.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS, safe to run more than once.
-- Additive only - nothing existing is altered.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS scan_request_queue (
    id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    asset_id         INT UNSIGNED NULL,
    qualys_host_id   BIGINT UNSIGNED NOT NULL,
    qualys_asset_id  BIGINT UNSIGNED NULL,
    hostname         VARCHAR(255) NULL,
    ip_address       VARCHAR(45) NULL,
    status           ENUM('pending','processing','sent','failed') NOT NULL DEFAULT 'pending',
    requested_by     INT UNSIGNED NULL,
    requested_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at     DATETIME NULL,
    attempts         INT UNSIGNED NOT NULL DEFAULT 0,
    last_error       TEXT NULL,
    active_dedup     BIGINT UNSIGNED GENERATED ALWAYS AS (
                         CASE WHEN status IN ('pending','processing') THEN qualys_host_id ELSE NULL END
                     ) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uq_scan_request_active_host (active_dedup),
    KEY idx_scan_request_status (status),
    KEY idx_scan_request_asset (asset_id, requested_at),
    KEY fk_scan_request_user (requested_by),
    CONSTRAINT fk_scan_request_asset FOREIGN KEY (asset_id)     REFERENCES assets (id) ON DELETE SET NULL,
    CONSTRAINT fk_scan_request_user  FOREIGN KEY (requested_by) REFERENCES users (id)  ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
