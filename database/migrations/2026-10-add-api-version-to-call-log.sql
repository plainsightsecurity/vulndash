-- Adds qualys_api_call_log.api_version (+ an index on it).
--
-- Qualys counts its rate limit per endpoint per API version (confirmed
-- 2026-10-17 - see QualysApiClient::budgetKeyForUrl()), and since the
-- licence dropped to 25 calls each per 24h the admin API usage page needs
-- to show calls made and left PER ENDPOINT AND VERSION. Until now
-- the log only stored the endpoint path, because QualysApiClient strips the
-- /api/{version} prefix before logging, so the version was simply lost.
--
-- Values written by QualysApiClient: '2.0', '3.0', '4.0' (or whatever
-- version a "fo" call used), or 'QPS' for the /qps/rest/ calls (asset id
-- resolution and agent uninstalls). Existing rows stay NULL - the version
-- was never recorded, so there's nothing to backfill them from; the page
-- shows them as "not recorded".
--
-- Run scripts/diagnose_api_version_migration.php first (read-only).
--
-- Idempotent: each step checks information_schema first and does nothing
-- if already applied. ALTER TABLE ... ADD COLUMN IF NOT EXISTS is
-- MariaDB-only and a hard error on MySQL 8, hence the PREPARE/EXECUTE idiom.
--
-- Deploy order: run this BEFORE overlaying the matching code. The new code
-- writes this column; before it exists, each sync's call-log insert fails
-- (caught and logged as a warning - the sync itself still succeeds) and
-- /admin/api_usage shows a "run the migration" notice in place of the
-- per-version panel.

SET @col_exists := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'qualys_api_call_log'
      AND COLUMN_NAME  = 'api_version'
);

SET @ddl := IF(
    @col_exists = 0,
    'ALTER TABLE qualys_api_call_log ADD COLUMN api_version VARCHAR(10) NULL AFTER endpoint',
    'DO 0'
);

PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @idx_exists := (
    SELECT COUNT(*)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'qualys_api_call_log'
      AND INDEX_NAME   = 'idx_api_version_called_at'
);

SET @ddl := IF(
    @idx_exists = 0,
    'ALTER TABLE qualys_api_call_log ADD INDEX idx_api_version_called_at (api_version, called_at)',
    'DO 0'
);

PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
