-- ---------------------------------------------------------------------------
-- 2026-11: tags.ce_assessment_date
--
-- The date a tag's CE+ assessment is booked for, set by an admin on the CE+
-- readiness page (public/ce_readiness.php). The page projects each host's
-- status forward to that date - which findings still inside the 14-day
-- patch window today will be overdue by then (see src/Lib/CePlusReadiness.php).
-- Stored per tag rather than per user (decision 2026-11-10) so every account
-- on a client's tag sees the same date.
--
-- On tags because tag rows are stable: the detection sync resolves tags in
-- place (UserRepository::resolveSyncedTagId()) and never re-creates them, so
-- a date set here survives every sync. Only scripts/reset_asset_data.php
-- --wipe-tags deletes tag rows, and that loses the date along with the
-- user_tags assignments.
--
-- DATE, not DATETIME: an assessment is booked for a day, and the page
-- treats it as a UK calendar day. Nullable, no default - NULL means "no
-- assessment booked", and the page then shows today's status only.
--
-- Run scripts/diagnose_tag_ce_assessment_date_migration.php first.
-- Idempotent: safe to run more than once. Uses information_schema + PREPARE
-- rather than ADD COLUMN IF NOT EXISTS, which is MariaDB-only.
-- ---------------------------------------------------------------------------

SET @col_exists := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'tags'
      AND COLUMN_NAME = 'ce_assessment_date'
);

SET @sql := IF(
    @col_exists = 0,
    'ALTER TABLE tags ADD COLUMN ce_assessment_date DATE NULL DEFAULT NULL AFTER name',
    'SELECT ''tags.ce_assessment_date already exists - nothing to do'' AS note'
);

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
