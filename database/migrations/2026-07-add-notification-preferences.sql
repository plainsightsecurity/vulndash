-- Migration: opt-in "new activity" email notifications
-- Target: MySQL 8.0 (production). Idempotent - safe to run more than once.
--
-- Adds the per-user opt-in notification preference and the state the daily
-- cron (scripts/send_notifications.php) needs to decide who to nudge, plus a
-- 'notifications' value on sync_log.sync_type so that cron's runs are logged
-- alongside the existing syncs.
--
-- Design (see scripts/send_notifications.php and src/Lib/NotificationRepository.php
-- for the full rationale):
--   * notify_frequency   - the opt-in itself. 'off' by default, so NO account
--                          is ever enrolled without explicitly choosing daily
--                          or weekly on public/preferences.php.
--   * notify_watermark_id - high-water mark of host_detections.id at the last
--                          notification. host_detections is UPSERTed on its
--                          unique key, so an existing row's id never changes;
--                          only genuinely new detection rows take a higher id.
--                          "Is there new activity since we last told them?" is
--                          therefore just "does their scope contain a detection
--                          with id > notify_watermark_id". Seeded to the current
--                          MAX(id) when an account first opts in, so opting in
--                          never nudges about the entire pre-existing backlog.
--   * notify_last_sent_at - cadence gate + audit. daily/weekly is enforced as a
--                          minimum spacing off this timestamp; only advanced when
--                          an email is actually sent (a run that finds nothing new
--                          leaves it untouched, so the account stays "due" and is
--                          nudged the moment something new does land).
--
-- MySQL 8 has no portable "ADD COLUMN IF NOT EXISTS" (that syntax is
-- MariaDB-only and is a hard error here), so each add is guarded by an
-- information_schema check + PREPARE/EXECUTE, and is a no-op on re-run.

-- --- users.notify_frequency ---------------------------------------------------
SET @exists := (
    SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'notify_frequency'
);
SET @ddl := IF(@exists = 0,
    "ALTER TABLE users ADD COLUMN notify_frequency ENUM('off','daily','weekly') NOT NULL DEFAULT 'off' AFTER default_tag_id",
    'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- --- users.notify_watermark_id ------------------------------------------------
SET @exists := (
    SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'notify_watermark_id'
);
SET @ddl := IF(@exists = 0,
    'ALTER TABLE users ADD COLUMN notify_watermark_id BIGINT UNSIGNED NULL AFTER notify_frequency',
    'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- --- users.notify_last_sent_at ------------------------------------------------
SET @exists := (
    SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'notify_last_sent_at'
);
SET @ddl := IF(@exists = 0,
    'ALTER TABLE users ADD COLUMN notify_last_sent_at DATETIME NULL AFTER notify_watermark_id',
    'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- --- sync_log.sync_type: add 'notifications' ----------------------------------
-- Re-running with the value already present is a harmless no-op MODIFY. Guarded
-- anyway so a re-run doesn't rewrite the column's definition needlessly.
SET @has := (
    SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'sync_log' AND column_name = 'sync_type'
      AND COLUMN_TYPE LIKE '%notifications%'
);
SET @ddl := IF(@has = 0,
    "ALTER TABLE sync_log MODIFY COLUMN sync_type ENUM('knowledge_base','host_detections','exploit_intel','notifications') NOT NULL",
    'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
