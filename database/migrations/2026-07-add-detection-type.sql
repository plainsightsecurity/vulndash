-- Adds host_detections.detection_type.
--
-- This column is almost certainly ALREADY PRESENT on the live server: the
-- hourly scripts/sync_host_detections.php has been writing it, and
-- VulnerabilityRepository/public/vulnerabilities.php read it to drive the
-- "Potential" chip, so its absence would have failed every sync run. It is
-- missing from database/schema.sql, which means schema.sql has drifted from
-- the live database rather than the database being behind - a fresh install
-- from schema.sql alone would break. This migration exists so that a rebuild
-- from schema.sql + migrations produces the column, and so nothing depends on
-- spotting the gap by eye.
--
-- Idempotent and safe to run either way: if the column is already there this
-- does nothing at all. Verified as a no-op on a database that already has it.
--
-- Values written are the normalised set from QualysApiClient's
-- normaliseDetectionType(): 'Confirmed' (Qualys <TYPE>Vuln</TYPE>),
-- 'Potential' (Practice) and 'Info' (Ig). VARCHAR rather than an ENUM because
-- that method deliberately passes an unrecognised value through unchanged
-- instead of discarding it, and an ENUM would turn a new Qualys type into a
-- write error on the hourly sync.
--
-- ALTER TABLE ... ADD COLUMN IF NOT EXISTS is MariaDB-only syntax and a hard
-- error on MySQL 8, so this uses the portable information_schema check +
-- PREPARE/EXECUTE idiom instead.

SET @col_exists := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'host_detections'
      AND COLUMN_NAME  = 'detection_type'
);

SET @ddl := IF(
    @col_exists = 0,
    'ALTER TABLE host_detections ADD COLUMN detection_type VARCHAR(16) NULL AFTER status',
    'DO 0'
);

PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
