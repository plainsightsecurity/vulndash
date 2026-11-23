-- Detection resolutions: capture CVSS at resolution time (2026-07)
-- ---------------------------------------------------------------------------
-- Adds effective_cvss_score to the detection_resolutions tombstone so the
-- Trends "Recently resolved" list can show each resolved finding's severity.
--
-- Why it's stored rather than looked up: the effective CVSS score is a
-- per-detection value on host_detections (CVSS3 > CVSS2 > Qualys-severity
-- estimate, resolved at ingest by CvssCalculator - see VulnerabilityRepository's
-- class docblock). Once a detection is remediated its host_detections row is
-- DELETED, so that score is gone; capturing it into the tombstone at deletion
-- time preserves the exact severity the finding had, rather than falling back to
-- the raw knowledge_base CVSS (which is NULL for QIDs scored only by CVSS2 or a
-- Qualys estimate). The "Resolved" movement COUNT doesn't need it - only the
-- list, to show a severity badge and to order most-severe-first within a day.
--
-- NULL means "resolved before this column existed" (a tombstone written by an
-- earlier version) - such rows simply don't appear in the severity-filtered
-- "Recently resolved" list, which is fine; they still count toward the Resolved
-- total and age out of the table via the normal retention prune.
--
-- Apply once, after 2026-07-add-detection-resolutions.sql:
--   mysql -u root -p vulndash < database/migrations/2026-07-add-resolution-cvss.sql
--
-- Written for MySQL 8. The column is added behind an information_schema check
-- (rather than "ADD COLUMN IF NOT EXISTS", which isn't valid on MySQL 8) so this
-- migration is safely re-runnable.

SET @col_exists := (
    SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name   = 'detection_resolutions'
      AND column_name  = 'effective_cvss_score'
);
SET @ddl := IF(@col_exists = 0,
    'ALTER TABLE detection_resolutions ADD COLUMN effective_cvss_score DECIMAL(3,1) NULL AFTER qid',
    'DO 0'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
