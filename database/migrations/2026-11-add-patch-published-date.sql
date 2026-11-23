-- ---------------------------------------------------------------------------
-- 2026-11: knowledge_base.patch_published_date
--
-- Qualys's KnowledgeBase API returns PATCH_PUBLISHED_DATE - when the vendor
-- released the fix - for patchable QIDs (confirmed 2026-11-04 with
-- scripts/diagnose_kb_raw.php against five live QIDs: present on all four
-- patchable ones, absent on the one with PATCHABLE 0). The CE+ 14-day patch
-- clock (src/Lib/CePlusDeadline.php) counts from it, because the QID's own
-- published date can be years later than the patch: two of those Python
-- QIDs were published by Qualys in June 2026 for a patch released April 2023.
--
-- Nullable, no default: NULL means "not captured yet" (filled by the KB
-- sync as Qualys modifies each QID, or at once by
-- scripts/backfill_patch_published_date.php) or "Qualys has no patch date".
-- Stored in UTC like published_datetime (see QualysApiClient::toMysqlDatetime()).
--
-- Run scripts/diagnose_patch_published_date_migration.php first.
-- Idempotent: safe to run more than once. Uses information_schema +
-- PREPARE rather than ADD COLUMN IF NOT EXISTS, which is MariaDB-only.
-- ---------------------------------------------------------------------------

SET @col_exists := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'knowledge_base'
      AND COLUMN_NAME = 'patch_published_date'
);

SET @sql := IF(
    @col_exists = 0,
    'ALTER TABLE knowledge_base ADD COLUMN patch_published_date DATETIME NULL DEFAULT NULL AFTER published_datetime',
    'SELECT ''knowledge_base.patch_published_date already exists - nothing to do'' AS note'
);

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
