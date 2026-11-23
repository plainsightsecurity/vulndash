-- Adds custom_remediations.content_format ('text' | 'html').
--
-- Custom remediation is moving from a plain <textarea> (stored as plain text,
-- shown escaped) to a CKEditor 5 rich-text editor (stored as sanitised HTML,
-- shown through Helpers::sanitizeVendorHtml() like Qualys's own solution).
-- Existing overrides are plain text; read as HTML they would lose every line
-- break and any literal "<" in them would be taken as markup. Recording the
-- format per row lets both coexist without converting anything here:
--
--   - every EXISTING row takes the column default, 'text', and keeps
--     displaying exactly as it does today;
--   - the editor loads a 'text' row converted to HTML, and saving it writes
--     the row back as 'html'.
--
-- So no existing remediation text is modified by this migration - only the
-- new column is added.
--
-- Run scripts/diagnose_custom_remediation_format.php first (read-only).
--
-- Idempotent: checks information_schema first and does nothing if already
-- applied. ALTER TABLE ... ADD COLUMN IF NOT EXISTS is MariaDB-only and a
-- hard error on MySQL 8, hence the PREPARE/EXECUTE idiom.
--
-- Deploy order: run this BEFORE overlaying the matching code. The new code
-- reads and writes this column; before it exists, opening the detail page of
-- a QID with an override, or saving one, fails with an unknown-column error.

SET @col_exists := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'custom_remediations'
      AND COLUMN_NAME  = 'content_format'
);

SET @ddl := IF(
    @col_exists = 0,
    'ALTER TABLE custom_remediations ADD COLUMN content_format ENUM(''text'',''html'') NOT NULL DEFAULT ''text'' AFTER remediation',
    'DO 0'
);

PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
