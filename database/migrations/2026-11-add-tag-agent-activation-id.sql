-- ---------------------------------------------------------------------------
-- 2026-11: tags.agent_activation_id
--
-- The Qualys Cloud Agent activation ID (a UUID) to install new agents with
-- for a tag, set by an admin in Manage Users > Tags. Accounts that can see
-- the tag get an "Install agent" button on the Assets page that shows the
-- Windows and macOS/Linux install commands with this ID filled in (see
-- src/Lib/AgentInstall.php).
--
-- Stored per tag, like ce_assessment_date, because tag rows are stable: the
-- detection sync resolves tags in place and never re-creates them, so the
-- ID survives every sync. Not unique - one activation key can apply several
-- tags, so more than one tag may legitimately share an ID.
--
-- CHAR(36): always the canonical lower-case 8-4-4-4-12 form; the admin page
-- normalises and validates before saving. NULL = no install command offered.
--
-- Idempotent: safe to run more than once. Uses information_schema + PREPARE
-- rather than ADD COLUMN IF NOT EXISTS, which is MariaDB-only.
-- ---------------------------------------------------------------------------

SET @col_exists := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'tags'
      AND COLUMN_NAME = 'agent_activation_id'
);

SET @sql := IF(
    @col_exists = 0,
    'ALTER TABLE tags ADD COLUMN agent_activation_id CHAR(36) NULL DEFAULT NULL AFTER ce_assessment_date',
    'SELECT ''tags.agent_activation_id already exists - nothing to do'' AS note'
);

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
