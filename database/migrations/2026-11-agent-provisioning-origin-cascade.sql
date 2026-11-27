-- ---------------------------------------------------------------------------
-- 2026-11: agent_provisioning - bring a first-version table up to date
--
-- 2026-11-add-agent-provisioning.sql was changed after its first version had
-- already been run on the live server, and CREATE TABLE IF NOT EXISTS leaves
-- an existing table alone. This makes a first-version table match the current
-- one; on a table already created by the current file it does nothing.
--
--   1. origin column (created / existing_tag / linked) - how each set-up
--      came about. Existing rows were all made by the page, so 'created'
--      is right for them.
--   2. organisation_id NOT NULL, and its foreign key ON DELETE CASCADE (was
--      SET NULL): deleting an organisation deletes its set-up row, so a
--      name is never retired. The foreign key has to be dropped first -
--      MySQL won't make a SET NULL column NOT NULL - then re-added.
--
-- If any row already has a NULL organisation_id (an organisation deleted
-- after its set-up), step 2 fails with "Invalid use of NULL value" and
-- changes nothing - run scripts/diagnose_agent_provisioning_migration.php,
-- which lists them, and decide what to do with them first.
--
-- Idempotent: safe to run more than once. Uses information_schema + PREPARE
-- rather than ADD COLUMN IF NOT EXISTS, which is MariaDB-only.
-- ---------------------------------------------------------------------------

-- 1. origin
SET @col_exists := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'agent_provisioning' AND COLUMN_NAME = 'origin'
);
SET @sql := IF(
    @col_exists = 0,
    'ALTER TABLE agent_provisioning ADD COLUMN origin ENUM(''created'',''existing_tag'',''linked'') NOT NULL DEFAULT ''created'' AFTER status',
    'SELECT ''agent_provisioning.origin already exists - nothing to do'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 2. organisation_id NOT NULL + ON DELETE CASCADE. A missing foreign key
-- (a run interrupted between the two ALTERs below) also counts as needing
-- the fix, so a re-run finishes the job.
SET @fk_exists := (
    SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = 'agent_provisioning' AND CONSTRAINT_NAME = 'fk_agent_prov_org'
);
SET @needs_fix := (1 - @fk_exists) + (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'agent_provisioning'
      AND COLUMN_NAME = 'organisation_id' AND IS_NULLABLE = 'YES'
) + (
    SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = 'agent_provisioning'
      AND CONSTRAINT_NAME = 'fk_agent_prov_org' AND DELETE_RULE <> 'CASCADE'
);

SET @sql := IF(
    @needs_fix > 0,
    IF(@fk_exists > 0,
       'ALTER TABLE agent_provisioning DROP FOREIGN KEY fk_agent_prov_org, MODIFY organisation_id INT UNSIGNED NOT NULL',
       'ALTER TABLE agent_provisioning MODIFY organisation_id INT UNSIGNED NOT NULL'),
    'SELECT ''agent_provisioning.organisation_id already NOT NULL with ON DELETE CASCADE - nothing to do'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := IF(
    @needs_fix > 0,
    'ALTER TABLE agent_provisioning ADD CONSTRAINT fk_agent_prov_org FOREIGN KEY (organisation_id) REFERENCES organisations (id) ON DELETE CASCADE',
    'SELECT ''fk_agent_prov_org already ON DELETE CASCADE - nothing to do'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
