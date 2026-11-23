-- Rescopes hidden_issues from a single platform-wide hide (qid + optional
-- asset_id, visible to every account) to a per-account hide, additionally
-- narrowed by tag for the former "hide everywhere" case. See
-- src/Lib/HiddenIssueRepository.php's class docblock for the exact
-- semantics this enables, and VulnerabilityRepository::hiddenMatchWhere()
-- for how it's matched on every read.
--
-- BEFORE RUNNING: run scripts/diagnose_hidden_issues_migration.php against
-- this database and read its output. It lists every existing hidden_issues
-- row and which account it will be attributed to (hidden_by - the account
-- that actually set the rule). If any row has a NULL hidden_by (that
-- account has since been deleted), this migration will fail loudly at the
-- "make user_id NOT NULL" step below rather than silently dropping
-- anything - resolve those rows manually first (attribute them to a
-- specific account, or delete them) and re-run.
--
-- Idempotent: safe to run again against a database already migrated, using
-- the same information_schema-check + PREPARE/EXECUTE/DEALLOCATE idiom as
-- every other migration here (MySQL 8 has no ALTER TABLE ... IF NOT EXISTS).

-- Step 1: add the new columns, nullable for now - user_id is backfilled in
-- step 2 and only made NOT NULL in step 3, once nothing is left unattributed.
SET @col_exists := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'hidden_issues' AND COLUMN_NAME = 'user_id'
);
SET @sql := IF(@col_exists = 0,
    'ALTER TABLE hidden_issues ADD COLUMN user_id INT UNSIGNED NULL AFTER id',
    'DO 0'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'hidden_issues' AND COLUMN_NAME = 'tag_id'
);
SET @sql := IF(@col_exists = 0,
    'ALTER TABLE hidden_issues ADD COLUMN tag_id INT UNSIGNED NULL AFTER asset_scope',
    'DO 0'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'hidden_issues' AND COLUMN_NAME = 'tag_scope'
);
SET @sql := IF(@col_exists = 0,
    'ALTER TABLE hidden_issues ADD COLUMN tag_scope INT UNSIGNED GENERATED ALWAYS AS (COALESCE(tag_id,0)) STORED AFTER tag_id',
    'DO 0'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Step 2: backfill ownership from hidden_by (the account that actually
-- clicked "hide") for any row not yet attributed. A no-op once already run.
UPDATE hidden_issues SET user_id = hidden_by WHERE user_id IS NULL;

-- Step 3: everything past this point assumes no orphans remain (see the
-- note at the top of this file). If any row's hidden_by was NULL, user_id
-- is still NULL here and this statement fails with a NOT NULL violation -
-- that's deliberate; nothing below runs until it's resolved.
SET @col_nullable := (
    SELECT IS_NULLABLE FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'hidden_issues' AND COLUMN_NAME = 'user_id'
);
SET @sql := IF(@col_nullable = 'YES',
    'ALTER TABLE hidden_issues MODIFY COLUMN user_id INT UNSIGNED NOT NULL',
    'DO 0'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Step 4: swap the unique key from (qid, asset_scope) to
-- (user_id, qid, asset_scope, tag_scope) - the old key can't coexist with
-- more than one account holding a hide on the same QID/asset.
SET @new_key_exists := (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'hidden_issues'
      AND INDEX_NAME = 'uq_hidden_issue' AND COLUMN_NAME = 'user_id' AND SEQ_IN_INDEX = 1
);
SET @sql := IF(@new_key_exists = 0,
    'ALTER TABLE hidden_issues DROP KEY uq_hidden_issue, ADD UNIQUE KEY uq_hidden_issue (user_id, qid, asset_scope, tag_scope)',
    'DO 0'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Step 5: foreign key for user_id (there is deliberately no FK on tag_id -
-- InnoDB refuses a foreign key on a column that a generated column also
-- reads from, and tag_scope reads tag_id; asset_id has the same restriction
-- for the same reason in the original schema, which is why it was never
-- foreign-keyed either. tag_id/asset_id both keep a plain index for lookup
-- speed - see the idx_hidden_tag step below).
SET @fk_exists := (
    SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'hidden_issues' AND CONSTRAINT_NAME = 'fk_hidden_user_id'
);
SET @sql := IF(@fk_exists = 0,
    'ALTER TABLE hidden_issues ADD CONSTRAINT fk_hidden_user_id FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE',
    'DO 0'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Step 6: plain lookup index on tag_id (not a foreign key - see step 5).
SET @idx_exists := (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'hidden_issues' AND INDEX_NAME = 'idx_hidden_tag'
);
SET @sql := IF(@idx_exists = 0,
    'ALTER TABLE hidden_issues ADD KEY idx_hidden_tag (tag_id)',
    'DO 0'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
