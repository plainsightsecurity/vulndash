-- ---------------------------------------------------------------------------
-- 2026-11-27 (later the same evening): access end dates move from accounts
-- and organisations to TAGS, because an MSP account sees several clients'
-- tags and one client's CE+ lapsing mustn't lock the MSP out of the rest.
-- See src/Lib/AccessExpiry.php.
--
-- 1. Adds tags.expires_on: the last day (inclusive) that non-admin accounts
--    can see assets carrying the tag. NULL (the default) = no end date.
-- 2. Removes users.expires_on and organisations.expires_on, added by
--    2026-11-27-add-access-expiry.sql earlier the same day and no longer
--    used. Any date set in them is discarded.
--
-- Idempotent: every change is behind an information_schema check, since
-- MySQL 8 has no ADD/DROP COLUMN IF [NOT] EXISTS. Apply with
-- scripts/migrate.php.
-- ---------------------------------------------------------------------------

SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'tags' AND column_name = 'expires_on');
SET @s := IF(@c = 0,
    'ALTER TABLE tags ADD COLUMN expires_on DATE NULL DEFAULT NULL AFTER agent_activation_id',
    'SELECT ''tags.expires_on already exists''');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'expires_on');
SET @s := IF(@c = 1, 'ALTER TABLE users DROP COLUMN expires_on', 'SELECT ''users.expires_on already gone''');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'organisations' AND column_name = 'expires_on');
SET @s := IF(@c = 1, 'ALTER TABLE organisations DROP COLUMN expires_on', 'SELECT ''organisations.expires_on already gone''');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
