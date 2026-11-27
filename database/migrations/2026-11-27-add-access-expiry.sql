-- ---------------------------------------------------------------------------
-- 2026-11-27: optional access end date ("Access until") on organisations and
-- on individual accounts - for clients whose service runs for the validity
-- of a CE+ certificate. See src/Lib/AccessExpiry.php.
--
-- The date is the LAST day of access, inclusive: an account with
-- expires_on = 2027-03-01 can sign in all of 1 March and is refused from
-- 2 March. A member of an organisation gets the earlier of the two dates.
-- NULL (the default, so every existing row) = no end date. Admin accounts
-- never expire. Changing or clearing the date restores access immediately.
--
-- Purely additive (two nullable columns). Idempotent: each column is added
-- behind an information_schema check, since MySQL 8 has no
-- ADD COLUMN IF NOT EXISTS. Apply with scripts/migrate.php.
-- ---------------------------------------------------------------------------

SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'organisations' AND column_name = 'expires_on');
SET @s := IF(@c = 0,
    'ALTER TABLE organisations ADD COLUMN expires_on DATE NULL DEFAULT NULL AFTER is_active',
    'SELECT ''organisations.expires_on already exists''');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'expires_on');
SET @s := IF(@c = 0,
    'ALTER TABLE users ADD COLUMN expires_on DATE NULL DEFAULT NULL AFTER is_active',
    'SELECT ''users.expires_on already exists''');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
