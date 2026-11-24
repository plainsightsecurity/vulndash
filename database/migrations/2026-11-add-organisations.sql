-- ---------------------------------------------------------------------------
-- 2026-11: client organisations
--
-- organisations         one row per client: name, active flag, and max_users
--                       (how many ACTIVE accounts the organisation may have;
--                       organisation admins can't invite or reactivate past
--                       it - Plainsight admins can. NULL = no limit).
-- organisation_tags     the tags every member of the organisation sees.
-- users.organisation_id the account's organisation (NULL = none, as every
--                       account is until an admin assigns one - nothing
--                       changes for existing users on deploy).
-- users.is_org_admin    may manage their own organisation's users from
--                       /org/users (invite, deactivate, reactivate, resend
--                       a setup link) within max_users. Nothing else.
--
-- A member's access = their own user_tags (optional extras) + their active
-- organisation's tags; see UserRepository::EFFECTIVE_TAGS_SQL. A suspended
-- organisation (is_active = 0) contributes no tags and its members cannot
-- sign in, and are signed out on their next request.
--
-- Deleting an organisation leaves its users in place with organisation_id
-- NULL (ON DELETE SET NULL): they keep only their own extra tags.
--
-- Idempotent: safe to run more than once. Uses information_schema + PREPARE
-- rather than ADD COLUMN IF NOT EXISTS, which is MariaDB-only.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS `organisations` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(191) NOT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `max_users` int unsigned DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_organisations_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `organisation_tags` (
  `organisation_id` int unsigned NOT NULL,
  `tag_id` int unsigned NOT NULL,
  PRIMARY KEY (`organisation_id`,`tag_id`),
  KEY `fk_organisation_tags_tag` (`tag_id`),
  CONSTRAINT `fk_organisation_tags_org` FOREIGN KEY (`organisation_id`) REFERENCES `organisations` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_organisation_tags_tag` FOREIGN KEY (`tag_id`) REFERENCES `tags` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- users.organisation_id
SET @col_exists := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'organisation_id'
);
SET @sql := IF(@col_exists = 0,
    'ALTER TABLE users ADD COLUMN organisation_id int unsigned DEFAULT NULL AFTER kev_alert_baseline_at',
    'DO 0');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- users.is_org_admin
SET @col_exists := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'is_org_admin'
);
SET @sql := IF(@col_exists = 0,
    'ALTER TABLE users ADD COLUMN is_org_admin tinyint(1) NOT NULL DEFAULT ''0'' AFTER organisation_id',
    'DO 0');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- users -> organisations foreign key
SET @fk_exists := (
    SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'
      AND CONSTRAINT_NAME = 'fk_users_organisation' AND CONSTRAINT_TYPE = 'FOREIGN KEY'
);
SET @sql := IF(@fk_exists = 0,
    'ALTER TABLE users ADD CONSTRAINT fk_users_organisation FOREIGN KEY (organisation_id) REFERENCES organisations (id) ON DELETE SET NULL',
    'DO 0');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
