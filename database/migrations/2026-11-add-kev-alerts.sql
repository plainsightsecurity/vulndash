-- ---------------------------------------------------------------------------
-- 2026-11: new-KEV alert emails (scripts/send_kev_alerts.php)
--
-- An account is emailed when a finding on the CISA Known Exploited
-- Vulnerabilities list newly appears in its scope - either a new detection
-- of a KEV-listed QID, or CISA adding an existing finding's CVE to the list.
--
-- users.kev_alerts            per-account on/off, set under Preferences.
--                             Defaults ON: unlike the opt-in activity digest,
--                             this only fires for confirmed-exploited issues,
--                             and the email carries no vulnerability detail.
-- users.kev_alert_baseline_at when the account's existing KEV findings were
--                             recorded without emailing. NULL = not yet: the
--                             next run records everything currently in scope
--                             silently, so turning this on (or creating an
--                             account) never sends a backlog email.
-- kev_alert_seen              (account, asset, QID) combinations already
--                             alerted or baselined. A row is removed once that
--                             finding is no longer open, so if it comes back
--                             later the account is alerted again.
--
-- Idempotent: safe to run more than once. Uses information_schema + PREPARE
-- rather than ADD COLUMN IF NOT EXISTS, which is MariaDB-only.
-- ---------------------------------------------------------------------------

SET @col_exists := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'kev_alerts'
);
SET @sql := IF(
    @col_exists = 0,
    'ALTER TABLE users ADD COLUMN kev_alerts TINYINT(1) NOT NULL DEFAULT 1',
    'SELECT ''users.kev_alerts already exists - nothing to do'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'kev_alert_baseline_at'
);
SET @sql := IF(
    @col_exists = 0,
    'ALTER TABLE users ADD COLUMN kev_alert_baseline_at DATETIME NULL DEFAULT NULL',
    'SELECT ''users.kev_alert_baseline_at already exists - nothing to do'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS kev_alert_seen (
    user_id     INT UNSIGNED NOT NULL,
    asset_id    INT UNSIGNED NOT NULL,
    qid         INT UNSIGNED NOT NULL,
    seen_at     DATETIME NOT NULL,
    PRIMARY KEY (user_id, asset_id, qid),
    KEY idx_kev_alert_seen_asset_qid (asset_id, qid),
    CONSTRAINT fk_kev_alert_seen_user  FOREIGN KEY (user_id)  REFERENCES users (id)  ON DELETE CASCADE,
    CONSTRAINT fk_kev_alert_seen_asset FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
