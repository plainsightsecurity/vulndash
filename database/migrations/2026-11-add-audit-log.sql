-- ---------------------------------------------------------------------------
-- 2026-11: audit_log - who did what, for the admin Audit Log page
-- (public/admin/audit_log.php). Written by src/Lib/AuditLog.php.
--
-- Covers sign-ins (and failures, lockouts, MFA), account security changes,
-- every admin action on users and tags, hiding/unhiding findings, scan and
-- agent-uninstall requests, custom remediation edits, CE+ assessment dates
-- and report exports.
--
-- user_id has no foreign key on purpose: the row must outlive a deleted
-- account, so the actor's username is copied into the row as well. Rows
-- older than audit.retention_days (default 365) are pruned automatically.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS, safe to run more than once.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS audit_log (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    occurred_at   DATETIME NOT NULL,
    user_id       INT UNSIGNED NULL,
    username      VARCHAR(255) NULL,
    action        VARCHAR(64) NOT NULL,
    target_type   VARCHAR(32) NULL,
    target_id     VARCHAR(64) NULL,
    target_label  VARCHAR(255) NULL,
    details       JSON NULL,
    ip_address    VARCHAR(45) NULL,
    PRIMARY KEY (id),
    KEY idx_audit_log_occurred (occurred_at),
    KEY idx_audit_log_user (user_id, occurred_at),
    KEY idx_audit_log_action (action, occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
