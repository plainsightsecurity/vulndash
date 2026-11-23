-- Vulnerability Management Dashboard - core schema
-- Target: MySQL 8.0+ / MariaDB 10.5+, InnoDB, utf8mb4
--
-- Run this once to create the database structure:
--   mysql -u root -p vulndash < database/schema.sql
--
-- See README.md for the full setup sequence (creating the DB/user first).

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ---------------------------------------------------------------------------
-- Accounts
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS users (
    id                     INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username               VARCHAR(64)  NOT NULL,
    email                  VARCHAR(255) NOT NULL,
    password_hash          VARCHAR(255) NOT NULL,
    is_admin               TINYINT(1)   NOT NULL DEFAULT 0,
    is_active              TINYINT(1)   NOT NULL DEFAULT 1,
    failed_login_attempts  INT UNSIGNED NOT NULL DEFAULT 0,
    locked_until           DATETIME     NULL,
    last_login_at          DATETIME     NULL,

    -- Server-side session-invalidation counter. Every logged-in session
    -- snapshots this value at login (Auth::finalizeLogin()); Auth::check()
    -- re-reads it each request and signs the session out if it no longer
    -- matches. UserRepository::resetPassword() increments it on any password
    -- change, so a password change logs out every OTHER session for the
    -- account (the one that made a self-service change re-seeds its own copy
    -- and stays in). Trusted-device grants are unaffected. See
    -- database/migrations/2026-07-add-session-epoch-and-login-throttle.sql.
    session_epoch          INT UNSIGNED NOT NULL DEFAULT 0,

    -- Optional "land on this tag at login" preference (self-service, set on
    -- public/preferences.php). Auth::finalizeLogin() seeds the per-session
    -- view-tag filter from this; NULL = start on "All tags" as before. See
    -- database/migrations/2026-07-add-user-default-tag.sql for the full
    -- rationale and why it's ON DELETE SET NULL.
    default_tag_id          INT UNSIGNED    NULL,

    -- Opt-in "new activity" email notifications (self-service, set on
    -- public/preferences.php; sent by scripts/send_notifications.php). See
    -- database/migrations/2026-07-add-notification-preferences.sql for the full
    -- rationale. notify_frequency is the opt-in itself ('off' by default, so no
    -- account is ever enrolled without choosing). notify_watermark_id is the
    -- high-water mark of host_detections.id at the last notification - "new
    -- since" is just "scope has a detection with a higher id"; seeded to the
    -- current MAX(id) when an account first opts in, so opting in never nudges
    -- about the pre-existing backlog. notify_last_sent_at is the cadence gate +
    -- audit, advanced only when an email is actually sent. The emails carry NO
    -- vulnerability detail - only a prompt to sign in - so nothing sensitive
    -- ever crosses the (unencrypted-at-rest) email channel.
    notify_frequency        ENUM('off','daily','weekly') NOT NULL DEFAULT 'off',
    notify_watermark_id     BIGINT UNSIGNED NULL,
    notify_last_sent_at     DATETIME        NULL,

    -- TOTP multi-factor auth (see database/migrations/2026-07-add-mfa.sql
    -- for the full rationale behind each of these). mfa_enabled is the one
    -- flag everything else (login, admin UI) actually checks; the rest
    -- support the enroll/confirm flow, the encrypted-at-rest secret, and
    -- rate-limiting/replay protection for the 6-digit code itself.
    mfa_enabled             TINYINT(1)      NOT NULL DEFAULT 0,
    mfa_secret              VARCHAR(255)    NULL,
    mfa_confirmed_at        DATETIME        NULL,
    mfa_failed_attempts     INT UNSIGNED    NOT NULL DEFAULT 0,
    mfa_locked_until        DATETIME        NULL,
    mfa_last_used_counter   BIGINT UNSIGNED NULL,

    created_at             DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_users_username (username),
    UNIQUE KEY uq_users_email (email),
    -- References tags(id), created further down in this file - relies on the
    -- SET FOREIGN_KEY_CHECKS = 0 at the top of this script so table order
    -- here doesn't matter (same as the other cross-table FKs below).
    CONSTRAINT fk_users_default_tag FOREIGN KEY (default_tag_id) REFERENCES tags(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- "Trust this device" grants created at the MFA challenge step during
-- login (see public/mfa_verify.php) - lets a subsequent login from the
-- same browser skip the TOTP prompt for a while. Password is always still
-- required regardless; this only ever skips the second factor. See
-- database/migrations/2026-07-add-mfa.sql for the full selector/validator
-- rationale and src/Lib/TrustedDeviceRepository.php for how it's used.
CREATE TABLE IF NOT EXISTS user_trusted_devices (
    id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id       INT UNSIGNED NOT NULL,
    selector      CHAR(24)     NOT NULL,
    token_hash    CHAR(64)     NOT NULL,
    device_label  VARCHAR(255) NULL,
    ip_address    VARCHAR(45)  NULL,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at  DATETIME NULL,
    expires_at    DATETIME NOT NULL,
    revoked_at    DATETIME NULL,
    revoked_by    INT UNSIGNED NULL,
    UNIQUE KEY uq_trusted_devices_selector (selector),
    CONSTRAINT fk_trusted_devices_user       FOREIGN KEY (user_id)    REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_trusted_devices_revoked_by FOREIGN KEY (revoked_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_trusted_devices_user (user_id),
    INDEX idx_trusted_devices_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- One row per outstanding "set your password" link, sent via the Resend
-- API (see src/Lib/Mailer.php) - either because an admin just created the
-- account (purpose = 'setup') or because someone used "Forgot your
-- password?" on the login page (purpose = 'reset'). Both land on the same
-- public/reset_password.php page; purpose only changes which email copy
-- was sent. Same selector/validator split as user_trusted_devices above -
-- see database/migrations/2026-07-add-mfa.sql for the full rationale.
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id       INT UNSIGNED NOT NULL,
    selector      CHAR(24)     NOT NULL,
    token_hash    CHAR(64)     NOT NULL,
    purpose       ENUM('setup', 'reset') NOT NULL DEFAULT 'reset',
    requested_ip  VARCHAR(45)  NULL,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at    DATETIME NOT NULL,
    used_at       DATETIME NULL,
    UNIQUE KEY uq_password_reset_tokens_selector (selector),
    CONSTRAINT fk_password_reset_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_password_reset_tokens_user (user_id),
    INDEX idx_password_reset_tokens_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Per-IP failed-login rate limiting - the password-spraying backstop the
-- per-account lockout (users.failed_login_attempts / locked_until) can't
-- provide. One row per failed password attempt (recorded even for a
-- non-existent username so it can't be evaded), counted within a sliding
-- window by LoginThrottleRepository; a successful login clears the IP's rows,
-- and rows past the window are pruned opportunistically. ip_address is the
-- REMOTE_ADDR value only - X-Forwarded-For is never trusted (it's
-- attacker-settable). See
-- database/migrations/2026-07-add-session-epoch-and-login-throttle.sql.
CREATE TABLE IF NOT EXISTS login_throttle (
    id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address    VARCHAR(45) NOT NULL,
    attempted_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_login_throttle_ip_time (ip_address, attempted_at),
    INDEX idx_login_throttle_time (attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Qualys asset tags. A user is scoped to one or more tags; they can only see
-- assets (and therefore vulnerabilities) carrying at least one of their tags.
--
-- qualys_tag_id is deliberately a string, not a number: Qualys tag names are
-- alphanumeric (and may contain spaces), and some subscriptions scope by
-- Cloud Agent Activation ID instead (a UUID) rather than a named tag. This
-- column just needs to be whatever string value your Qualys data uses to
-- identify the group - `name` below is the separate, human-friendly label
-- shown in the dashboard UI, so an ugly UUID here doesn't have to be what
-- an admin sees when assigning tags to a user.
--
-- NULL qualys_tag_id = a "pending" tag: pre-created by name (so a client
-- account can be scoped to it) before any agent carrying it has reported,
-- with the numeric Qualys ID filled in automatically on first sight (see
-- database/migrations/2026-07-add-pending-tags.sql for the full rationale and
-- UserRepository::resolveSyncedTagId() for the promotion logic). The UNIQUE
-- key below still forbids two rows sharing a non-NULL id, while permitting
-- any number of pending (NULL) rows - MariaDB never treats NULLs as equal for
-- UNIQUE purposes. Pending rows are instead kept unique by NAME in
-- UserRepository::createTag() so promotion can only ever match one.
CREATE TABLE IF NOT EXISTS tags (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    qualys_tag_id   VARCHAR(191) NULL,
    name            VARCHAR(255)    NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_tags_qualys_tag_id (qualys_tag_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_tags (
    user_id  INT UNSIGNED NOT NULL,
    tag_id   INT UNSIGNED NOT NULL,
    PRIMARY KEY (user_id, tag_id),
    CONSTRAINT fk_user_tags_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_tags_tag  FOREIGN KEY (tag_id)  REFERENCES tags(id)  ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Assets and their Qualys tag associations
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS assets (
    id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    qualys_host_id    BIGINT UNSIGNED NOT NULL,
    qualys_asset_id   BIGINT UNSIGNED NULL,
    hostname          VARCHAR(255) NULL,
    ip_address        VARCHAR(45)  NULL,
    dns_name          VARCHAR(255) NULL,
    os                VARCHAR(255) NULL,
    tracking_method   VARCHAR(20)  NULL,
    last_scan_date    DATETIME NULL,
    is_active         TINYINT(1) NOT NULL DEFAULT 1,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_assets_qualys_host_id (qualys_host_id),
    INDEX idx_assets_ip (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS asset_tags (
    asset_id  INT UNSIGNED NOT NULL,
    tag_id    INT UNSIGNED NOT NULL,
    PRIMARY KEY (asset_id, tag_id),
    CONSTRAINT fk_asset_tags_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    CONSTRAINT fk_asset_tags_tag   FOREIGN KEY (tag_id)   REFERENCES tags(id)   ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Qualys KnowledgeBase cache (qid is the Qualys primary key)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS knowledge_base (
    qid                    INT UNSIGNED PRIMARY KEY,
    title                  VARCHAR(500) NOT NULL,
    severity_level         TINYINT UNSIGNED NOT NULL,   -- Qualys 1 (Informational) - 5 (Critical)
    category               VARCHAR(100) NULL,
    cvss_base              DECIMAL(3,1) NULL,           -- CVSS v2 base score, if published
    cvss_vector            VARCHAR(255) NULL,
    cvss3_base             DECIMAL(3,1) NULL,           -- CVSS v3(.1) base score, if published
    cvss3_vector           VARCHAR(255) NULL,
    cve_ids                TEXT NULL,                   -- comma-separated CVE identifiers
    vendor_reference       TEXT NULL,
    patchable              TINYINT(1) NOT NULL DEFAULT 0,
    pci_flag               TINYINT(1) NOT NULL DEFAULT 0,
    diagnosis              MEDIUMTEXT NULL,
    consequence            MEDIUMTEXT NULL,
    solution               MEDIUMTEXT NULL,
    published_datetime     DATETIME NULL,
    qualys_last_modified   DATETIME NULL,
    cached_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_kb_severity (severity_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Admin-authored remediation override, per QID. When a row exists here for a
-- QID, the vulnerability detail page shows this text instead of Qualys's
-- knowledge_base.solution, for every detection of that QID and every account
-- that can see it. Kept separate from knowledge_base (rather than a column on
-- it) so the KnowledgeBase sync can never clobber it, and so "revert to the
-- Qualys-supplied remediation" is simply deleting the row - the original
-- solution was never touched. See
-- database/migrations/2026-07-add-custom-remediation.sql for the full
-- rationale and src/Lib/CustomRemediationRepository.php for how it's used.
CREATE TABLE IF NOT EXISTS custom_remediations (
    qid          INT UNSIGNED PRIMARY KEY,
    remediation  MEDIUMTEXT NOT NULL,
    updated_by   INT UNSIGNED NULL,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_custom_remediation_qid  FOREIGN KEY (qid)        REFERENCES knowledge_base(qid) ON DELETE CASCADE,
    CONSTRAINT fk_custom_remediation_user FOREIGN KEY (updated_by) REFERENCES users(id)           ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Per-asset vulnerability detections
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS host_detections (
    id                       BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    asset_id                 INT UNSIGNED NOT NULL,
    qid                      INT UNSIGNED NOT NULL,
    status                   ENUM('New','Active','Fixed','Re-Opened') NOT NULL DEFAULT 'Active',
    port                     INT UNSIGNED NULL,

    -- MySQL/MariaDB never treats two NULLs as equal for UNIQUE purposes,
    -- so a plain UNIQUE KEY on (asset_id, qid, port) fails to dedupe any
    -- detection with no port at all - common for OS/registry-based checks
    -- (as opposed to network-service detections - see the PORT/PROTOCOL
    -- comment in scripts/lib/QualysApiClient.php's parseHostDetectionFile())
    -- - every sync run would insert a brand new row for these instead of
    -- updating the existing one. This generated column substitutes a
    -- fixed sentinel (the max UNSIGNED INT value - safely outside any
    -- real port number, and higher than the ICMP-style "port 0" already
    -- used for some detections) for NULL, purely so the unique key below
    -- has something to actually compare; `port` itself is untouched and
    -- still NULL exactly when Qualys reported none.
    port_dedup_key            INT UNSIGNED GENERATED ALWAYS AS (COALESCE(port, 4294967295)) STORED,

    protocol                 VARCHAR(10) NULL,
    is_ssl                   TINYINT(1) NOT NULL DEFAULT 0,
    first_found              DATETIME NULL,
    last_found               DATETIME NULL,
    last_fixed               DATETIME NULL,
    times_found              INT UNSIGNED NOT NULL DEFAULT 1,

    -- Cached at ingest time by src/Lib/CvssCalculator.php so dashboard/list
    -- queries never need to recompute this on the fly. See that class for
    -- the exact precedence: CVSS3 base -> CVSS2 base -> severity estimate.
    effective_cvss_score     DECIMAL(3,1) NULL,
    effective_cvss_source    ENUM('CVSS3','CVSS2','QUALYS_SEVERITY_ESTIMATE') NULL,
    is_ce_plus_fail          TINYINT(1) NOT NULL DEFAULT 0,   -- effective_cvss_score >= 7.0

    results                  TEXT NULL,
    created_at               DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uq_host_detections_asset_qid_portdedup (asset_id, qid, port_dedup_key),
    CONSTRAINT fk_detections_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    CONSTRAINT fk_detections_qid   FOREIGN KEY (qid)      REFERENCES knowledge_base(qid),
    INDEX idx_detections_status (status),
    INDEX idx_detections_ce_plus (is_ce_plus_fail),
    INDEX idx_detections_qid (qid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Sync history / observability for the two cron jobs
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sync_log (
    id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    sync_type           ENUM('knowledge_base','host_detections','exploit_intel','notifications') NOT NULL,
    started_at          DATETIME NOT NULL,
    completed_at        DATETIME NULL,
    status              ENUM('running','success','failed') NOT NULL DEFAULT 'running',
    records_processed   INT UNSIGNED NOT NULL DEFAULT 0,
    error_message        TEXT NULL,
    INDEX idx_sync_log_type_started (sync_type, started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Small persistent key-value store for cross-run sync state that doesn't
-- fit sync_log's one-row-per-run history model - currently just the
-- KnowledgeBase backfill cursor (see scripts/sync_knowledge_base.php).
-- Qualys's global KnowledgeBase is too large to pull in one API call in
-- practice, and the endpoint has no built-in pagination, so the initial
-- backfill runs as a bounded date-range chunk per script invocation
-- (single API call), resuming from here each time until caught up.
CREATE TABLE IF NOT EXISTS sync_state (
    sync_type    VARCHAR(50) NOT NULL PRIMARY KEY,
    state_json   TEXT NULL,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Daily per-asset open-detection rollup, for the dashboard's "vulnerability
-- posture" trend line - see database/migrations/2026-07-add-asset-vuln-snapshot.sql
-- for the full rationale (why this exists instead of reconstructing history
-- from first_found/last_fixed, and why it's per-asset rather than per-tag).
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS asset_vuln_snapshot (
    snapshot_date DATE NOT NULL,
    asset_id      INT UNSIGNED NOT NULL,
    open_count    INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (snapshot_date, asset_id),
    CONSTRAINT fk_snapshot_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    INDEX idx_snapshot_asset_date (asset_id, snapshot_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Every physical HTTP call this app makes to Qualys, one row per call - for
-- the admin-only API usage page. See
-- database/migrations/2026-07-add-qualys-api-call-log.sql for the full
-- rationale.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS qualys_api_call_log (
    id                    BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    endpoint              VARCHAR(255) NOT NULL,
    called_at             DATETIME NOT NULL,
    http_status           SMALLINT UNSIGNED NULL,
    duration_sec          DECIMAL(8,2) NULL,
    response_bytes        INT UNSIGNED NULL,
    rate_limit_remaining  INT UNSIGNED NULL,
    rate_limit_limit      INT UNSIGNED NULL,
    INDEX idx_endpoint_called_at (endpoint, called_at),
    INDEX idx_called_at (called_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Exploitability intelligence: CISA KEV + FIRST EPSS. See
-- database/migrations/2026-07-add-exploit-intel.sql for the full design. In
-- short: cisa_kev / epss_scores are per-CVE source feeds refreshed wholesale
-- by scripts/sync_exploit_intel.php; kb_cve normalises knowledge_base.cve_ids
-- into (qid, cve) pairs; qid_exploit is the per-QID rollup the dashboard reads
-- via a single LEFT JOIN (no read-time aggregation), rebuilt transactionally
-- each run. Kept in their own tables (not columns on knowledge_base) because
-- the KnowledgeBase sync rewrites knowledge_base rows wholesale.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS cisa_kev (
    cve                 VARCHAR(30) NOT NULL PRIMARY KEY,
    vendor_project      VARCHAR(255) NULL,
    product             VARCHAR(255) NULL,
    vulnerability_name  VARCHAR(512) NULL,
    date_added          DATE NULL,
    due_date            DATE NULL,
    known_ransomware    TINYINT(1) NOT NULL DEFAULT 0,
    notes               MEDIUMTEXT NULL,
    synced_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS epss_scores (
    cve         VARCHAR(30) NOT NULL PRIMARY KEY,
    epss        DECIMAL(6,5) NOT NULL,
    percentile  DECIMAL(6,5) NOT NULL,
    score_date  DATE NULL,
    synced_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_epss_epss (epss)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS kb_cve (
    qid  INT UNSIGNED NOT NULL,
    cve  VARCHAR(30)  NOT NULL,
    PRIMARY KEY (qid, cve),
    INDEX idx_kb_cve_cve (cve),
    CONSTRAINT fk_kb_cve_qid FOREIGN KEY (qid) REFERENCES knowledge_base(qid) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS qid_exploit (
    qid                  INT UNSIGNED NOT NULL PRIMARY KEY,
    is_kev               TINYINT(1) NOT NULL DEFAULT 0,
    kev_cve              VARCHAR(30) NULL,
    kev_date_added       DATE NULL,
    kev_due_date         DATE NULL,
    kev_ransomware       TINYINT(1) NOT NULL DEFAULT 0,
    max_epss             DECIMAL(6,5) NULL,
    max_epss_percentile  DECIMAL(6,5) NULL,
    cve_count            INT UNSIGNED NOT NULL DEFAULT 0,
    computed_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_qid_exploit_kev (is_kev),
    INDEX idx_qid_exploit_epss (max_epss),
    CONSTRAINT fk_qid_exploit_qid FOREIGN KEY (qid) REFERENCES knowledge_base(qid) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Remediation tombstones - see database/migrations/2026-07-add-detection-resolutions.sql
-- for the full rationale. Remediation on this agent-only platform is recorded
-- by DELETING a no-longer-reported detection (not a status='Fixed' update), so
-- the sync writes one small row here per deletion and getMovementCounts() reads
-- "Resolved" from these rows. Append-only and pruned every sync run
-- (sync.resolution_retention_days, default 90), so it stays small.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS detection_resolutions (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    asset_id     INT UNSIGNED NOT NULL,
    qid          INT UNSIGNED NOT NULL,
    -- The finding's effective CVSS score, captured at resolution time (the
    -- host_detections row is deleted, so it can't be looked up afterwards) -
    -- lets the "Recently resolved" list show severity. NULL for tombstones
    -- written before this column existed. See
    -- database/migrations/2026-07-add-resolution-cvss.sql.
    effective_cvss_score DECIMAL(3,1) NULL,
    resolved_at  DATETIME NOT NULL,
    INDEX idx_res_asset_date (asset_id, resolved_at),
    INDEX idx_res_date (resolved_at),
    CONSTRAINT fk_res_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS = 1;
