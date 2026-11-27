-- Sample data for local testing / demoing the interface before Qualys API
-- access is available. Safe to run against a fresh database loaded from
-- install_schema.sql.
--
--   mysql -u root -p vulndash < install_schema.sql
--   mysql -u root -p vulndash < database/seed_sample_data.sql
--
-- This creates two test logins (see README.md "Test accounts" section for
-- both usernames):
--   admin        / ChangeMe123!   (is_admin = 1, sees everything)
--   acme_client  / ChangeMe123!   (scoped to the "Acme Corp - Production" tag only)
--
-- DELETE OR CHANGE THESE BEFORE THE APP IS EXPOSED ANYWHERE REAL.
-- The password hash below is a genuine bcrypt hash of "ChangeMe123!",
-- generated with PHP's password_hash(), not a placeholder.

SET NAMES utf8mb4;

-- ---------------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------------

INSERT INTO users (id, username, email, password_hash, is_admin, is_active) VALUES
    (1, 'admin',       'admin@plainsightsecurity.co.uk',      '$2y$10$/iHVIX9/y3Fo9KlsSn8U7eFg193LpAgZLIfp0TY2lk0fIRP48q9rW', 1, 1),
    (2, 'acme_client', 'security-contact@acmecorp.example',   '$2y$10$/iHVIX9/y3Fo9KlsSn8U7eFg193LpAgZLIfp0TY2lk0fIRP48q9rW', 0, 1);

-- ---------------------------------------------------------------------------
-- Tags (would normally be populated by a Qualys tag sync - see README)
-- ---------------------------------------------------------------------------

INSERT INTO tags (id, qualys_tag_id, name) VALUES
    (1, '1001', 'Acme Corp - Production'),
    (2, '2002', 'Beacon Retail - Stores'),
    (3, '3003', 'Plainsight Security - Internal');

INSERT INTO user_tags (user_id, tag_id) VALUES
    (2, 1); -- acme_client can only ever see assets tagged "Acme Corp - Production"

-- ---------------------------------------------------------------------------
-- KnowledgeBase sample - deliberately covers every CvssCalculator branch:
--   91001, 91002, 91008          -> real CVSS3/CVSS2 base score present
--   91003, 91005, 91006, 91009, 91010 -> no CVSS score, estimated from severity
-- ---------------------------------------------------------------------------

INSERT INTO knowledge_base
    (qid, title, severity_level, category, cvss_base, cvss3_base, cve_ids, patchable, pci_flag, solution, cached_at)
VALUES
    (91001, 'OpenSSL Multiple Vulnerabilities',                 5, 'General remote services', 9.30, 9.80, 'CVE-2024-0001',              1, 1, 'Upgrade OpenSSL to the latest stable release.', NOW()),
    (91002, 'Apache HTTP Server Denial of Service',             4, 'Web server',               7.80, NULL, 'CVE-2024-0002',              1, 1, 'Apply the vendor-supplied patch for this Apache release.', NOW()),
    (91003, 'Deprecated TLS 1.0/1.1 Protocol Supported',        4, 'General remote services',   NULL, NULL, NULL,                          0, 1, 'Disable TLS 1.0 and 1.1, allow TLS 1.2+ only.', NOW()),
    (91004, 'SSH Weak MAC Algorithms Supported',                3, 'General remote services',   NULL, 5.30, NULL,                          0, 0, 'Disable weak MAC algorithms in the SSH daemon configuration.', NOW()),
    (91005, 'Self-Signed SSL Certificate',                      3, 'General remote services',   NULL, NULL, NULL,                          0, 0, 'Replace the self-signed certificate with one from a trusted CA.', NOW()),
    (91006, 'ICMP Timestamp Request Response',                  1, 'General remote services',   NULL, NULL, NULL,                          0, 0, 'Disable ICMP timestamp responses at the host firewall if not required.', NOW()),
    (91007, 'Missing HttpOnly Flag on Session Cookie',          2, 'Web application',            NULL, 3.10, NULL,                          1, 0, 'Set the HttpOnly flag on all session cookies.', NOW()),
    (91008, 'Remote Code Execution in Legacy CMS Plugin',       5, 'Web application',            9.00, 9.10, 'CVE-2024-0008',              1, 1, 'Update or remove the affected plugin immediately.', NOW()),
    (91009, 'Outdated PHP Version Detected',                    4, 'Web application',            NULL, NULL, NULL,                          1, 1, 'Upgrade PHP to a currently supported version.', NOW()),
    (91010, 'Directory Listing Enabled',                        2, 'Web server',                 NULL, NULL, NULL,                          0, 0, 'Disable directory indexing in the web server configuration.', NOW());

-- ---------------------------------------------------------------------------
-- Assets
-- ---------------------------------------------------------------------------

INSERT INTO assets (id, qualys_host_id, hostname, ip_address, os, tracking_method, last_scan_date) VALUES
    (1, 500001, 'web01.acme.internal',        '10.10.1.10', 'Ubuntu 22.04 LTS', 'AGENT',   NOW()),
    (2, 500002, 'db01.acme.internal',         '10.10.1.11', 'Ubuntu 22.04 LTS', 'AGENT',   NOW()),
    (3, 500003, 'pos01.beacon.internal',      '10.20.5.5',  'Windows Server 2019', 'AGENT', NOW()),
    (4, 500004, 'fileserver.beacon.internal', '10.20.5.6',  'Windows Server 2016', 'AGENT', NOW()),
    (5, 500005, 'mgmt01.internal',            '10.0.0.5',   'Ubuntu 22.04 LTS', 'AGENT',   NOW());

INSERT INTO asset_tags (asset_id, tag_id) VALUES
    (1, 1), (2, 1),   -- Acme Corp - Production
    (3, 2), (4, 2),   -- Beacon Retail - Stores
    (5, 3);           -- Plainsight Security - Internal

-- ---------------------------------------------------------------------------
-- Host detections
--
-- effective_cvss_score / source / is_ce_plus_fail below mirror exactly what
-- scripts/sync_host_detections.php computes via CvssCalculator at ingest
-- time - they are not recalculated by the application at read time.
-- ---------------------------------------------------------------------------

INSERT INTO host_detections
    (asset_id, qid, status, port, protocol, is_ssl, first_found, last_found,
     effective_cvss_score, effective_cvss_source, is_ce_plus_fail)
VALUES
    -- web01.acme.internal
    (1, 91001, 'Active', 443, 'tcp', 1, '2026-05-01 09:00:00', '2026-07-01 09:00:00', 9.80, 'CVSS3', 1),
    (1, 91003, 'Active', 443, 'tcp', 1, '2026-05-01 09:00:00', '2026-07-01 09:00:00', 7.95, 'QUALYS_SEVERITY_ESTIMATE', 1),
    (1, 91007, 'Active', 80,  'tcp', 0, '2026-05-01 09:00:00', '2026-07-01 09:00:00', 3.10, 'CVSS3', 0),

    -- db01.acme.internal
    (2, 91002, 'Active', 3306, 'tcp', 0, '2026-04-15 09:00:00', '2026-07-01 09:00:00', 7.80, 'CVSS2', 1),
    (2, 91005, 'Active', 3306, 'tcp', 1, '2026-04-15 09:00:00', '2026-07-01 09:00:00', 5.45, 'QUALYS_SEVERITY_ESTIMATE', 0),
    (2, 91001, 'Fixed',  3306, 'tcp', 1, '2026-01-10 09:00:00', '2026-04-01 09:00:00', 9.80, 'CVSS3', 1),

    -- pos01.beacon.internal
    (3, 91008, 'New',    445, 'tcp', 0, '2026-07-01 09:00:00', '2026-07-01 09:00:00', 9.10, 'CVSS3', 1),
    (3, 91009, 'Active', 443, 'tcp', 1, '2026-03-01 09:00:00', '2026-07-01 09:00:00', 7.95, 'QUALYS_SEVERITY_ESTIMATE', 1),
    (3, 91010, 'Active', 80,  'tcp', 0, '2026-03-01 09:00:00', '2026-07-01 09:00:00', 2.00, 'QUALYS_SEVERITY_ESTIMATE', 0),

    -- fileserver.beacon.internal
    (4, 91004, 'Active',    22, 'tcp',  0, '2026-02-01 09:00:00', '2026-07-01 09:00:00', 5.30, 'CVSS3', 0),
    (4, 91006, 'Active',    0,  'icmp', 0, '2026-02-01 09:00:00', '2026-07-01 09:00:00', 0.00, 'QUALYS_SEVERITY_ESTIMATE', 0),
    (4, 91002, 'Re-Opened', 8080, 'tcp', 0, '2026-02-01 09:00:00', '2026-07-01 09:00:00', 7.80, 'CVSS2', 1),

    -- mgmt01.internal
    (5, 91001, 'Active', 443,  'tcp', 1, '2026-06-01 09:00:00', '2026-07-01 09:00:00', 9.80, 'CVSS3', 1),
    (5, 91008, 'Active', 3389, 'tcp', 0, '2026-06-01 09:00:00', '2026-07-01 09:00:00', 9.10, 'CVSS3', 1);
