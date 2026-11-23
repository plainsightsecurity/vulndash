-- ---------------------------------------------------------------------------
-- 2026-11: qualys_tag_rules - how each Qualys tag is built, cached locally
--
-- Tag scoping is per host, so any tag Qualys puts on an agent host scopes ALL
-- of that host's findings. Asset-group and IP-range tags land on agent hosts
-- purely because the host's IP matches - an asset group made for an external
-- scan ("FaiceTech Ce Ext 2026") ended up showing those servers' internal
-- agent findings. Host List Detection's <TAGS> gives only id and name, so the
-- rule type comes from the Asset Management Search Tags endpoint
-- (POST /qps/rest/2.0/search/am/tag) and is cached here, one row per Qualys
-- tag id, by src/Lib/TagScopeClassifier.php. HostSyncWriter then keeps
-- IP-based tags - and any tag not yet classified - out of asset_tags.
--
-- Keyed by Qualys tag id rather than tags.id: an IP-based tag never gets a
-- tags row at all (it is dropped before resolution), and a classification
-- is about the Qualys object, so it outlives any local tags row.
--
-- found = 0: Qualys didn't return the tag when asked (deleted, or outside
-- the API user's scope). Treated as unclassified - it scopes nothing - and
-- asked about again once checked_at is older than
-- qualys.tag_rule_refresh_hours.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS, safe to run more than once.
-- Additive only - nothing existing is altered.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS qualys_tag_rules (
    qualys_tag_id       VARCHAR(191) NOT NULL,
    tag_name            VARCHAR(255) NULL,
    rule_type           VARCHAR(64) NULL,
    src_asset_group_id  BIGINT UNSIGNED NULL,
    found               TINYINT(1) NOT NULL,
    is_ip_based         TINYINT(1) NOT NULL DEFAULT 0,
    checked_at          DATETIME NOT NULL,
    PRIMARY KEY (qualys_tag_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
