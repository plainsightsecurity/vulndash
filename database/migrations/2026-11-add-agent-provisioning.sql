-- ---------------------------------------------------------------------------
-- 2026-11: agent_provisioning - one Qualys agent tag + activation key per client
--
-- Admin > Agent Setup (public/admin/agent_setup.php, src/Lib/AgentProvisioner.php)
-- creates, for an organisation, a static Qualys tag (e.g.
-- Plainsight-Security-Agents) and a Cloud Agent activation key that applies
-- it, then a local tags row carrying the key's activation ID and the
-- organisation's link to it - so the Assets page's "Install agent" button
-- works for the organisation's members straight away.
--
-- One row per set-up. Each Qualys id is saved the moment Qualys returns it,
-- so a run that fails partway (or a lost response) is resumed by Retry from
-- the ids already held rather than creating a second tag or key.
--
-- Uniqueness is enforced here, not left to Qualys (which doesn't promise
-- unique tag names, and doesn't make key titles unique at all):
--   - organisation_id: one set-up per organisation. Deleting the
--     organisation deletes its set-up row (the tag and key stay in Qualys,
--     where the duplicate check still sees them) - a name is never retired
--     just for having been used.
--   - tag_name: the column's utf8mb4_0900_ai_ci collation compares
--     case-insensitively, so Acme-Agents and acme-agents can't both exist.
--   - qualys_tag_id, activation_key_id, activation_key, local_tag_id: no two
--     clients can share a tag or a key.
--
-- origin records how the set-up came about, for the page and the audit
-- trail: 'created' = this page made the tag and key; 'existing_tag' = the
-- admin chose an existing Qualys tag and this page made the key; 'linked' =
-- an existing tag and key recorded with Link existing. Delete removes the
-- key and tag whatever the origin, behind a typed confirmation.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS, safe to run more than once.
-- Additive only - nothing existing is altered.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS agent_provisioning (
    id                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
    organisation_id    INT UNSIGNED NOT NULL,
    tag_name           VARCHAR(191) NOT NULL,
    qualys_tag_id      BIGINT UNSIGNED NULL,
    activation_key_id  BIGINT UNSIGNED NULL,
    activation_key     CHAR(36) NULL,
    local_tag_id       INT UNSIGNED NULL,
    status             ENUM('in_progress','complete') NOT NULL DEFAULT 'in_progress',
    origin             ENUM('created','existing_tag','linked') NOT NULL DEFAULT 'created',
    last_error         TEXT NULL,
    created_by         INT UNSIGNED NULL,
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at       DATETIME NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_agent_prov_org (organisation_id),
    UNIQUE KEY uq_agent_prov_tag_name (tag_name),
    UNIQUE KEY uq_agent_prov_qualys_tag (qualys_tag_id),
    UNIQUE KEY uq_agent_prov_key_id (activation_key_id),
    UNIQUE KEY uq_agent_prov_key (activation_key),
    UNIQUE KEY uq_agent_prov_local_tag (local_tag_id),
    KEY fk_agent_prov_user (created_by),
    CONSTRAINT fk_agent_prov_org       FOREIGN KEY (organisation_id) REFERENCES organisations (id) ON DELETE CASCADE,
    CONSTRAINT fk_agent_prov_local_tag FOREIGN KEY (local_tag_id)    REFERENCES tags (id)          ON DELETE SET NULL,
    CONSTRAINT fk_agent_prov_user      FOREIGN KEY (created_by)      REFERENCES users (id)         ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
