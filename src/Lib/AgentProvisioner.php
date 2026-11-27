<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Sets a client organisation up for Qualys Cloud Agents (Admin > Agent Setup,
 * table: database/migrations/2026-11-add-agent-provisioning.sql):
 *
 *   1. a static Qualys tag named for the client - <Name>-Agents by default
 *      (suggestTagName()), letters, numbers and hyphens only, no parent tag;
 *   2. an UNLIMITED activation key with the same title that applies that tag,
 *      so every agent installed with it lands in the client's scope;
 *   3. a local tags row for the tag carrying the key's activation ID, linked
 *      to the organisation - which is all the Assets page's "Install agent"
 *      button needs (AgentInstall), and the detection sync later matches
 *      the row by its Qualys id (UserRepository::resolveSyncedTagId()).
 *
 * One tag and one key per client, guaranteed here rather than by Qualys,
 * which doesn't promise unique tag names and allows any number of keys with
 * the same title:
 *   - before anything is created, Qualys is searched for a tag with the same
 *     name (case-insensitively); if one exists nothing is created and the
 *     admin chooses: use that tag (only if it's static and no other client
 *     has it) or cancel and pick another name. Every key is read the same
 *     way before one is created, and a same-titled key stops the set-up.
 *   - the agent_provisioning table's UNIQUE keys (organisation, name - case-
 *     insensitive by collation - Qualys tag id, key id, activation ID, local
 *     tag) stop two set-ups ever sharing anything, whatever the code does.
 *   - each Qualys id is saved the moment it comes back, so Retry after a
 *     failure resumes from what already exists instead of creating a second
 *     tag or key. A key whose create response was lost is recognised on
 *     retry by its title plus the client's own tag, which no other key can
 *     carry legitimately (the tag was created for this set-up).
 *
 * Calls (each its own 25-per-24h counter at Qualys): one tag search and one
 * tag create, one or more key searches (1000 keys per page) and one key
 * create - so four for a normal set-up. A run holds a MySQL named lock on its
 * row, so two admins pressing Retry together can't both create a key.
 */
final class AgentProvisioner
{
    public const NAME_SUFFIX = '-Agents';
    public const MAX_NAME_LENGTH = 191;

    /** Licences an activation key can be provisioned for, from Qualys's Create Activation Key docs. */
    public const KNOWN_MODULES = ['VM_LICENSE', 'PC_LICENSE', 'SCA', 'PM', 'SA', 'FIM', 'EDR', 'SWCA', 'CAPS', 'MTG'];

    /** Used when qualys.activation_key_modules isn't set: vulnerability management only. */
    public const DEFAULT_MODULES = ['VM_LICENSE'];

    public function __construct(private AgentProvisioningApi $api)
    {
    }

    /**
     * "Plainsight Security" -> "Plainsight-Security-Agents". Spaces and
     * underscores become hyphens, anything else that isn't a letter, number
     * or hyphen is dropped, runs of hyphens collapse, and -Agents is added
     * unless the name already ends with it. '' if nothing usable is left
     * (the admin then types a name).
     */
    public static function suggestTagName(string $organisationName): string
    {
        $name = preg_replace('/[\s_]+/u', '-', trim($organisationName)) ?? '';
        $name = preg_replace('/[^A-Za-z0-9-]/', '', $name) ?? '';
        $name = trim(preg_replace('/-{2,}/', '-', $name) ?? '', '-');
        if ($name === '') {
            return '';
        }
        if (strcasecmp(substr($name, -strlen(self::NAME_SUFFIX)), self::NAME_SUFFIX) !== 0) {
            $name .= self::NAME_SUFFIX;
        }
        return substr($name, 0, self::MAX_NAME_LENGTH);
    }

    /** Why $name can't be used as a tag name, or null if it can. Applies to suggested and typed names alike. */
    public static function tagNameError(string $name): ?string
    {
        if ($name === '') {
            return 'Enter a tag name.';
        }
        if (preg_match('/\s/u', $name)) {
            return 'Tag names can\'t contain spaces - use hyphens instead, e.g. Plainsight-Security-Agents.';
        }
        if (preg_match('/^[A-Za-z0-9-]+$/', $name) !== 1 || preg_match('/[A-Za-z0-9]/', $name) !== 1) {
            return 'Tag names can only use letters, numbers and hyphens.';
        }
        if (strlen($name) > self::MAX_NAME_LENGTH) {
            return 'Tag names can be at most ' . self::MAX_NAME_LENGTH . ' characters.';
        }
        return null;
    }

    /**
     * Modules new keys are provisioned for: qualys.activation_key_modules, or
     * VM_LICENSE alone. An unknown name throws rather than being sent, so a
     * typo in config can't create a key with the wrong licences.
     *
     * @return string[]
     */
    public static function modules(): array
    {
        $configured = Config::get('qualys.activation_key_modules');
        if ($configured === null) {
            return self::DEFAULT_MODULES;
        }
        $modules = array_values(array_unique(array_map(static fn ($m) => strtoupper(trim((string)$m)), (array)$configured)));
        $unknown = array_diff($modules, self::KNOWN_MODULES);
        if ($modules === [] || $unknown !== []) {
            throw new \RuntimeException('qualys.activation_key_modules in src/config/config.php must list modules from: '
                . implode(', ', self::KNOWN_MODULES) . ($unknown !== [] ? ' (not recognised: ' . implode(', ', $unknown) . ')' : '') . '.');
        }
        return $modules;
    }

    /**
     * Every organisation with its set-up (or null), then set-ups whose
     * organisation has since been deleted - their tag and key still exist in
     * Qualys, so they're still listed.
     *
     * @return array{organisations: array<int, array{id: int, name: string, setup: ?array}>, orphans: array<int, array>}
     */
    public static function listForAdmin(): array
    {
        $pdo = Database::getConnection();
        $setups = [];
        $orphans = [];
        foreach ($pdo->query('SELECT * FROM agent_provisioning ORDER BY tag_name')->fetchAll() as $row) {
            $row = self::shape($row);
            if ($row['organisation_id'] === null) {
                $orphans[] = $row;
            } else {
                $setups[$row['organisation_id']] = $row;
            }
        }
        $orgs = [];
        foreach ($pdo->query('SELECT id, name FROM organisations ORDER BY name')->fetchAll() as $o) {
            $orgs[] = ['id' => (int)$o['id'], 'name' => (string)$o['name'], 'setup' => $setups[(int)$o['id']] ?? null];
        }
        return ['organisations' => $orgs, 'orphans' => $orphans];
    }

    public static function get(int $id): ?array
    {
        $stmt = Database::getConnection()->prepare('SELECT * FROM agent_provisioning WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();
        return $row === false ? null : self::shape($row);
    }

    /**
     * Removes an unfinished set-up so the organisation can start again.
     * Nothing is deleted in Qualys: the returned row says what was already
     * created there, for the admin to remove by hand if it isn't wanted.
     */
    public static function cancel(int $id): array
    {
        $row = self::get($id) ?? throw new \RuntimeException('That set-up no longer exists.');
        if ($row['status'] === 'complete') {
            throw new \RuntimeException('That set-up is complete - there is nothing to cancel.');
        }
        Database::getConnection()->prepare('DELETE FROM agent_provisioning WHERE id = :id AND status = \'in_progress\'')
            ->execute(['id' => $id]);
        return $row;
    }

    /**
     * Starts a set-up for an organisation and runs it as far as it gets. The
     * row is saved before any Qualys call, so the name and organisation are
     * reserved even if the run then fails.
     *
     * @throws AgentTagExistsException when Qualys already has a tag with this name - nothing was created
     * @throws \RuntimeException on any other problem; the row keeps the error for Retry
     */
    public function start(int $organisationId, string $tagName, ?int $userId): array
    {
        $pdo = Database::getConnection();
        $stmt = $pdo->prepare('SELECT name FROM organisations WHERE id = :id');
        $stmt->execute(['id' => $organisationId]);
        if ($stmt->fetchColumn() === false) {
            throw new \RuntimeException('That organisation no longer exists.');
        }
        if (($error = self::tagNameError($tagName)) !== null) {
            throw new \RuntimeException($error);
        }

        $existing = $pdo->prepare('SELECT * FROM agent_provisioning WHERE organisation_id = :org');
        $existing->execute(['org' => $organisationId]);
        if (($row = $existing->fetch()) !== false) {
            throw new \RuntimeException($row['status'] === 'complete'
                ? "This organisation is already set up, with tag {$row['tag_name']}."
                : "This organisation already has a set-up in progress ({$row['tag_name']}) - retry or cancel that one.");
        }
        $taken = $pdo->prepare('SELECT tag_name FROM agent_provisioning WHERE tag_name = :name');
        $taken->execute(['name' => $tagName]);
        if (($other = $taken->fetchColumn()) !== false) {
            throw new \RuntimeException("The tag name {$other} is already used by another client's set-up.");
        }

        try {
            $pdo->prepare('INSERT INTO agent_provisioning (organisation_id, tag_name, created_by) VALUES (:org, :name, :user)')
                ->execute(['org' => $organisationId, 'name' => $tagName, 'user' => $userId]);
        } catch (\PDOException $e) {
            if ((int)$e->getCode() === 23000) {
                // Another admin got there between the checks and the insert.
                throw new \RuntimeException('That organisation or tag name was just taken by another set-up - reload the page.');
            }
            throw $e;
        }
        return $this->resume((int)$pdo->lastInsertId());
    }

    /**
     * Carries an unfinished set-up on from wherever it stopped.
     *
     * @param int|null $useExistingTagId the admin's answer to an
     *        AgentTagExistsException: use this existing Qualys tag instead of
     *        creating one. Ignored once the set-up has a tag.
     * @throws AgentTagExistsException|\RuntimeException as start()
     */
    public function resume(int $id, ?int $useExistingTagId = null): array
    {
        $pdo = Database::getConnection();
        $lockName = 'vulndash_agent_setup_' . $id;
        $lock = $pdo->prepare('SELECT GET_LOCK(:n, 0)');
        $lock->execute(['n' => $lockName]);
        if ((int)$lock->fetchColumn() !== 1) {
            throw new \RuntimeException('Someone else is working on this set-up right now - wait a moment and reload.');
        }
        try {
            $row = self::get($id) ?? throw new \RuntimeException('That set-up no longer exists.');
            if ($row['status'] === 'complete') {
                return $row;
            }
            try {
                $this->ensureTag($row, $useExistingTagId);
                $this->ensureKey($row);
                $this->finishLocally($row);
            } catch (\Throwable $e) {
                $pdo->prepare('UPDATE agent_provisioning SET last_error = :e WHERE id = :id')
                    ->execute(['e' => mb_substr($e->getMessage(), 0, 2000), 'id' => $id]);
                throw $e;
            }
            return self::get($id);
        } finally {
            $pdo->prepare('SELECT RELEASE_LOCK(:n)')->execute(['n' => $lockName]);
        }
    }

    /** Step 1: the Qualys tag, created or (by the admin's choice) adopted. */
    private function ensureTag(array &$row, ?int $useExistingTagId): void
    {
        if ($row['qualys_tag_id'] !== null) {
            return;
        }
        $matches = array_filter(
            $this->api->searchTagsByNameContains($row['tag_name']),
            static fn (array $t): bool => strcasecmp(trim((string)$t['name']), $row['tag_name']) === 0
        );

        if ($matches === []) {
            if ($useExistingTagId !== null) {
                throw new \RuntimeException("Qualys no longer has a tag called {$row['tag_name']} - retry to create a new one.");
            }
            $this->save($row, ['qualys_tag_id' => $this->api->createStaticTag($row['tag_name'])]);
            return;
        }
        if ($useExistingTagId === null || !isset($matches[$useExistingTagId])) {
            throw new AgentTagExistsException($row['id'], $row['tag_name'], $matches);
        }

        $tag = $matches[$useExistingTagId];
        if ($tag['ruleType'] !== null || $tag['srcAssetGroupId'] !== null) {
            throw new \RuntimeException("The existing tag {$tag['name']} is a dynamic tag (" . ($tag['ruleType'] ?? 'asset group')
                . ') - Qualys only lets an activation key apply static tags. Cancel and choose another name.');
        }
        $pdo = Database::getConnection();
        $claimed = $pdo->prepare('SELECT tag_name FROM agent_provisioning WHERE qualys_tag_id = :q AND id <> :id');
        $claimed->execute(['q' => $useExistingTagId, 'id' => $row['id']]);
        if (($other = $claimed->fetchColumn()) !== false) {
            throw new \RuntimeException("The existing tag {$tag['name']} already belongs to another client's set-up ({$other}).");
        }
        $otherOrgs = $pdo->prepare('SELECT o.name FROM tags t JOIN organisation_tags ot ON ot.tag_id = t.id JOIN organisations o ON o.id = ot.organisation_id
                                    WHERE t.qualys_tag_id = :q AND ot.organisation_id <> :org ORDER BY o.name');
        $otherOrgs->execute(['q' => (string)$useExistingTagId, 'org' => (int)$row['organisation_id']]);
        $names = $otherOrgs->fetchAll(\PDO::FETCH_COLUMN);
        if ($names !== []) {
            throw new \RuntimeException("The existing tag {$tag['name']} is already given to " . implode(', ', $names)
                . ' - a client tag must belong to one client only. Cancel and choose another name.');
        }
        // Qualys's spelling wins: the name may differ from what was typed in case only.
        $this->save($row, ['qualys_tag_id' => $useExistingTagId, 'tag_name' => trim((string)$tag['name'])]);
    }

    /** Step 2: the activation key - found again after a lost response, otherwise created - and its tag checked. */
    private function ensureKey(array &$row): void
    {
        $tagId = (int)$row['qualys_tag_id'];
        if ($row['activation_key_id'] !== null) {
            // Saved on an earlier run but never confirmed to carry the tag.
            $key = $this->api->getActivationKey($row['activation_key_id'])
                ?? throw new \RuntimeException("Activation key {$row['activation_key_id']} no longer exists in Qualys. Cancel this set-up, delete tag {$row['tag_name']} in Qualys if it isn't wanted, and start again.");
            $this->assertKeyCarriesTag($key, $row);
            return;
        }

        $sameTitle = array_filter($this->api->listActivationKeys(),
            static fn (array $k): bool => strcasecmp($k['title'], $row['tag_name']) === 0);
        $ours = array_filter($sameTitle, static fn (array $k): bool => in_array($tagId, $k['tag_ids'], true));
        if (count($sameTitle) === 1 && count($ours) === 1) {
            $key = reset($ours);
            $this->save($row, ['activation_key_id' => $key['id'], 'activation_key' => $key['activation_key']]);
            return;
        }
        if ($sameTitle !== []) {
            $ids = implode(', ', array_keys($sameTitle));
            throw new \RuntimeException("Qualys already has an activation key titled {$row['tag_name']} (key id {$ids}) that isn't this client's. "
                . 'Rename or delete it in Qualys and retry, or cancel and choose another tag name.');
        }

        $key = $this->api->createActivationKey($row['tag_name'], $tagId, $row['tag_name'], self::modules());
        $this->save($row, ['activation_key_id' => $key['id'], 'activation_key' => $key['activation_key']]);
        if (!in_array($tagId, $key['tag_ids'], true)) {
            // The create response didn't list the tag - ask Qualys directly
            // before deciding, as the response may just leave tags out.
            $key = $this->api->getActivationKey($key['id']) ?? $key;
        }
        $this->assertKeyCarriesTag($key, $row);
    }

    private function assertKeyCarriesTag(array $key, array $row): void
    {
        if (!in_array((int)$row['qualys_tag_id'], $key['tag_ids'], true)) {
            throw new \RuntimeException("Qualys shows activation key {$key['id']} without tag {$row['tag_name']}, so agents installed with it "
                . "wouldn't be tagged. Add the tag to the key in Qualys and retry.");
        }
    }

    /**
     * Step 3: the local tag row (reusing the one the sync already made, or
     * an admin's pending one with this name), its activation ID, and the
     * organisation's link to it - all or nothing.
     */
    private function finishLocally(array &$row): void
    {
        $pdo = Database::getConnection();
        $qualysTagId = (string)$row['qualys_tag_id'];
        $pdo->beginTransaction();
        try {
            $byId = $pdo->prepare('SELECT id FROM tags WHERE qualys_tag_id = :q FOR UPDATE');
            $byId->execute(['q' => $qualysTagId]);
            $localId = $byId->fetchColumn();

            if ($localId === false) {
                $byName = $pdo->prepare('SELECT id, qualys_tag_id FROM tags WHERE LOWER(TRIM(name)) = LOWER(TRIM(:n)) FOR UPDATE');
                $byName->execute(['n' => $row['tag_name']]);
                $named = $byName->fetch();
                if ($named !== false && $named['qualys_tag_id'] !== null) {
                    throw new \RuntimeException("VulnDash already has a different tag called {$row['tag_name']} (Qualys id {$named['qualys_tag_id']}). "
                        . 'Rename or delete it on Manage Users and retry.');
                }
                if ($named !== false) {
                    // An admin pre-created it by name - promote it, exactly as the sync would.
                    $localId = (int)$named['id'];
                    $pdo->prepare('UPDATE tags SET qualys_tag_id = :q WHERE id = :id')->execute(['q' => $qualysTagId, 'id' => $localId]);
                } else {
                    $pdo->prepare('INSERT INTO tags (qualys_tag_id, name) VALUES (:q, :n)')->execute(['q' => $qualysTagId, 'n' => $row['tag_name']]);
                    $localId = (int)$pdo->lastInsertId();
                }
            }
            $localId = (int)$localId;

            $pdo->prepare('UPDATE tags SET agent_activation_id = :a WHERE id = :id')
                ->execute(['a' => $row['activation_key'], 'id' => $localId]);
            if ($row['organisation_id'] !== null) {
                $pdo->prepare('INSERT IGNORE INTO organisation_tags (organisation_id, tag_id) VALUES (:org, :tag)')
                    ->execute(['org' => $row['organisation_id'], 'tag' => $localId]);
            }
            $pdo->prepare("UPDATE agent_provisioning SET local_tag_id = :t, status = 'complete', completed_at = NOW(), last_error = NULL WHERE id = :id")
                ->execute(['t' => $localId, 'id' => $row['id']]);
            $pdo->commit();
        } catch (\Throwable $e) {
            $pdo->rollBack();
            if ($e instanceof \PDOException && (int)$e->getCode() === 23000) {
                throw new \RuntimeException("The VulnDash tag for {$row['tag_name']} is already linked to another client's set-up.");
            }
            throw $e;
        }
    }

    /** Writes columns straight away (a Qualys id must never be held only in memory) and updates $row to match. */
    private function save(array &$row, array $values): void
    {
        $sets = implode(', ', array_map(static fn (string $c): string => "{$c} = :{$c}", array_keys($values)));
        Database::getConnection()->prepare("UPDATE agent_provisioning SET {$sets} WHERE id = :id")
            ->execute($values + ['id' => $row['id']]);
        $row = array_merge($row, $values);
    }

    private static function shape(array $r): array
    {
        $int = static fn ($v): ?int => $v !== null ? (int)$v : null;
        return [
            'id'                => (int)$r['id'],
            'organisation_id'   => $int($r['organisation_id']),
            'tag_name'          => (string)$r['tag_name'],
            'qualys_tag_id'     => $int($r['qualys_tag_id']),
            'activation_key_id' => $int($r['activation_key_id']),
            'activation_key'    => $r['activation_key'] !== null ? (string)$r['activation_key'] : null,
            'local_tag_id'      => $int($r['local_tag_id']),
            'status'            => (string)$r['status'],
            'last_error'        => $r['last_error'] !== null ? (string)$r['last_error'] : null,
            'created_by'        => $int($r['created_by']),
            'created_at'        => (string)$r['created_at'],
            'completed_at'      => $r['completed_at'] !== null ? (string)$r['completed_at'] : null,
        ];
    }
}
