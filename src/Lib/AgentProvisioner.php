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
 *     has it) or delete the set-up and pick another name. Every key is read the same
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
 * Existing set-ups (a tag and key made by hand before this page existed) are
 * recorded with linkExisting(), which creates nothing - it finds the key in
 * Qualys from the activation ID VulnDash already holds and checks it applies
 * the tag. While an organisation already has such a tag, the page offers
 * Link existing instead of a new set-up.
 *
 * Removing a set-up frees its name for reuse (a name is never retired):
 * unlink() just forgets the record; deleteSetup() - for set-ups this page
 * created, e.g. a test - also deletes in Qualys whatever this page made (the
 * key, and the tag unless it was an existing one the admin chose) and the
 * local tag it made. Linked set-ups can only be unlinked, so a live client's
 * tag and key can't be deleted from here.
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
     * Every organisation with its set-up (or null) and the tags it already
     * has. 'linkable' are those an existing set-up can be recorded from: a
     * Qualys id and an activation ID, and no other set-up using them.
     *
     * @return array<int, array{id: int, name: string, setup: ?array, tags: array<int, array{id: int, name: string}>, linkable: array<int, array{id: int, name: string, qualys_tag_id: string, activation_id: string}>}>
     */
    public static function listForAdmin(): array
    {
        $pdo = Database::getConnection();
        $setups = [];
        foreach ($pdo->query('SELECT * FROM agent_provisioning')->fetchAll() as $row) {
            $row = self::shape($row);
            $setups[$row['organisation_id']] = $row;
        }
        $tags = [];
        foreach ($pdo->query('SELECT ot.organisation_id, t.id, t.name, t.qualys_tag_id, t.agent_activation_id,
                                     (SELECT COUNT(*) FROM agent_provisioning ap
                                      WHERE ap.local_tag_id = t.id OR ap.activation_key = t.agent_activation_id) AS used
                              FROM organisation_tags ot JOIN tags t ON t.id = ot.tag_id ORDER BY t.name')->fetchAll() as $t) {
            $tags[(int)$t['organisation_id']][] = $t;
        }
        $orgs = [];
        foreach ($pdo->query('SELECT id, name FROM organisations ORDER BY name')->fetchAll() as $o) {
            $orgTags = $tags[(int)$o['id']] ?? [];
            $orgs[] = [
                'id'       => (int)$o['id'],
                'name'     => (string)$o['name'],
                'setup'    => $setups[(int)$o['id']] ?? null,
                'tags'     => array_map(static fn (array $t): array => ['id' => (int)$t['id'], 'name' => (string)$t['name']], $orgTags),
                'linkable' => array_values(array_map(
                    static fn (array $t): array => ['id' => (int)$t['id'], 'name' => (string)$t['name'],
                                                    'qualys_tag_id' => (string)$t['qualys_tag_id'], 'activation_id' => (string)$t['agent_activation_id']],
                    array_filter($orgTags, static fn (array $t): bool => $t['qualys_tag_id'] !== null
                        && ctype_digit((string)$t['qualys_tag_id']) && $t['agent_activation_id'] !== null && (int)$t['used'] === 0)
                )),
            ];
        }
        return $orgs;
    }

    public static function get(int $id): ?array
    {
        $stmt = Database::getConnection()->prepare('SELECT * FROM agent_provisioning WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();
        return $row === false ? null : self::shape($row);
    }

    /**
     * Forgets a set-up so its organisation and name are free again. Nothing
     * changes in Qualys or on the local tag - the organisation keeps its tag
     * and the Install agent button. Returns the removed row.
     */
    public static function unlink(int $id): array
    {
        $row = self::get($id) ?? throw new \RuntimeException('That set-up no longer exists.');
        Database::getConnection()->prepare('DELETE FROM agent_provisioning WHERE id = :id')->execute(['id' => $id]);
        return $row;
    }

    /**
     * Records an organisation's existing tag and key as its set-up, creating
     * nothing. $localTagId must be one of the organisation's tags with a
     * Qualys id and an activation ID; Qualys must have a key with that
     * activation ID that applies the tag (one key search). Tag naming rules
     * aren't applied - the tag already exists and agents already carry it.
     */
    public function linkExisting(int $organisationId, int $localTagId, ?int $userId): array
    {
        $pdo = Database::getConnection();
        $stmt = $pdo->prepare('SELECT t.id, t.name, t.qualys_tag_id, t.agent_activation_id FROM tags t
                               JOIN organisation_tags ot ON ot.tag_id = t.id AND ot.organisation_id = :org WHERE t.id = :tag');
        $stmt->execute(['org' => $organisationId, 'tag' => $localTagId]);
        $tag = $stmt->fetch() ?: throw new \RuntimeException('That tag isn\'t one of this organisation\'s tags any more.');
        $activationId = AgentInstall::normaliseActivationId((string)($tag['agent_activation_id'] ?? ''));
        if ($tag['qualys_tag_id'] === null || !ctype_digit((string)$tag['qualys_tag_id']) || $activationId === null) {
            throw new \RuntimeException("Tag {$tag['name']} needs both a Qualys tag id and an activation ID to be linked.");
        }
        $existing = $pdo->prepare('SELECT tag_name FROM agent_provisioning WHERE organisation_id = :org');
        $existing->execute(['org' => $organisationId]);
        if (($other = $existing->fetchColumn()) !== false) {
            throw new \RuntimeException("This organisation already has a set-up ({$other}).");
        }

        $key = $this->api->findActivationKeyByUuid($activationId)
            ?? throw new \RuntimeException("Qualys has no activation key with ID {$activationId} - check the ID set for {$tag['name']} on Manage Users.");
        if (!in_array((int)$tag['qualys_tag_id'], $key['tag_ids'], true)) {
            throw new \RuntimeException("Activation key {$key['id']} ({$key['title']}) doesn't apply tag {$tag['name']} in Qualys, so it isn't this client's set-up. "
                . 'Add the tag to the key in Qualys, or correct the activation ID on Manage Users, then try again.');
        }

        try {
            $pdo->prepare("INSERT INTO agent_provisioning (organisation_id, tag_name, qualys_tag_id, activation_key_id, activation_key, local_tag_id,
                                                           status, origin, created_by, completed_at)
                           VALUES (:org, :name, :q, :kid, :k, :t, 'complete', 'linked', :user, NOW())")
                ->execute(['org' => $organisationId, 'name' => trim((string)$tag['name']), 'q' => (int)$tag['qualys_tag_id'],
                           'kid' => $key['id'], 'k' => $activationId, 't' => $localTagId, 'user' => $userId]);
        } catch (\PDOException $e) {
            if ((int)$e->getCode() === 23000) {
                throw new \RuntimeException("Tag {$tag['name']} or its activation key is already part of another organisation's set-up.");
            }
            throw $e;
        }
        return self::get((int)$pdo->lastInsertId());
    }

    /**
     * Deletes a set-up this page created - a test, typically - and what it
     * made: the activation key and tag in Qualys (key first: Qualys refuses
     * while active agents use it, and stopping there leaves the tag in
     * place), then the local tag, which takes the organisation's and any
     * accounts' links to it. Each step is saved as it completes, so if one
     * fails, running this again carries on. Something already gone from
     * Qualys counts as deleted. Linked set-ups are refused: unlink those.
     */
    public function deleteSetup(int $id): void
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
            if ($row['origin'] === 'linked') {
                throw new \RuntimeException("{$row['tag_name']} was linked from an existing tag and key, so it can only be unlinked - delete those in Qualys itself if you mean to.");
            }
            $deletedKey = $row['activation_key'];
            try {
                if ($row['activation_key_id'] !== null) {
                    try {
                        $this->api->deleteActivationKey($row['activation_key_id']);
                    } catch (\RuntimeException $e) {
                        if ($this->api->getActivationKey($row['activation_key_id']) !== null) {
                            throw $e;
                        }
                    }
                    $this->save($row, ['activation_key_id' => null, 'activation_key' => null]);
                }
                if ($row['origin'] === 'existing_tag') {
                    // The tag was there before this set-up: it stays, in
                    // Qualys and locally, without the deleted key's ID.
                    if ($row['local_tag_id'] !== null) {
                        $pdo->prepare('UPDATE tags SET agent_activation_id = NULL WHERE id = :id AND agent_activation_id <=> :k')
                            ->execute(['id' => $row['local_tag_id'], 'k' => $deletedKey]);
                    }
                } elseif ($row['qualys_tag_id'] !== null) {
                    try {
                        $this->api->deleteTag($row['qualys_tag_id']);
                    } catch (\RuntimeException $e) {
                        if ($this->api->getTag($row['qualys_tag_id']) !== null) {
                            throw $e;
                        }
                    }
                    $qualysTagId = $row['qualys_tag_id'];
                    $this->save($row, ['qualys_tag_id' => null]);
                    // Matched by Qualys id too, in case the set-up stopped
                    // before it recorded the local tag.
                    $pdo->prepare('DELETE FROM tags WHERE id = :id OR qualys_tag_id = :q')
                        ->execute(['id' => (int)$row['local_tag_id'], 'q' => (string)$qualysTagId]);
                } elseif ($row['local_tag_id'] !== null) {
                    $pdo->prepare('DELETE FROM tags WHERE id = :id')->execute(['id' => $row['local_tag_id']]);
                }
                $pdo->prepare('DELETE FROM agent_provisioning WHERE id = :id')->execute(['id' => $id]);
            } catch (\Throwable $e) {
                $pdo->prepare('UPDATE agent_provisioning SET last_error = :e WHERE id = :id')
                    ->execute(['e' => 'Delete stopped: ' . mb_substr($e->getMessage(), 0, 1980), 'id' => $id]);
                throw $e;
            }
        } finally {
            $pdo->prepare('SELECT RELEASE_LOCK(:n)')->execute(['n' => $lockName]);
        }
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
                : "This organisation already has a set-up in progress ({$row['tag_name']}) - retry or delete that one.");
        }
        $current = $pdo->prepare('SELECT t.name FROM organisation_tags ot JOIN tags t ON t.id = ot.tag_id
                                  WHERE ot.organisation_id = :org AND t.agent_activation_id IS NOT NULL ORDER BY t.name LIMIT 1');
        $current->execute(['org' => $organisationId]);
        if (($have = $current->fetchColumn()) !== false) {
            throw new \RuntimeException("This organisation already has tag {$have} with an activation ID - use Link existing to record it, "
                . 'or clear that activation ID on Manage Users first if you really want a second tag and key.');
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
                . ') - Qualys only lets an activation key apply static tags. Delete this set-up and choose another name.');
        }
        $pdo = Database::getConnection();
        $claimed = $pdo->prepare('SELECT tag_name FROM agent_provisioning WHERE qualys_tag_id = :q AND id <> :id');
        $claimed->execute(['q' => $useExistingTagId, 'id' => $row['id']]);
        if (($other = $claimed->fetchColumn()) !== false) {
            throw new \RuntimeException("The existing tag {$tag['name']} already belongs to another client's set-up ({$other}).");
        }
        $otherOrgs = $pdo->prepare('SELECT o.name FROM tags t JOIN organisation_tags ot ON ot.tag_id = t.id JOIN organisations o ON o.id = ot.organisation_id
                                    WHERE t.qualys_tag_id = :q AND ot.organisation_id <> :org ORDER BY o.name');
        $otherOrgs->execute(['q' => (string)$useExistingTagId, 'org' => $row['organisation_id']]);
        $names = $otherOrgs->fetchAll(\PDO::FETCH_COLUMN);
        if ($names !== []) {
            throw new \RuntimeException("The existing tag {$tag['name']} is already given to " . implode(', ', $names)
                . ' - a client tag must belong to one client only. Delete this set-up and choose another name.');
        }
        // Qualys's spelling wins: the name may differ from what was typed in case only.
        $this->save($row, ['qualys_tag_id' => $useExistingTagId, 'tag_name' => trim((string)$tag['name']), 'origin' => 'existing_tag']);
    }

    /** Step 2: the activation key - found again after a lost response, otherwise created - and its tag checked. */
    private function ensureKey(array &$row): void
    {
        $tagId = (int)$row['qualys_tag_id'];
        if ($row['activation_key_id'] !== null) {
            // Saved on an earlier run but never confirmed to carry the tag.
            $key = $this->api->getActivationKey($row['activation_key_id'])
                ?? throw new \RuntimeException("Activation key {$row['activation_key_id']} no longer exists in Qualys. Delete this set-up (which also deletes tag {$row['tag_name']} if this page made it) and start again.");
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
                . 'Rename or delete it in Qualys and retry, or delete this set-up and choose another tag name.');
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
            $pdo->prepare('INSERT IGNORE INTO organisation_tags (organisation_id, tag_id) VALUES (:org, :tag)')
                ->execute(['org' => $row['organisation_id'], 'tag' => $localId]);
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
            'organisation_id'   => (int)$r['organisation_id'],
            'tag_name'          => (string)$r['tag_name'],
            'qualys_tag_id'     => $int($r['qualys_tag_id']),
            'activation_key_id' => $int($r['activation_key_id']),
            'activation_key'    => $r['activation_key'] !== null ? (string)$r['activation_key'] : null,
            'local_tag_id'      => $int($r['local_tag_id']),
            'status'            => (string)$r['status'],
            'origin'            => (string)$r['origin'],
            'last_error'        => $r['last_error'] !== null ? (string)$r['last_error'] : null,
            'created_by'        => $int($r['created_by']),
            'created_at'        => (string)$r['created_at'],
            'completed_at'      => $r['completed_at'] !== null ? (string)$r['completed_at'] : null,
        ];
    }
}
