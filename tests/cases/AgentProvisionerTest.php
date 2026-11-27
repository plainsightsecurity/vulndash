<?php
declare(strict_types=1);

// Agent Setup (AgentProvisioner): tag naming rules, one tag + one key per
// client, duplicate handling in Qualys and locally, resuming after a failure
// without creating a second tag or key, and the local wiring the Install
// agent button relies on. Qualys is an in-memory stub (FakeQualys).

use VulnDash\Lib\AgentProvisioner as P;
use VulnDash\Lib\AgentProvisioningApi;
use VulnDash\Lib\AgentTagExistsException;
use VulnDash\Lib\Database;
use VulnDash\Lib\OrganisationRepository as Org;

/** A small Qualys: tags and activation keys in arrays, every call recorded, failures injectable. */
final class FakeQualys implements AgentProvisioningApi
{
    /** @var array<int, array> */
    public array $tags = [];
    /** @var array<int, array> */
    public array $keys = [];
    /** @var string[] */
    public array $calls = [];
    /** @var array<string, string> method => message to throw once */
    public array $failNext = [];
    /** createActivationKey stores the key and then fails, like a lost response. */
    public bool $loseKeyResponse = false;
    /** Created keys leave out the tag in both the response and later reads. */
    public bool $dropKeyTag = false;
    public array $lastModules = [];
    private int $nextId = 9000;

    private function call(string $m): void
    {
        $this->calls[] = $m;
        if (isset($this->failNext[$m])) {
            $msg = $this->failNext[$m];
            unset($this->failNext[$m]);
            throw new \RuntimeException($msg);
        }
    }

    public function addTag(string $name, ?string $ruleType = null): int
    {
        $id = ++$this->nextId;
        $this->tags[$id] = ['name' => $name, 'ruleType' => $ruleType, 'ruleText' => null, 'srcAssetGroupId' => null, 'parentTagId' => null, 'other' => []];
        return $id;
    }

    public function addKey(string $title, array $tagIds): int
    {
        $id = ++$this->nextId;
        $this->keys[$id] = ['id' => $id, 'title' => $title, 'activation_key' => sprintf('00000000-0000-4000-8000-%012d', $id), 'tag_ids' => $tagIds];
        return $id;
    }

    public function searchTagsByNameContains(string $name): array
    {
        $this->call('searchTags');
        return array_filter($this->tags, static fn (array $t): bool => stripos($t['name'], $name) !== false);
    }

    public function createStaticTag(string $name): int
    {
        $this->call('createTag');
        return $this->addTag($name);
    }

    public function listActivationKeys(): array
    {
        $this->call('listKeys');
        return $this->keys;
    }

    public function createActivationKey(string $title, int $tagId, string $tagName, array $modules): array
    {
        $this->call('createKey');
        $this->lastModules = $modules;
        $id = $this->addKey($title, $this->dropKeyTag ? [] : [$tagId]);
        if ($this->loseKeyResponse) {
            $this->loseKeyResponse = false;
            throw new \RuntimeException('Qualys QPS API request failed: Operation timed out');
        }
        return $this->keys[$id];
    }

    public function getActivationKey(int $keyId): ?array
    {
        $this->call('getKey');
        return $this->keys[$keyId] ?? null;
    }

    public function findActivationKeyByUuid(string $activationKey): ?array
    {
        $this->call('findKey');
        foreach ($this->keys as $k) {
            if ($k['activation_key'] === strtolower($activationKey)) {
                return $k;
            }
        }
        return null;
    }

    public function getTag(int $tagId): ?array
    {
        $this->call('getTag');
        return $this->tags[$tagId] ?? null;
    }

    public function deleteActivationKey(int $keyId): void
    {
        $this->call('deleteKey');
        if (!isset($this->keys[$keyId])) {
            throw new \RuntimeException('Qualys Delete Activation Key returned NOT_FOUND');
        }
        unset($this->keys[$keyId]);
    }

    public function deleteTag(int $tagId): void
    {
        $this->call('deleteTag');
        if (!isset($this->tags[$tagId])) {
            throw new \RuntimeException('Qualys Delete Tag returned NOT_FOUND');
        }
        unset($this->tags[$tagId]);
    }
}

/** Organisation "Plainsight Security" (id returned) on the standard estate. */
function seed_setup_org(string $name = 'Plainsight Security'): int
{
    seed_estate();
    return Org::create($name, [], null);
}

function throws(callable $fn, string $class = \RuntimeException::class): \Throwable
{
    try {
        $fn();
    } catch (\Throwable $e) {
        ok($e instanceof $class, 'expected ' . $class . ', got ' . get_class($e) . ': ' . $e->getMessage());
        return $e;
    }
    throw new TestFailure("expected $class, nothing thrown");
}

function prov_count(): int
{
    return (int)Database::getConnection()->query('SELECT COUNT(*) FROM agent_provisioning')->fetchColumn();
}

// --- naming -----------------------------------------------------------------

test('suggested tag names: hyphens for spaces, symbols dropped, -Agents added once', function () {
    eq(P::suggestTagName('Plainsight Security'), 'Plainsight-Security-Agents');
    eq(P::suggestTagName('Smith & Sons Ltd.'), 'Smith-Sons-Ltd-Agents');
    eq(P::suggestTagName('  Wave__hill   Ltd  '), 'Wave-hill-Ltd-Agents');
    eq(P::suggestTagName('Acme Agents'), 'Acme-Agents', 'no double suffix');
    eq(P::suggestTagName('Café Nord'), 'Caf-Nord-Agents');
    eq(P::suggestTagName('&&&'), '', 'nothing usable');
});

test('tag names: letters, numbers and hyphens only, never spaces', function () {
    eq(P::tagNameError('Plainsight-Security-Agents'), null);
    eq(P::tagNameError('custom-name-2'), null, 'override without -Agents is allowed');
    ok(str_contains((string)P::tagNameError('Plainsight Security'), 'spaces'), 'space rejected');
    ok(P::tagNameError('Acme_Agents') !== null, 'underscore rejected');
    ok(P::tagNameError('Acme&Co') !== null, 'symbol rejected');
    ok(P::tagNameError('---') !== null, 'hyphens only rejected');
    ok(P::tagNameError('') !== null, 'empty rejected');
    ok(P::tagNameError(str_repeat('a', 192)) !== null, 'too long rejected');
});

test('modules default to VM only and an unknown module is refused', function () {
    eq(P::modules(), ['VM_LICENSE']);
    set_config('qualys.activation_key_modules', ['vm_license', 'PM']);
    eq(P::modules(), ['VM_LICENSE', 'PM']);
    set_config('qualys.activation_key_modules', ['VM_LICENSE', 'VMM']);
    throws(fn () => P::modules());
});

// --- the normal path --------------------------------------------------------

test('a set-up creates one tag and one key, and wires them into VulnDash', function () {
    $org = seed_setup_org();
    $q = new FakeQualys();
    $row = (new P($q))->start($org, 'Plainsight-Security-Agents', 1);

    eq($q->calls, ['searchTags', 'createTag', 'listKeys', 'createKey'], 'four calls');
    eq($row['status'], 'complete');
    eq(count($q->tags), 1);
    eq(count($q->keys), 1);
    $key = reset($q->keys);
    eq($key['title'], 'Plainsight-Security-Agents', 'key named after the tag');
    eq($key['tag_ids'], [$row['qualys_tag_id']], 'key applies the tag');
    eq($q->lastModules, ['VM_LICENSE']);

    $tag = Database::getConnection()->query('SELECT * FROM tags WHERE id = ' . (int)$row['local_tag_id'])->fetch();
    eq($tag['qualys_tag_id'], (string)$row['qualys_tag_id']);
    eq($tag['name'], 'Plainsight-Security-Agents');
    eq($tag['agent_activation_id'], $key['activation_key'], 'install button gets the key');
    eq(Org::get($org)['tag_ids'], [(int)$row['local_tag_id']], 'organisation sees the tag');
    eq($row['last_error'], null);
});

test('a pending local tag with the same name is promoted, not duplicated', function () {
    $org = seed_setup_org();
    $pdo = Database::getConnection();
    $pdo->exec("INSERT INTO tags (id, qualys_tag_id, name) VALUES (50, NULL, 'plainsight-security-agents')");
    $row = (new P(new FakeQualys()))->start($org, 'Plainsight-Security-Agents', 1);
    eq($row['local_tag_id'], 50, 'pending row promoted');
    eq($pdo->query('SELECT qualys_tag_id FROM tags WHERE id = 50')->fetchColumn(), (string)$row['qualys_tag_id']);
    eq((int)$pdo->query('SELECT COUNT(*) FROM tags')->fetchColumn(), 3, 'no new row');
});

// --- uniqueness ---------------------------------------------------------------

test('a tag name already in Qualys creates nothing until the admin chooses', function () {
    $org = seed_setup_org();
    $q = new FakeQualys();
    $existing = $q->addTag('plainsight-security-agents');
    $q->addTag('Plainsight-Security-Agents-Old');
    $e = throws(fn () => (new P($q))->start($org, 'Plainsight-Security-Agents', 1), AgentTagExistsException::class);
    eq(array_keys($e->matches), [$existing], 'only the exact (case-insensitive) match');
    eq(count($q->tags), 2, 'no tag created');
    eq($q->calls, ['searchTags']);

    $row = P::get($e->provisioningId);
    eq($row['status'], 'in_progress');
    ok(str_contains((string)$row['last_error'], 'already has a tag'), 'error kept for the page');

    // The sync has already seen this tag on a host: its row is reused.
    Database::getConnection()->prepare("INSERT INTO tags (id, qualys_tag_id, name) VALUES (70, ?, 'plainsight-security-agents')")->execute([(string)$existing]);
    $row = (new P($q))->resume($row['id'], $existing);
    eq($row['status'], 'complete');
    eq($row['qualys_tag_id'], $existing);
    eq($row['local_tag_id'], 70, 'synced row reused');
    eq($row['tag_name'], 'plainsight-security-agents', 'Qualys spelling kept');
    eq(count($q->tags), 2, 'still no tag created');
});

test('an existing dynamic tag, or one another client has, can\'t be used', function () {
    $org = seed_setup_org();
    $q = new FakeQualys();
    $dyn = $q->addTag('Plainsight-Security-Agents', 'GROOVY');
    $e = throws(fn () => (new P($q))->start($org, 'Plainsight-Security-Agents', 1), AgentTagExistsException::class);
    ok(str_contains($e->getMessage(), 'dynamic'), 'message says why');
    throws(fn () => (new P($q))->resume($e->provisioningId, $dyn));

    // A static tag already given to another organisation.
    $pdo = Database::getConnection();
    $other = Org::create('Other Client', [], null);
    $q2 = new FakeQualys();
    $shared = $q2->addTag('Shared-Agents');
    $pdo->prepare("INSERT INTO tags (id, qualys_tag_id, name) VALUES (60, ?, 'Shared-Agents')")->execute([(string)$shared]);
    $pdo->exec("INSERT INTO organisation_tags (organisation_id, tag_id) VALUES ($other, 60)");
    $org3 = Org::create('Third', [], null);
    $e = throws(fn () => (new P($q2))->start($org3, 'Shared-Agents', 1), AgentTagExistsException::class);
    $e2 = throws(fn () => (new P($q2))->resume($e->provisioningId, $shared));
    ok(str_contains($e2->getMessage(), 'Other Client'), 'names the other client');
});

test('one set-up per organisation, and tag names are unique whatever the case', function () {
    $org = seed_setup_org();
    $org2 = Org::create('Second', [], null);
    $q = new FakeQualys();
    (new P($q))->start($org, 'Plainsight-Security-Agents', 1);

    throws(fn () => (new P($q))->start($org, 'Another-Agents', 1));
    $e = throws(fn () => (new P($q))->start($org2, 'PLAINSIGHT-security-agents', 1));
    ok(str_contains($e->getMessage(), 'already used'), 'case-insensitive clash');
    eq(prov_count(), 1);
    eq(count($q->tags), 1, 'nothing sent to Qualys for either');

    // The database refuses it even if the code's checks were bypassed.
    throws(fn () => Database::getConnection()->exec("INSERT INTO agent_provisioning (organisation_id, tag_name) VALUES ($org2, 'plainsight-SECURITY-agents')"), \PDOException::class);
});

test('a key with the same title that isn\'t this client\'s stops the set-up', function () {
    $org = seed_setup_org();
    $q = new FakeQualys();
    $q->addKey('Plainsight-Security-Agents', [123]);
    $e = throws(fn () => (new P($q))->start($org, 'Plainsight-Security-Agents', 1));
    ok(str_contains($e->getMessage(), 'activation key titled'), 'says why');
    eq(count($q->keys), 1, 'no key created');
    ok(!in_array('createKey', $q->calls, true), 'create never called');
});

test('a spelling clash with a different local tag stops before anything is wired', function () {
    $org = seed_setup_org();
    Database::getConnection()->exec("INSERT INTO tags (qualys_tag_id, name) VALUES ('555', 'Plainsight-Security-Agents')");
    $q = new FakeQualys();
    $e = throws(fn () => (new P($q))->start($org, 'Plainsight-Security-Agents', 1));
    ok(str_contains($e->getMessage(), 'different tag'), 'says why');
    eq(Org::get($org)['tag_ids'], [], 'organisation untouched');
    eq(P::listForAdmin()[0]['setup']['status'], 'in_progress');
});

// --- resuming -----------------------------------------------------------------

test('retry after a failed key create reuses the tag it already made', function () {
    $org = seed_setup_org();
    $q = new FakeQualys();
    $q->failNext['createKey'] = 'Qualys Create Activation Key returned UNAUTHORIZED';
    $e = throws(fn () => (new P($q))->start($org, 'Plainsight-Security-Agents', 1));
    $row = P::listForAdmin()[0]['setup'];
    ok($row['qualys_tag_id'] !== null, 'tag id saved straight away');
    eq($row['last_error'], $e->getMessage());

    $q->calls = [];
    $row = (new P($q))->resume($row['id']);
    eq($row['status'], 'complete');
    eq($q->calls, ['listKeys', 'createKey'], 'no second tag search or create');
    eq(count($q->tags), 1);
    eq(count($q->keys), 1);
});

test('a key whose create response was lost is found again, not made twice', function () {
    $org = seed_setup_org();
    $q = new FakeQualys();
    $q->loseKeyResponse = true;
    throws(fn () => (new P($q))->start($org, 'Plainsight-Security-Agents', 1));
    eq(count($q->keys), 1, 'Qualys did make the key');
    $row = P::listForAdmin()[0]['setup'];
    eq($row['activation_key_id'], null, 'but we never saw its id');

    $q->calls = [];
    $row = (new P($q))->resume($row['id']);
    eq($row['status'], 'complete');
    eq($q->calls, ['listKeys'], 'adopted, not re-created');
    eq($row['activation_key_id'], array_key_first($q->keys));
});

test('a key Qualys shows without the tag isn\'t accepted until the tag is on it', function () {
    $org = seed_setup_org();
    $q = new FakeQualys();
    $q->dropKeyTag = true;
    $e = throws(fn () => (new P($q))->start($org, 'Plainsight-Security-Agents', 1));
    ok(str_contains($e->getMessage(), 'without tag'), 'says why');
    $row = P::listForAdmin()[0]['setup'];
    ok($row['activation_key_id'] !== null, 'key id saved');
    eq($row['local_tag_id'], null, 'nothing wired locally');

    $q->keys[$row['activation_key_id']]['tag_ids'] = [$row['qualys_tag_id']]; // fixed in Qualys
    $q->calls = [];
    $row = (new P($q))->resume($row['id']);
    eq($row['status'], 'complete');
    eq($q->calls, ['getKey'], 'checked, nothing created');
    eq(count($q->keys), 1);
});

// --- link, unlink, delete -------------------------------------------------------

/** Org with an existing hand-made tag (local 80, Qualys 4001) and key applying it. */
function seed_existing_setup(FakeQualys $q, bool $keyAppliesTag = true): array
{
    $org = seed_setup_org('FaiceTech');
    $q->tags[4001] = ['name' => 'FaiceTechAgents', 'ruleType' => null, 'ruleText' => null, 'srcAssetGroupId' => null, 'parentTagId' => null, 'other' => []];
    $keyId = $q->addKey('FaiceTech', $keyAppliesTag ? [4001] : [999]);
    $uuid = $q->keys[$keyId]['activation_key'];
    $pdo = Database::getConnection();
    $pdo->prepare("INSERT INTO tags (id, qualys_tag_id, name, agent_activation_id) VALUES (80, '4001', 'FaiceTechAgents', ?)")->execute([$uuid]);
    $pdo->exec("INSERT INTO organisation_tags (organisation_id, tag_id) VALUES ($org, 80)");
    return [$org, $keyId, $uuid];
}

test('an organisation that already has a tag and key is offered Link, not Create', function () {
    $q = new FakeQualys();
    [$org] = seed_existing_setup($q);
    $list = P::listForAdmin();
    eq($list[0]['setup'], null);
    eq(array_column($list[0]['linkable'], 'id'), [80]);
    $e = throws(fn () => (new P($q))->start($org, 'FaiceTech-Agents', 1));
    ok(str_contains($e->getMessage(), 'Link existing'), 'points at Link');
    eq($q->calls, [], 'nothing sent to Qualys');
});

test('Link existing records the set-up and changes nothing', function () {
    $q = new FakeQualys();
    [$org, $keyId, $uuid] = seed_existing_setup($q);
    $tagsBefore = $q->tags;
    $keysBefore = $q->keys;
    $row = (new P($q))->linkExisting($org, 80, 1);
    eq($q->calls, ['findKey'], 'one read-only call');
    eq([$row['status'], $row['origin'], $row['tag_name'], $row['qualys_tag_id'], $row['activation_key_id'], $row['activation_key'], $row['local_tag_id']],
       ['complete', 'linked', 'FaiceTechAgents', 4001, $keyId, $uuid, 80]);
    eq($q->tags, $tagsBefore);
    eq($q->keys, $keysBefore);
    eq(Database::getConnection()->query('SELECT agent_activation_id FROM tags WHERE id = 80')->fetchColumn(), $uuid, 'activation ID untouched');
    eq(P::listForAdmin()[0]['linkable'], [], 'no longer offered');

    P::unlink($row['id']);
    eq(prov_count(), 0);
    eq(Org::get($org)['tag_ids'], [80], 'organisation keeps its tag');
});

test('Link refuses a key that doesn\'t apply the tag, or an unknown activation ID', function () {
    $q = new FakeQualys();
    [$org, $keyId] = seed_existing_setup($q, false);
    $e = throws(fn () => (new P($q))->linkExisting($org, 80, 1));
    ok(str_contains($e->getMessage(), "doesn't apply tag"), $e->getMessage());
    unset($q->keys[$keyId]);
    $e = throws(fn () => (new P($q))->linkExisting($org, 80, 1));
    ok(str_contains($e->getMessage(), 'no activation key'), $e->getMessage());
    eq(prov_count(), 0);
});

test('Delete removes a test set-up everywhere and frees the name, repeatably', function () {
    $org = seed_setup_org();
    $q = new FakeQualys();
    $pdo = Database::getConnection();
    for ($i = 0; $i < 3; $i++) {
        $row = (new P($q))->start($org, 'Plainsight-Security-Agents', 1);
        $pdo->exec("INSERT INTO user_tags (user_id, tag_id) VALUES (2, {$row['local_tag_id']})");
        $q->calls = [];
        (new P($q))->deleteSetup($row['id'], 'Plainsight-Security-Agents');
        eq($q->calls, ['deleteKey', 'deleteTag'], "run $i: key first, then tag");
        eq([$q->tags, $q->keys], [[], []], "run $i: gone from Qualys");
        eq(prov_count(), 0, "run $i: record gone");
        eq((int)$pdo->query("SELECT COUNT(*) FROM tags WHERE name = 'Plainsight-Security-Agents'")->fetchColumn(), 0, "run $i: local tag gone");
        eq(Org::get($org)['tag_ids'], [], "run $i: organisation link gone");
    }
    eq((int)$pdo->query('SELECT COUNT(*) FROM user_tags WHERE user_id = 2')->fetchColumn(), 1, 'the client keeps only its own original tag');
});

test('Delete stops at a key Qualys won\'t delete, and carries on next time', function () {
    $org = seed_setup_org();
    $q = new FakeQualys();
    $row = (new P($q))->start($org, 'Plainsight-Security-Agents', 1);
    $q->failNext['deleteKey'] = 'Qualys Delete Activation Key returned INVALID_REQUEST: key has active agents';
    $e = throws(fn () => (new P($q))->deleteSetup($row['id'], 'Plainsight-Security-Agents'));
    ok(str_contains($e->getMessage(), 'active agents'), 'Qualys reason shown');
    eq(count($q->tags), 1, 'tag left alone');
    ok(str_contains((string)P::get($row['id'])['last_error'], 'Delete stopped'), 'recorded');

    // The key goes, then the tag delete fails; a re-run doesn't retry the key.
    $q->failNext['deleteTag'] = 'timeout';
    throws(fn () => (new P($q))->deleteSetup($row['id'], 'Plainsight-Security-Agents'));
    eq(P::get($row['id'])['activation_key_id'], null, 'key deletion saved');
    $q->calls = [];
    (new P($q))->deleteSetup($row['id'], 'Plainsight-Security-Agents');
    eq($q->calls, ['deleteTag']);
    eq(prov_count(), 0);

    // Something already deleted in Qualys by hand counts as deleted.
    $row = (new P($q))->start($org, 'Plainsight-Security-Agents', 1);
    $q->keys = [];
    $q->tags = [];
    (new P($q))->deleteSetup($row['id'], 'Plainsight-Security-Agents');
    eq(prov_count(), 0);
});

test('Delete needs the tag name typed exactly, and works on linked set-ups too', function () {
    $q = new FakeQualys();
    [$org, $keyId] = seed_existing_setup($q);
    $row = (new P($q))->linkExisting($org, 80, 1);
    $q->calls = [];
    foreach (['', 'faicetechagents', 'FaiceTech', 'FaiceTechAgents2'] as $typed) {
        $e = throws(fn () => (new P($q))->deleteSetup($row['id'], $typed));
        ok(str_contains($e->getMessage(), 'Nothing was deleted'), "'$typed' refused");
    }
    eq($q->calls, [], 'no Qualys call for a wrong name');
    eq(prov_count(), 1);

    (new P($q))->deleteSetup($row['id'], ' FaiceTechAgents ');
    eq($q->calls, ['deleteKey', 'deleteTag']);
    eq([$q->tags, $q->keys], [[], []], 'key and tag gone from Qualys');
    eq((int)Database::getConnection()->query('SELECT COUNT(*) FROM tags WHERE id = 80')->fetchColumn(), 0, 'local tag gone');
    eq(Org::get($org)['tag_ids'], [], 'organisation has no tag');
    eq(prov_count(), 0);
});

test('Delete of a set-up that used an existing tag deletes that tag too', function () {
    $org = seed_setup_org();
    $q = new FakeQualys();
    $existing = $q->addTag('Plainsight-Security-Agents');
    $e = throws(fn () => (new P($q))->start($org, 'Plainsight-Security-Agents', 1), AgentTagExistsException::class);
    $row = (new P($q))->resume($e->provisioningId, $existing);
    eq($row['origin'], 'existing_tag');
    $q->calls = [];
    (new P($q))->deleteSetup($row['id'], 'Plainsight-Security-Agents');
    eq($q->calls, ['deleteKey', 'deleteTag']);
    eq([$q->tags, $q->keys], [[], []]);
});

test('deleting an organisation deletes its set-up record, freeing the name', function () {
    $org = seed_setup_org();
    $q = new FakeQualys();
    (new P($q))->start($org, 'Plainsight-Security-Agents', 1);
    Org::delete($org);
    eq(prov_count(), 0);
    // The tag is still in Qualys, so reusing the name goes to the admin's choice.
    $org2 = Org::create('New Name', [], null);
    throws(fn () => (new P($q))->start($org2, 'Plainsight-Security-Agents', 1), AgentTagExistsException::class);
});

// --- parsing Qualys's key responses -----------------------------------------

test('activation key responses: UUIDs normalised, Tag and TagSimple both read, unusable keys skipped', function () {
    require_once __DIR__ . '/../../scripts/lib/QualysApiClient.php';
    $client = new VulnDash\Scripts\QualysApiClient('http://127.0.0.1:9', 'u', 'p');
    $file = tempnam(sys_get_temp_dir(), 'vdkey');
    file_put_contents($file, '<?xml version="1.0" encoding="UTF-8"?><ServiceResponse><responseCode>SUCCESS</responseCode><count>3</count>'
        . '<hasMoreRecords>true</hasMoreRecords><data>'
        . '<AgentActKey><id>11</id><activationKey>0888D22D-C088-4E0E-85C3-E4F60F3F3582</activationKey><title>Acme-Agents</title>'
        . '<tags><list><Tag><id>501</id><name>Acme-Agents</name></Tag></list></tags></AgentActKey>'
        . '<AgentActKey><id>12</id><activationKey>1888d22d-c088-4e0e-85c3-e4f60f3f3582</activationKey><title>Other</title>'
        . '<tags><list><TagSimple><id>502</id></TagSimple></list></tags></AgentActKey>'
        . '<AgentActKey><id>13</id><activationKey>not-a-uuid</activationKey><title>Broken</title></AgentActKey>'
        . '</data></ServiceResponse>');
    $xml = (new ReflectionMethod($client, 'qpsSuccessXml'))->invoke($client, $file, 'test');
    $keys = (new ReflectionMethod($client, 'parseActivationKeys'))->invoke($client, $xml);
    eq(array_keys($keys), [11, 12]);
    eq($keys[11]['activation_key'], '0888d22d-c088-4e0e-85c3-e4f60f3f3582');
    eq($keys[11]['tag_ids'], [501]);
    eq($keys[12]['tag_ids'], [502]);
    eq((new ReflectionMethod($client, 'qpsHasMoreRecords'))->invoke($client, $file), true);

    file_put_contents($file, '<?xml version="1.0"?><ServiceResponse><responseCode>INVALID_REQUEST</responseCode>'
        . '<responseErrorDetails><errorMessage>Title already exists</errorMessage></responseErrorDetails></ServiceResponse>');
    $e = throws(fn () => (new ReflectionMethod($client, 'qpsSuccessXml'))->invoke($client, $file, 'Create Activation Key'));
    ok(str_contains($e->getMessage(), 'Title already exists'), 'Qualys error surfaced');
    unlink($file);
});

// --- the page -----------------------------------------------------------------

test('Agent Setup page: admin only, suggests the name, rejects a bad one for free', function () {
    seed_setup_org();
    $out = render_page('admin/agent_setup.php');
    ok(!str_contains($out, 'PHPERR'), $out);
    ok(str_contains($out, 'value="Plainsight-Security-Agents"'), 'suggested name filled in');
    ok(str_contains(render_page('admin/agent_setup.php', '', 'client'), '403 Forbidden'), 'client refused');

    render_page('admin/agent_setup.php', '', 'admin', 'action=start&organisation_id=1&tag_name=' . urlencode('Plainsight Security'));
    eq(prov_count(), 0, 'nothing reserved');
    eq((int)Database::getConnection()->query('SELECT COUNT(*) FROM qualys_api_call_log')->fetchColumn(), 0, 'no API call');
});

test('Agent Setup page: a Qualys failure leaves a retryable set-up and logs the call', function () {
    $org = seed_setup_org();
    // tests/config.test.php points Qualys at a closed port.
    $out = render_page('admin/agent_setup.php', '', 'admin', "action=start&organisation_id={$org}&tag_name=Plainsight-Security-Agents");
    ok(!str_contains($out, 'PHPERR'), $out);
    $row = P::listForAdmin()[0]['setup'];
    eq($row['status'], 'in_progress');
    ok(str_contains((string)$row['last_error'], 'Qualys'), 'error kept: ' . $row['last_error']);
    eq(Database::getConnection()->query('SELECT endpoint FROM qualys_api_call_log')->fetchColumn(), '/qps/rest/2.0/search/am/tag', 'call logged');

    $page = render_page('admin/agent_setup.php');
    ok(str_contains($page, 'Retry') && str_contains($page, 'Stopped partway'), 'offers Retry');
});

test('Agent Setup page: Link, Delete and Unlink render and act', function () {
    $q = new FakeQualys();
    [$org] = seed_existing_setup($q);
    $other = Org::create('Wavehill Ltd', [], null);
    $pdo = Database::getConnection();
    $pdo->exec("INSERT INTO tags (id, qualys_tag_id, name, agent_activation_id) VALUES (90, '5001', 'Wavehill-Ltd-Agents', '00000000-0000-4000-8000-000000000090')");
    $pdo->exec("INSERT INTO agent_provisioning (id, organisation_id, tag_name, qualys_tag_id, activation_key_id, activation_key, local_tag_id, status, completed_at)
                VALUES (5, $other, 'Wavehill-Ltd-Agents', 5001, 6001, '00000000-0000-4000-8000-000000000090', 90, 'complete', NOW())");

    $out = render_page('admin/agent_setup.php');
    ok(!str_contains($out, 'PHPERR'), $out);
    ok(str_contains($out, 'Link existing: FaiceTechAgents'), 'Link offered');
    ok(!str_contains($out, 'value="FaiceTech-Agents"'), 'no Create for an organisation already set up');
    ok(str_contains($out, 'Delete&hellip;') && str_contains($out, '>Unlink<'), 'Delete and Unlink offered');
    ok(str_contains($out, 'Type <strong class="mono">Wavehill-Ltd-Agents</strong> to confirm'), 'asks for the name');

    // Qualys is unreachable in tests: Link and Delete fail safely, changing nothing.
    render_page('admin/agent_setup.php', '', 'admin', "action=link&organisation_id={$org}&tag_id=80");
    eq(prov_count(), 1, 'nothing linked');
    $calls = (int)$pdo->query('SELECT COUNT(*) FROM qualys_api_call_log')->fetchColumn();
    render_page('admin/agent_setup.php', '', 'admin', 'action=delete&provisioning_id=5&confirm_tag_name=wavehill');
    eq((int)$pdo->query('SELECT COUNT(*) FROM qualys_api_call_log')->fetchColumn(), $calls, 'wrong name: no Qualys call');
    eq(P::get(5)['last_error'], null, 'wrong name: nothing attempted');
    render_page('admin/agent_setup.php', '', 'admin', 'action=delete&provisioning_id=5&confirm_tag_name=Wavehill-Ltd-Agents');
    ok(str_contains((string)P::get(5)['last_error'], 'Delete stopped'), 'delete failure recorded');
    eq((int)$pdo->query('SELECT COUNT(*) FROM tags WHERE id = 90')->fetchColumn(), 1, 'local tag kept');

    render_page('admin/agent_setup.php', '', 'admin', 'action=unlink&provisioning_id=5');
    eq(prov_count(), 0, 'unlinked');
    eq((int)$pdo->query('SELECT COUNT(*) FROM tags WHERE id = 90')->fetchColumn(), 1, 'unlink keeps the tag');
    eq(audit_rows()[count(audit_rows()) - 1][0], 'admin.agent_setup_unlinked');
});
