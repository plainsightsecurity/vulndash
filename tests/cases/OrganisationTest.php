<?php
declare(strict_types=1);

// Client organisations: effective tags (own extras + active organisation's),
// suspension, the admin Organisations page, Manage Users integration, the
// organisation admin page and its user limit, and CSV import.
//
// seed_estate(): tag 1 ClientA (host-a, "Critical remote code execution"),
// tag 2 ClientB (host-b, "High severity flaw"); user 1 admin, user 2 client
// (own tag ClientA).

use VulnDash\Lib\Auth;
use VulnDash\Lib\Database;
use VulnDash\Lib\KevAlertRepository;
use VulnDash\Lib\OrganisationRepository as Org;
use VulnDash\Lib\UserImport;
use VulnDash\Lib\UserRepository as U;

/** Org "Wavehill" (tag 2) with user 2 as its organisation admin, plus member user 3. */
function seed_org(?int $maxUsers = null): int
{
    seed_estate();
    $orgId = Org::create('Wavehill', [2], $maxUsers);
    U::setOrganisation(2, $orgId, true);
    Database::getConnection()->prepare("INSERT INTO users (id, username, email, password_hash, organisation_id) VALUES (3, 'member', 'member@example.com', 'x', ?)")
        ->execute([$orgId]);
    return $orgId;
}

function sorted(array $a): array
{
    $a = array_map('intval', $a);
    sort($a);
    return $a;
}

function post_capturing_mail(string $page, string $post, string $role = 'admin'): array
{
    $log = tempnam(sys_get_temp_dir(), 'vdmail');
    putenv("VULNDASH_MAIL_LOG=$log");
    try {
        $out = render_page($page, '', $role, $post);
    } finally {
        putenv('VULNDASH_MAIL_LOG');
    }
    $mails = array_map(fn ($l) => json_decode($l, true), array_filter(explode("\n", (string)file_get_contents($log))));
    unlink($log);
    return [$out, $mails];
}

// --- access -----------------------------------------------------------------

test('members see their organisation\'s tags plus their own extras', function () {
    seed_org();
    eq(sorted(U::getEffectiveTagIds(2)), [1, 2], 'own ClientA + org ClientB');
    eq(sorted(U::getEffectiveTagIds(3)), [2], 'org only');
    eq(sorted(U::getSessionAccount(2)['tag_ids']), [1, 2]);
    eq(U::getUserTagIds(2), [1], 'own tags unchanged');
    eq(U::getSessionAccount(2)['is_org_admin'], true);
});

test('changing the organisation\'s tags changes every member at once', function () {
    $org = seed_org();
    Org::update($org, 'Wavehill', [1, 2], null);
    eq(sorted(U::getSessionAccount(3)['tag_ids']), [1, 2]);
    Org::update($org, 'Wavehill', [], null);
    eq(U::getSessionAccount(3)['tag_ids'], [], 'fails closed to nothing');
});

test('a member sees the organisation\'s data on the dashboard', function () {
    seed_org();
    Database::getConnection()->exec('DELETE FROM user_tags WHERE user_id = 2');
    $out = render_page('vulnerabilities.php', '', 'client');
    ok(!str_contains($out, 'PHPERR'), $out);
    ok(str_contains($out, 'High severity flaw'), 'ClientB via the organisation');
    ok(!str_contains($out, 'Critical remote code execution'), 'not ClientA');
});

test('suspending an organisation signs members out, blocks sign-in and stops emails', function () {
    $org = seed_org();
    Database::getConnection()->exec("UPDATE users SET kev_alerts = 1, email = 'client@example.com' WHERE id = 2");
    ok(in_array(2, array_column(KevAlertRepository::recipients(), 'id'), true), 'gets KEV alerts while active');
    Org::setActive($org, false);
    eq(U::getSessionAccount(2)['is_active'], false, 'session ends');
    eq(U::getEffectiveTagIds(2), [1], 'organisation tags gone');
    ok(!in_array(2, array_column(KevAlertRepository::recipients(), 'id'), true), 'no KEV alerts');
    eq(Auth::attemptLogin('client', 'pw-123456789'), Auth::RESULT_FAILED, 'cannot sign in');
    Org::setActive($org, true);
    eq(U::getSessionAccount(2)['is_active'], true);
});

test('deleting an organisation keeps its accounts with only their own tags', function () {
    $org = seed_org();
    Org::delete($org);
    $u = U::getUser(2);
    eq([$u['organisation_id'], (int)$u['is_org_admin']], [null, 0]);
    eq(U::getEffectiveTagIds(2), [1]);
});

// --- admin pages ----------------------------------------------------------------

test('admin Organisations page: create, update, suspend, delete - all audited', function () {
    seed_estate();
    $out = render_page('admin/organisations.php', '', 'admin', 'action=create&name=Acme&max_users=5&tag_ids[]=1');
    ok(!str_contains($out, 'PHPERR'), $out);
    $org = Org::findByName('Acme');
    eq([$org['max_users'], $org['tag_ids']], [5, [1]]);
    render_page('admin/organisations.php', '', 'admin', "action=update&organisation_id={$org['id']}&name=Acme+Ltd&max_users=&tag_ids[]=1&tag_ids[]=2");
    $org = Org::get($org['id']);
    eq([$org['name'], $org['max_users'], sorted($org['tag_ids'])], ['Acme Ltd', null, [1, 2]]);
    render_page('admin/organisations.php', '', 'admin', "action=toggle_active&organisation_id={$org['id']}");
    eq(Org::get($org['id'])['is_active'], false);
    render_page('admin/organisations.php', '', 'admin', "action=delete&organisation_id={$org['id']}");
    eq(Org::get($org['id']), null);
    eq(array_column(audit_rows(), 0), ['admin.org_created', 'admin.org_updated', 'admin.org_suspended', 'admin.org_deleted']);

    $out = render_page('admin/organisations.php');
    ok(str_contains($out, 'Add an organisation') && !str_contains($out, 'PHPERR'), 'renders');
    $out = render_page('admin/organisations.php', '', 'client');
    ok(str_contains($out, '403 Forbidden'), 'clients refused');
});

test('Manage Users: assign organisation, filter by it, and org tags count in the tag filter', function () {
    $org = seed_org();
    render_page('admin/users.php', '', 'admin', "action=set_organisation&user_id=3&organisation_id=&is_org_admin=1");
    eq(U::getUser(3)['organisation_id'], $org, 'refused: would see nothing');
    render_page('admin/users.php', '', 'admin', "action=set_organisation&user_id=2&organisation_id={$org}");
    eq((int)U::getUser(2)['is_org_admin'], 0, 'org admin flag cleared when unticked');
    eq(array_column(U::listUsers(null, null, 'username', 'asc', $org), 'username'), ['client', 'member']);
    eq(array_column(U::listUsers(null, null, 'username', 'asc', U::TAG_FILTER_NONE), 'username'), ['admin']);
    eq(array_column(U::listUsers(null, 2), 'username'), ['client', 'member'], 'ClientB via the organisation');
    $out = render_page('admin/users.php', 'org=' . $org);
    ok(!str_contains($out, 'PHPERR'), $out);
    ok(str_contains($out, '<option value="' . $org . '" selected>Wavehill</option>'), 'filter selected');
    ok(str_contains($out, 'action" value="set_organisation"'), 'organisation control in Manage');
});

test('Manage Users: create an account into an organisation with no extra tags', function () {
    $org = seed_org();
    [, $mails] = post_capturing_mail('admin/users.php', "action=create_user&username=newbie&email=newbie@example.com&organisation_id={$org}&is_org_admin=1");
    $u = U::findByUsernameOrEmail('newbie');
    ok($u !== null, 'created');
    $u = U::getUser((int)$u['id']);
    eq([(int)$u['organisation_id'], (int)$u['is_org_admin']], [$org, 1]);
    eq(count($mails), 1);
});

// --- organisation admin page ----------------------------------------------------

test('only organisation admins reach /org/users', function () {
    seed_org();
    ok(str_contains(render_page('org/users.php', '', 'client'), 'Wavehill'), 'org admin');
    ok(str_contains(render_page('org/users.php', '', 'admin'), '403 Forbidden'), 'Plainsight Security admin uses /admin');
    Database::getConnection()->exec('UPDATE users SET is_org_admin = 0 WHERE id = 2');
    ok(str_contains(render_page('org/users.php', '', 'client'), '403 Forbidden'), 'plain member');
});

test('org admin invites into their own organisation only, within the limit', function () {
    $org = seed_org(3); // client + member = 2 active
    [$out, $mails] = post_capturing_mail('org/users.php', 'action=invite&username=third&email=third@example.com&is_admin=1&organisation_id=999&tag_ids[]=1', 'client');
    ok(!str_contains($out, 'PHPERR'), $out);
    $u = U::getUser((int)U::findByUsernameOrEmail('third')['id']);
    eq([(int)$u['organisation_id'], (bool)$u['is_admin'], (int)$u['is_org_admin'], U::getUserTagIds((int)$u['id'])], [$org, false, 0, []], 'ignores smuggled fields');
    eq(count($mails), 1);
    ok(str_contains($mails[0]['subject'], 'Set up'), 'setup link');

    post_capturing_mail('org/users.php', 'action=invite&username=fourth&email=fourth@example.com', 'client');
    eq(U::findByUsernameOrEmail('fourth'), null, 'limit of 3 reached');

    render_page('org/users.php', '', 'client', 'action=toggle_active&user_id=3');
    eq((bool)U::getUser(3)['is_active'], false, 'deactivating frees a place');
    post_capturing_mail('org/users.php', 'action=invite&username=fourth&email=fourth@example.com', 'client');
    ok(U::findByUsernameOrEmail('fourth') !== null, 'now fits');
    render_page('org/users.php', '', 'client', 'action=toggle_active&user_id=3');
    eq((bool)U::getUser(3)['is_active'], false, 'reactivating refused at the limit');
    eq(audit_rows()[0][0] ?? null, 'org.user_invited');
});

test('org admin cannot touch other organisations, admins, other org admins or themselves', function () {
    seed_org();
    Database::getConnection()->exec("INSERT INTO users (id, username, email, password_hash) VALUES (4, 'outsider', 'out@example.com', 'x')");
    $other = Org::create('Other', [1], null);
    Database::getConnection()->exec("UPDATE users SET organisation_id = {$other} WHERE id = 4");
    Database::getConnection()->exec("INSERT INTO users (id, username, email, password_hash, organisation_id, is_org_admin) VALUES (5, 'coadmin', 'co@example.com', 'x', " . (int)U::getUser(2)['organisation_id'] . ', 1)');
    foreach ([1, 2, 4, 5] as $id) {
        render_page('org/users.php', '', 'client', "action=toggle_active&user_id={$id}");
        eq((bool)U::getUser($id)['is_active'], true, "user {$id} untouched");
        [, $mails] = post_capturing_mail('org/users.php', "action=send_link&user_id={$id}", 'client');
        eq($mails, [], "no link for user {$id}");
    }
    $out = render_page('org/users.php', '', 'client');
    ok(!str_contains($out, 'outsider') && str_contains($out, 'member'), 'lists own organisation only');
});

// --- CSV import -------------------------------------------------------------

test('CSV import: valid file parses; org, extra tags and org_admin resolved', function () {
    seed_org();
    $r = UserImport::parse("\xEF\xBB\xBFUsername,Email,Organisation,Tags,Org_Admin\r\n"
        . "a1,a1@example.com,wavehill,,yes\r\n"
        . "b2,b2@example.com,,ClientA;clientb,\r\n");
    eq($r['errors'], []);
    eq(count($r['rows']), 2);
    eq([$r['rows'][0]['organisation'], $r['rows'][0]['org_admin'], $r['rows'][1]['tag_ids']], ['Wavehill', true, [1, 2]]);
});

test('CSV import: any bad row means nothing is created, with every problem listed', function () {
    seed_org();
    $r = UserImport::parse("username,email,organisation,tags,org_admin\n"
        . "ok1,ok1@example.com,Wavehill,,\n"
        . "client,dup@example.com,,ClientA,\n"
        . "x,bad@example.co.u,Nope,Missing,maybe\n"
        . "y,ok1@example.com,,,yes\n"
        . "z,z@example.com,,,\n");
    eq($r['rows'], []);
    eq(count($r['errors']), 4, implode(' | ', $r['errors']));
    ok(str_contains($r['errors'][0], 'Line 3') && str_contains($r['errors'][0], 'already in use'), $r['errors'][0]);
    foreach (['".u"', 'no organisation called "Nope"', 'no tag called "Missing"', 'org_admin must be yes or no'] as $bit) {
        ok(str_contains($r['errors'][1], $bit), "line 4 mentions {$bit}: {$r['errors'][1]}");
    }
    ok(str_contains($r['errors'][2], 'also on line 2') && str_contains($r['errors'][2], 'needs an organisation'), $r['errors'][2]);
    ok(str_contains($r['errors'][3], 'would see no data'), $r['errors'][3]);
    eq(UserImport::parse("user,email\nx,x@example.com")['rows'], [], 'bad header');
});

test('CSV import through Manage Users creates accounts and emails them, or not', function () {
    $org = seed_org(2); // already full: a warning, not a block, for Plainsight Security admins
    $csv = tempnam(sys_get_temp_dir(), 'vdcsv');
    file_put_contents($csv, "username,email,organisation\nn1,n1@example.com,Wavehill\nn2,n2@example.com,Wavehill\n");
    $parsed = UserImport::parse((string)file_get_contents($csv));
    eq(count($parsed['warnings']), 1, 'over-limit warning');
    $sent = [];
    $result = UserImport::run($parsed['rows'], true, function (int $id, string $email) use (&$sent): bool {
        $sent[] = $email;
        return true;
    });
    eq($result['created'], ['n1', 'n2']);
    eq($sent, ['n1@example.com', 'n2@example.com']);
    eq((int)U::getUser((int)U::findByUsernameOrEmail('n1')['id'])['organisation_id'], $org);
    $result = UserImport::run(UserImport::parse("username,email,tags\nn3,n3@example.com,ClientA\n")['rows'], false, fn () => throw new \LogicException('must not send'));
    eq($result['created'], ['n3']);
    unlink($csv);
    $out = render_page('admin/users.php');
    ok(str_contains($out, 'Import from CSV') && str_contains($out, 'enctype="multipart/form-data"'), 'panel renders');
});
