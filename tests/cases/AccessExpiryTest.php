<?php
declare(strict_types=1);

// Tag access end dates (src/Lib/AccessExpiry.php): the date is the last day
// a tag is visible to client accounts. After it, the tag drops out of every
// non-admin account's scope (own tags or organisation's) - so an MSP keeps
// its other clients - while admins still see everything. Nobody is locked
// out; a client with nothing left signs in to an empty view with a notice.
// Plus the notices, the Tags table on Manage Users and the admin emails
// (src/Lib/AccessExpiryAlerts.php).
//
// seed_estate(): tag 1 ClientA (host-a), tag 2 ClientB (host-b), admin
// (user 1), client (user 2) with ClientA only.

use VulnDash\Lib\AccessExpiry;
use VulnDash\Lib\AccessExpiryAlerts;
use VulnDash\Lib\Auth;
use VulnDash\Lib\Database;
use VulnDash\Lib\UserRepository;

function day_offset(int $days): string
{
    return (new DateTimeImmutable(AccessExpiry::today()))->modify(($days >= 0 ? '+' : '') . $days . ' days')->format('Y-m-d');
}

function tag_ends(int $tagId, ?string $date): void
{
    UserRepository::setTagExpiresOn($tagId, $date);
}

/** The client as an MSP: ClientA and ClientB. */
function client_sees_both(): void
{
    Database::getConnection()->exec('INSERT INTO user_tags (user_id, tag_id) VALUES (2, 2)');
}

function expiry_mail(callable $fn): array
{
    $log = tempnam(sys_get_temp_dir(), 'vdmail');
    putenv("VULNDASH_MAIL_LOG=$log");
    try {
        $r = $fn();
        return [$r, array_values(array_map(fn ($l) => json_decode($l, true), array_filter(explode("\n", (string)file_get_contents($log)))))];
    } finally {
        putenv('VULNDASH_MAIL_LOG');
        unlink($log);
    }
}

test('rules: last day inclusive, notices, dates validated', function () {
    $t = '2027-03-01';
    ok(!AccessExpiry::isExpired('2027-03-01', $t) && AccessExpiry::isExpired('2027-02-28', $t), 'inclusive');
    eq([AccessExpiry::daysLeft('2027-03-01', $t), AccessExpiry::daysLeft('2027-03-30', $t), AccessExpiry::daysSinceEnded('2027-02-28', $t)], [1, 30, 1]);
    eq(AccessExpiry::notice('Acme', '2027-03-31', true, $t), null, '31 days out: nothing');
    eq(AccessExpiry::notice('Acme', '2027-03-30', true, $t), 'Access to Acme ends on Tue 30 Mar 2027 (in 30 days). To keep it, contact Plainsight Security about renewing.');
    eq(AccessExpiry::notice('Acme', '2027-03-01', true, $t), 'Access to Acme ends today. To keep it, contact Plainsight Security about renewing.');
    eq(AccessExpiry::notice('Acme', '2027-02-28', true, $t), 'Access to Acme ended on Sun 28 Feb 2027. To renew it, contact Plainsight Security.');
    eq(AccessExpiry::notice('Acme', '2027-01-01', true, $t), null, 'ended long ago, other tags still live: dropped');
    ok(AccessExpiry::notice('Acme', '2026-01-01', false, $t) !== null, 'nothing left to see: always explained');
    eq(AccessExpiry::notice('Acme', null, false, $t), null);
    eq([AccessExpiry::parse(''), AccessExpiry::parse(' 2027-03-01 ')], [null, '2027-03-01']);
    foreach (['2027-02-30', '01/03/2027', 'soon', '1999-12-31'] as $bad) {
        try {
            AccessExpiry::parse($bad);
            throw new TestFailure("accepted $bad");
        } catch (RuntimeException $e) {
            ok(!$e instanceof TestFailure, $e->getMessage());
        }
    }
});

test('an MSP loses only the ended tag; admins keep everything; the last day still counts', function () {
    seed_estate();
    client_sees_both();
    tag_ends(2, AccessExpiry::today());
    eq(UserRepository::getEffectiveTagIds(2), [1, 2], 'last day: still visible');

    tag_ends(2, day_offset(-1));
    eq(UserRepository::getEffectiveTagIds(2), [1], 'ClientB gone, ClientA kept');
    eq(UserRepository::getSessionAccount(2)['tag_ids'], [1], 'session scope too');
    eq(UserRepository::getSessionAccount(2)['is_active'], true, 'account itself untouched');

    $page = render_page('vulnerabilities.php', '', 'client');
    ok(!str_contains($page, 'PHPERR'), $page);
    ok(str_contains($page, 'host-a') && !str_contains($page, 'host-b'), 'list shows ClientA only');
    $csv = render_page('report_csv.php', '', 'client');
    ok(str_contains($csv, 'host-a') && !str_contains($csv, 'host-b'), 'exports follow');
    ok(str_contains(render_page('vulnerabilities.php', '', 'admin'), 'host-b'), 'admin still sees ClientB');

    tag_ends(2, day_offset(365));
    eq(UserRepository::getEffectiveTagIds(2), [1, 2], 'renewed');
});

test('a tag that came through the organisation drops out the same way', function () {
    seed_estate();
    $pdo = Database::getConnection();
    $pdo->exec("INSERT INTO organisations (id, name) VALUES (1, 'MSP Ltd')");
    $pdo->exec('INSERT INTO organisation_tags (organisation_id, tag_id) VALUES (1, 2)');
    $pdo->exec('UPDATE users SET organisation_id = 1 WHERE id = 2');
    eq(UserRepository::getEffectiveTagIds(2), [1, 2]);
    tag_ends(2, day_offset(-3));
    eq(UserRepository::getEffectiveTagIds(2), [1]);
});

test('with every tag ended the client still signs in, sees nothing, and is told why', function () {
    seed_estate();
    tag_ends(1, day_offset(-2));
    eq(Auth::attemptLogin('client', 'pw-123456789'), Auth::RESULT_SUCCESS, 'not locked out');
    eq(UserRepository::getSessionAccount(2)['tag_ids'], [], 'sees nothing');
    $page = render_page('dashboard.php', '', 'client');
    ok(!str_contains($page, 'PHPERR'), $page);
    ok(!str_contains($page, 'host-a'), 'no data');
    ok(str_contains($page, 'Access to ClientA ended on ' . AccessExpiry::display(day_offset(-2)) . '. To renew it, contact Plainsight Security.'), 'notice');

    tag_ends(1, day_offset(-400));
    ok(str_contains(render_page('dashboard.php', '', 'client'), 'Access to ClientA ended on'), 'still explained long after, with nothing left');
});

test('notices: in the last 30 days, per tag, for clients and view-as only', function () {
    seed_estate();
    client_sees_both();
    tag_ends(1, day_offset(40));
    ok(!str_contains(render_page('dashboard.php', '', 'client'), 'access-ending-bar'), 'none at 40 days');

    tag_ends(1, day_offset(9));
    tag_ends(2, day_offset(-1));
    $page = render_page('dashboard.php', '', 'client');
    ok(str_contains($page, 'Access to ClientA ends on ' . AccessExpiry::display(day_offset(9)) . ' (in 10 days)'), 'ending');
    ok(str_contains($page, 'Access to ClientB ended on'), 'ended, still within 30 days');
    ok(str_contains(render_page('dashboard.php', '', 'as_client'), 'Access to ClientA ends on'), 'admin viewing as sees it');
    ok(!str_contains(render_page('dashboard.php', '', 'admin'), 'access-ending-bar'), 'never for the admin themselves');
});

test('no KEV email for an ended tag\'s assets', function () {
    seed_estate();
    run_kev_alerts();                     // baseline (from KevAlertTest.php)
    tag_ends(1, day_offset(-1));
    new_kev_finding(1, 6001);             // host-a, ClientA
    [, , $mails] = run_kev_alerts();
    eq(array_column($mails, 'to'), ['admin@test'], 'admin only - the client no longer sees ClientA');
});

test('Tags table: set, clear and reject an end date; badges; audit; admin only', function () {
    seed_estate();
    $d = day_offset(20);
    $out = render_page('admin/users.php', '', 'admin', "action=set_tag_access_until&tag_id=1&expires_on=$d");
    ok(!str_contains($out, 'PHPERR'), $out);
    $date = fn () => Database::getConnection()->query('SELECT expires_on FROM tags WHERE id = 1')->fetchColumn();
    eq($date(), $d);
    $page = render_page('admin/users.php', '', 'admin');
    ok(str_contains($page, 'name="expires_on" value="' . $d . '"') && str_contains($page, '21d left'), 'shown with days left');

    render_page('admin/users.php', '', 'admin', 'action=set_tag_access_until&tag_id=1&expires_on=2027-02-30');
    eq($date(), $d, 'invalid date rejected');
    tag_ends(1, day_offset(-1));
    ok(str_contains(render_page('admin/users.php', '', 'admin'), '>Ended</span>'), 'ended badge');
    render_page('admin/users.php', '', 'admin', 'action=set_tag_access_until&tag_id=1&expires_on=');
    eq($date(), null, 'cleared');

    $rows = array_values(array_filter(audit_rows(), fn ($r) => $r[0] === 'admin.tag_access_until'));
    eq(array_map(fn ($r) => [$r[2], $r[3]['after']], $rows), [['ClientA', $d], ['ClientA', null]]);
    ok(str_contains(render_page('admin/users.php', '', 'client', "action=set_tag_access_until&tag_id=1&expires_on=$d"), '403 Forbidden'), 'client refused');
});

test('admin emails: 30 days before, once; when it ends, once; a new date starts afresh', function () {
    seed_estate();
    tag_ends(1, '2027-03-01');
    [$r, $mails] = expiry_mail(fn () => AccessExpiryAlerts::check('2027-01-29'));
    eq([$r['lines'], count($mails)], [[], 0], 'too early');

    [$r, $mails] = expiry_mail(fn () => AccessExpiryAlerts::check('2027-01-31'));
    eq(count($r['lines']), 1);
    ok(str_contains($r['lines'][0], 'ClientA (1 client account): access ends after Mon 1 Mar 2027 - 30 days left'), $r['lines'][0]);
    eq(array_column($mails, 'to'), ['admin@test'], 'admins only');
    ok(str_contains($mails[0]['subject'], 'client access ending') && str_contains($mails[0]['text'], '/admin/users#tags'), 'subject and link');
    eq(expiry_mail(fn () => AccessExpiryAlerts::check('2027-02-15'))[0]['lines'], [], 'not repeated');
    eq(expiry_mail(fn () => AccessExpiryAlerts::check('2027-03-01'))[0]['lines'], [], 'last day: nothing new');

    [$r, $mails] = expiry_mail(fn () => AccessExpiryAlerts::check('2027-03-02'));
    ok(count($mails) === 1 && str_contains($r['lines'][0], 'access ended after Mon 1 Mar 2027 - client accounts no longer see its assets'), 'ended');
    eq(expiry_mail(fn () => AccessExpiryAlerts::check('2027-03-03'))[0]['lines'], [], 'ended not repeated');

    tag_ends(1, '2028-03-01');            // renewed
    [$r] = expiry_mail(fn () => AccessExpiryAlerts::check('2028-02-01'));
    ok(count($r['lines']) === 1 && str_contains($r['lines'][0], '30 days left'), 'new date warned afresh');
});

test('admin emails: dry run saves nothing; a missed send is retried; the script runs', function () {
    seed_estate();
    tag_ends(2, day_offset(5));
    [$r] = expiry_mail(fn () => AccessExpiryAlerts::check(null, true));
    eq(count($r['lines']), 1, 'dry run reports');
    eq((int)Database::getConnection()->query("SELECT COUNT(*) FROM sync_state WHERE sync_type = 'access_expiry_alerts'")->fetchColumn(), 0, 'dry run saved nothing');

    Database::getConnection()->exec('UPDATE users SET is_admin = 0 WHERE id = 1');   // nobody to send to
    [$r, $mails] = expiry_mail(fn () => AccessExpiryAlerts::check());
    ok(count($r['lines']) === 1 && $mails === [] && $r['sent_to'] === [], 'unsent');
    Database::getConnection()->exec('UPDATE users SET is_admin = 1 WHERE id = 1');

    $log = tempnam(sys_get_temp_dir(), 'vdmail');
    $proc = proc_open([PHP_BINARY, __DIR__ . '/../../scripts/send_expiry_alerts.php'],
        [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, getenv() + ['VULNDASH_MAIL_LOG' => $log]);
    $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
    $code = proc_close($proc);
    $sentLines = count(array_filter(explode("\n", (string)file_get_contents($log))));
    unlink($log);
    ok($code === 0 && $sentLines === 1 && str_contains($out, 'Emailed: admin@test'), 'retried by the script: ' . $out);
});
