<?php
declare(strict_types=1);

// Access end dates (src/Lib/AccessExpiry.php): the date is the last day of
// access, a member gets the earlier of their own and their organisation's,
// admins never expire, and an expired account is refused at sign-in, signed
// out mid-session, gets no emails and sees nothing - until the date is moved
// on. Plus the client banner, the admin pages and the admin emails
// (src/Lib/AccessExpiryAlerts.php).

use VulnDash\Lib\AccessExpiry;
use VulnDash\Lib\AccessExpiryAlerts;
use VulnDash\Lib\Auth;
use VulnDash\Lib\Database;
use VulnDash\Lib\SessionTimeout;
use VulnDash\Lib\UserRepository;

function day_offset(int $days, ?string $from = null): string
{
    return (new DateTimeImmutable($from ?? AccessExpiry::today()))->modify(($days >= 0 ? '+' : '') . $days . ' days')->format('Y-m-d');
}

function set_user_expiry(int $userId, ?string $date): void
{
    UserRepository::setExpiresOn($userId, $date);
}

/** Puts the client (user 2) in organisation 1 "Acme", with an optional org date. */
function client_in_org(?string $orgDate): void
{
    $pdo = Database::getConnection();
    $pdo->prepare("INSERT INTO organisations (id, name, expires_on) VALUES (1, 'Acme', :d)")->execute(['d' => $orgDate]);
    $pdo->exec('UPDATE users SET organisation_id = 1 WHERE id = 2');
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

test('rules: last day inclusive, earliest date wins, admins never expire, dates validated', function () {
    $t = '2027-03-01';
    ok(!AccessExpiry::isExpired('2027-03-01', $t), 'the date itself is still allowed');
    ok(AccessExpiry::isExpired('2027-02-28', $t), 'the day after is not');
    eq([AccessExpiry::daysLeft('2027-03-01', $t), AccessExpiry::daysLeft('2027-03-02', $t), AccessExpiry::daysLeft('2027-02-01', $t)], [1, 2, 0]);
    ok(AccessExpiry::isEnding('2027-03-30', $t) && !AccessExpiry::isEnding('2027-03-31', $t), '30 days left warns, 31 does not');
    eq(AccessExpiry::effective('2027-05-01', '2027-04-01', false), '2027-04-01');
    eq(AccessExpiry::effective(null, '2027-04-01', false), '2027-04-01');
    eq(AccessExpiry::effective(null, null, false), null);
    eq(AccessExpiry::effective('2020-01-01', '2020-01-01', true), null, 'admin');
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

test('sign-in: allowed on the last day, refused after with the date, and back once renewed', function () {
    seed_estate();
    set_user_expiry(2, AccessExpiry::today());
    eq(Auth::attemptLogin('client', 'pw-123456789'), Auth::RESULT_SUCCESS, 'last day');

    set_user_expiry(2, day_offset(-1));
    eq(Auth::attemptLogin('client', 'wrong-password'), Auth::RESULT_FAILED, 'wrong password says nothing about expiry');
    eq(Auth::attemptLogin('client', 'pw-123456789'), Auth::RESULT_EXPIRED, 'right password, expired');
    eq(Auth::lastAccessUntil(), day_offset(-1));
    ok(str_contains(AccessExpiry::endedMessage(day_offset(-1)), 'To renew it, contact Plainsight Security'), 'message');
    $last = audit_rows()[count(audit_rows()) - 1];
    eq([$last[0], $last[3]['reason'] ?? null], ['auth.login_failed', 'access expired']);

    set_user_expiry(2, day_offset(365));
    eq(Auth::attemptLogin('client', 'pw-123456789'), Auth::RESULT_SUCCESS, 'renewed');
    set_user_expiry(2, null);
    eq(Auth::attemptLogin('client', 'pw-123456789'), Auth::RESULT_SUCCESS, 'cleared');
});

test('an organisation date applies to its members, the earlier date wins, admins are exempt', function () {
    seed_estate();
    client_in_org(day_offset(-1));
    eq(Auth::attemptLogin('client', 'pw-123456789'), Auth::RESULT_EXPIRED, 'org date passed');
    set_user_expiry(2, day_offset(100));
    eq(Auth::attemptLogin('client', 'pw-123456789'), Auth::RESULT_EXPIRED, "a later personal date doesn't override the org's");
    Database::getConnection()->exec("UPDATE organisations SET expires_on = '" . day_offset(200) . "' WHERE id = 1");
    eq(Auth::attemptLogin('client', 'pw-123456789'), Auth::RESULT_SUCCESS, 'org renewed');
    eq(UserRepository::getSessionAccount(2)['access_until'], day_offset(100), 'the earlier (personal) date applies');

    set_user_expiry(1, day_offset(-5));
    eq(Auth::attemptLogin('admin', 'pw-123456789'), Auth::RESULT_SUCCESS, 'admin with a past date still signs in');
});

test('an expired account is inactive for its session, password resets and emails', function () {
    seed_estate();
    eq(UserRepository::getSessionAccount(2)['is_active'], true);
    set_user_expiry(2, day_offset(-1));
    $acct = UserRepository::getSessionAccount(2);
    eq([$acct['is_active'], $acct['expired'], $acct['access_until']], [false, true, day_offset(-1)]);
    eq((int)UserRepository::findByUsernameOrEmail('client')['is_active'], 0, 'no password reset email');
    $live = Database::getConnection()->query('SELECT username FROM users WHERE ' . UserRepository::ACCESS_NOT_EXPIRED_CONDITION . ' ORDER BY id')->fetchAll(PDO::FETCH_COLUMN);
    eq($live, ['admin'], 'notification/KEV recipient condition drops the expired client');

    $_SESSION['signed_out_reason'] = SessionTimeout::REASON_ACCESS_EXPIRED;
    $_SESSION['signed_out_access_until'] = '2027-03-01';
    eq(SessionTimeout::takeSignedOutMessage(), 'Your access ended on Mon 1 Mar 2027. To renew it, contact Plainsight Security.');
    eq(SessionTimeout::takeSignedOutMessage(), null, 'shown once');
});

test('pages: an open session ends, the banner shows in the last 30 days only', function () {
    seed_estate();
    set_user_expiry(2, day_offset(40));
    $page = render_page('dashboard.php', '', 'client');
    ok(!str_contains($page, 'PHPERR') && !str_contains($page, 'access-ending-bar'), 'no banner at 40 days');

    set_user_expiry(2, day_offset(9));
    $page = render_page('dashboard.php', '', 'client');
    ok(!str_contains($page, 'PHPERR'), $page);
    ok(str_contains($page, 'Your access ends on ' . AccessExpiry::display(day_offset(9)) . ' (in 10 days)'), 'banner with date and days');

    set_user_expiry(2, AccessExpiry::today());
    ok(str_contains(render_page('dashboard.php', '', 'client'), 'Your access ends today'), 'last day');

    set_user_expiry(2, day_offset(-1));
    $page = render_page('dashboard.php', '', 'client');
    ok(!str_contains($page, 'host-a') && !str_contains($page, 'site-main'), 'expired: the page is not served');
    eq(audit_rows()[count(audit_rows()) - 1][0], 'auth.access_expired');

    $page = render_page('dashboard.php', '', 'as_client');
    ok(!str_contains($page, 'PHPERR') && str_contains($page, 'This account&#039;s access ended on'), 'admin viewing as is told');
    ok(!str_contains(render_page('dashboard.php', '', 'admin'), 'access-ending-bar'), 'never for the admin themselves');
});

test('Manage Users: set, clear and reject an end date; badges; admins have none', function () {
    seed_estate();
    $d = day_offset(20);
    $out = render_page('admin/users.php', '', 'admin', "action=set_access_until&user_id=2&expires_on=$d");
    ok(!str_contains($out, 'PHPERR'), $out);
    eq(UserRepository::getUser(2)['expires_on'], $d);
    $page = render_page('admin/users.php', '', 'admin');
    ok(str_contains($page, 'name="expires_on" value="' . $d . '"'), 'shown in the form');
    ok(str_contains($page, 'badge-warn') && str_contains($page, 'Until ' . date('j M Y', strtotime($d))), 'ending-soon badge');

    render_page('admin/users.php', '', 'admin', 'action=set_access_until&user_id=2&expires_on=2027-02-30');
    eq(UserRepository::getUser(2)['expires_on'], $d, 'invalid date rejected');
    render_page('admin/users.php', '', 'admin', 'action=set_access_until&user_id=1&expires_on=' . $d);
    eq(UserRepository::getUser(1)['expires_on'], null, 'not for an admin');

    set_user_expiry(2, day_offset(-1));
    ok(str_contains(render_page('admin/users.php', '', 'admin'), '>Expired</span>'), 'expired badge');
    render_page('admin/users.php', '', 'admin', 'action=set_access_until&user_id=2&expires_on=');
    eq(UserRepository::getUser(2)['expires_on'], null, 'cleared');

    $rows = array_values(array_filter(audit_rows(), fn ($r) => $r[0] === 'admin.user_access_until'));
    eq(array_map(fn ($r) => $r[3]['after'], $rows), [$d, null]);
    ok(str_contains(render_page('admin/users.php', '', 'client', "action=set_access_until&user_id=2&expires_on=$d"), '403 Forbidden'), 'client refused');
});

test('Organisations: date set on create and edit, shown, and applied to members', function () {
    seed_estate();
    $d = day_offset(15);
    $out = render_page('admin/organisations.php', '', 'admin', "action=create&name=Beta+Ltd&max_users=&expires_on=$d");
    ok(!str_contains($out, 'PHPERR'), $out);
    $pdo = Database::getConnection();
    $id = (int)$pdo->query("SELECT id FROM organisations WHERE name = 'Beta Ltd'")->fetchColumn();
    eq($pdo->query("SELECT expires_on FROM organisations WHERE id = $id")->fetchColumn(), $d);
    $page = render_page('admin/organisations.php', '', 'admin');
    ok(str_contains($page, 'until ' . AccessExpiry::display($d)) && str_contains($page, '16d left'), 'shown with days left');

    $pdo->exec("UPDATE users SET organisation_id = $id WHERE id = 2");
    $past = day_offset(-2);
    render_page('admin/organisations.php', '', 'admin', "action=update&organisation_id=$id&name=Beta+Ltd&max_users=&expires_on=$past");
    eq(Auth::attemptLogin('client', 'pw-123456789'), Auth::RESULT_EXPIRED, 'member refused');
    ok(str_contains(render_page('admin/organisations.php', '', 'admin'), '>Expired</span>'), 'status shows Expired');
    render_page('admin/organisations.php', '', 'admin', "action=update&organisation_id=$id&name=Beta+Ltd&max_users=&expires_on=");
    eq(Auth::attemptLogin('client', 'pw-123456789'), Auth::RESULT_SUCCESS, 'cleared: member back');
    $upd = array_values(array_filter(audit_rows(), fn ($r) => $r[0] === 'admin.org_updated'));
    eq(array_map(fn ($r) => [$r[3]['before']['access_until'], $r[3]['after']['access_until']], $upd), [[$d, $past], [$past, null]]);
});

test('admin emails: 30 days before, once; when it ends, once; a new date starts afresh', function () {
    seed_estate();
    client_in_org('2027-03-01');
    [$r, $mails] = expiry_mail(fn () => AccessExpiryAlerts::check('2027-01-29'));   // 32 days left
    eq([$r['lines'], count($mails)], [[], 0], 'too early');

    [$r, $mails] = expiry_mail(fn () => AccessExpiryAlerts::check('2027-01-31'));   // 30 days left
    eq(count($r['lines']), 1);
    ok(str_contains($r['lines'][0], 'Organisation Acme (1 active account): access ends after Mon 1 Mar 2027 - 30 days left'), $r['lines'][0]);
    eq(array_column($mails, 'to'), ['admin@test'], 'admins only');
    ok(str_contains($mails[0]['subject'], 'access ending') && str_contains($mails[0]['text'], '/admin/organisations'), 'subject and link');
    [$r] = expiry_mail(fn () => AccessExpiryAlerts::check('2027-02-15'));
    eq($r['lines'], [], 'not repeated');

    [$r] = expiry_mail(fn () => AccessExpiryAlerts::check('2027-03-01'));
    eq($r['lines'], [], 'last day: nothing new');
    [$r, $mails] = expiry_mail(fn () => AccessExpiryAlerts::check('2027-03-02'));
    ok(count($mails) === 1 && str_contains($r['lines'][0], 'access ended after Mon 1 Mar 2027 - they can no longer sign in'), 'ended');
    [$r] = expiry_mail(fn () => AccessExpiryAlerts::check('2027-03-03'));
    eq($r['lines'], [], 'ended not repeated');

    Database::getConnection()->exec("UPDATE organisations SET expires_on = '2028-03-01' WHERE id = 1");   // renewed
    [$r] = expiry_mail(fn () => AccessExpiryAlerts::check('2028-02-01'));
    ok(count($r['lines']) === 1 && str_contains($r['lines'][0], '30 days left'), 'new date warned afresh');
});

test('admin emails: own dates only when they apply; dry run; a missed send is retried', function () {
    seed_estate();
    client_in_org('2027-03-01');
    set_user_expiry(2, '2027-06-01');     // later than the org's - covered by the org line
    [$r] = expiry_mail(fn () => AccessExpiryAlerts::check('2027-05-10', true));
    eq(count($r['lines']), 1, 'org ended only: ' . implode(' | ', $r['lines']));
    ok(str_starts_with($r['lines'][0], 'Organisation Acme'), $r['lines'][0]);
    eq(Database::getConnection()->query("SELECT COUNT(*) FROM sync_state WHERE sync_type = 'access_expiry_alerts'")->fetchColumn(), 0, 'dry run saved nothing');

    Database::getConnection()->exec('UPDATE organisations SET expires_on = NULL WHERE id = 1');
    Database::getConnection()->exec('UPDATE users SET is_admin = 0 WHERE id = 1');   // nobody to send to
    [$r, $mails] = expiry_mail(fn () => AccessExpiryAlerts::check('2027-05-10'));
    ok(count($r['lines']) === 1 && str_starts_with($r['lines'][0], 'Account client (Acme): access ends after') && $mails === [] && $r['sent_to'] === [], 'own date, unsent');
    Database::getConnection()->exec('UPDATE users SET is_admin = 1 WHERE id = 1');
    [$r, $mails] = expiry_mail(fn () => AccessExpiryAlerts::check('2027-05-11'));
    eq([count($r['lines']), array_column($mails, 'to')], [1, ['admin@test']], 'retried and sent');
});
