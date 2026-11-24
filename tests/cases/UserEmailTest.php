<?php
declare(strict_types=1);

// Account email addresses (admin Manage Users): typo'd domain endings are
// refused on create and on edit, an admin can correct an address, and the
// optional password link goes to the new address - a 7-day setup link for
// an account that has never signed in, a 1-hour reset link otherwise.

use VulnDash\Lib\Database;
use VulnDash\Lib\Helpers;

/** render_page() with outgoing mail captured; returns [page output, emails]. */
function users_post_capturing_mail(string $post): array
{
    $log = tempnam(sys_get_temp_dir(), 'vdmail');
    putenv("VULNDASH_MAIL_LOG=$log");
    try {
        $out = render_page('admin/users.php', '', 'admin', $post);
    } finally {
        putenv('VULNDASH_MAIL_LOG');
    }
    $mails = array_map(fn ($l) => json_decode($l, true), array_filter(explode("\n", (string)file_get_contents($log))));
    unlink($log);
    return [$out, $mails];
}

function email_of(string $username): ?string
{
    $stmt = Database::getConnection()->prepare('SELECT email FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $email = $stmt->fetchColumn();
    return $email === false ? null : (string)$email;
}

test('emailError accepts real addresses and rejects typo\'d endings', function () {
    foreach (['frank.l@millstreamtech.co.uk', 'a.b+c@example.com', 'X@Example.ORG', 'x@y.xn--p1ai'] as $good) {
        eq(Helpers::emailError($good), null, $good);
    }
    foreach (['frank.l@millstreamtech.co.u', 'a@b.c', 'a@localhost', 'a@b.c0', 'not-an-email', ''] as $bad) {
        ok(Helpers::emailError($bad) !== null, "rejects $bad");
    }
    ok(str_contains((string)Helpers::emailError('frank.l@millstreamtech.co.u'), '".u"'), 'names the bad ending');
});

test('the browser-side pattern agrees with emailError', function () {
    $re = '/^(?:' . Helpers::EMAIL_INPUT_PATTERN . ')$/';
    ok(preg_match($re, 'frank.l@millstreamtech.co.uk') === 1, 'accepts .co.uk');
    ok(preg_match($re, 'frank.l@millstreamtech.co.u') === 0, 'rejects .co.u');
});

test('creating an account with a typo\'d domain is refused and sends nothing', function () {
    seed_estate();
    [$out, $mails] = users_post_capturing_mail('action=create_user&username=flennard&email=frank.l@millstreamtech.co.u&tag_ids[]=1');
    ok(!str_contains($out, 'PHPERR'), 'no PHP errors: ' . $out);
    eq(email_of('flennard'), null, 'no account created');
    eq($mails, [], 'no email sent');
});

test('an admin can correct the email and the setup link goes to the new address', function () {
    seed_estate();
    users_post_capturing_mail('action=create_user&username=flennard&email=frank@old.example.com&tag_ids[]=1');
    $id = (int)Database::getConnection()->query("SELECT id FROM users WHERE username = 'flennard'")->fetchColumn();

    [$out, $mails] = users_post_capturing_mail("action=update_email&user_id=$id&email=frank.l@millstreamtech.co.uk&send_link=1");
    ok(!str_contains($out, 'PHPERR'), 'no PHP errors: ' . $out);
    eq(email_of('flennard'), 'frank.l@millstreamtech.co.uk');
    eq(count($mails), 1, 'one email');
    ok(str_contains(json_encode($mails[0]['to']), 'frank.l@millstreamtech.co.uk'), 'sent to the new address');
    ok(str_contains($mails[0]['subject'], 'Set up'), 'never signed in, so a setup link: ' . $mails[0]['subject']);

    $change = array_values(array_filter(audit_rows(), fn ($r) => $r[0] === 'admin.user_email_changed'));
    eq(count($change), 1, 'audited');
    eq([$change[0][3]['before'], $change[0][3]['after']], ['frank@old.example.com', 'frank.l@millstreamtech.co.uk']);
});

test('an account that has signed in gets a reset link, and no link unless asked', function () {
    seed_estate();
    Database::getConnection()->exec('UPDATE users SET last_login_at = NOW() WHERE id = 2');

    [, $mails] = users_post_capturing_mail('action=update_email&user_id=2&email=client@new.example.com&send_link=1');
    eq(email_of('client'), 'client@new.example.com');
    eq(count($mails), 1);
    ok(str_contains($mails[0]['subject'], 'Reset'), 'reset link: ' . $mails[0]['subject']);

    [, $mails] = users_post_capturing_mail('action=update_email&user_id=2&email=client@newer.example.com');
    eq(email_of('client'), 'client@newer.example.com');
    eq($mails, [], 'box unticked, nothing sent');
});

test('editing to a typo\'d or already-used address is refused', function () {
    seed_estate();
    users_post_capturing_mail('action=update_email&user_id=2&email=client@example.co.u&send_link=1');
    eq(email_of('client'), 'client@test', 'typo refused');

    Database::getConnection()->exec("UPDATE users SET email = 'admin@example.com' WHERE id = 1");
    [$out, $mails] = users_post_capturing_mail('action=update_email&user_id=2&email=admin@example.com&send_link=1');
    ok(!str_contains($out, 'PHPERR'), 'no PHP errors: ' . $out);
    eq(email_of('client'), 'client@test', 'duplicate refused');
    eq($mails, []);
});

test('the Manage panel shows the email form with the right default', function () {
    seed_estate();
    $out = render_page('admin/users.php');
    ok(!str_contains($out, 'PHPERR'), 'no PHP errors: ' . $out);
    ok(substr_count($out, 'name="action" value="update_email"') === 2, 'one email form per user');
    ok(str_contains($out, 'setup link, 7 days'), 'never-signed-in hint shown');
});
