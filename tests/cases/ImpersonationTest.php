<?php
declare(strict_types=1);

// "View as" (Auth::startImpersonation / stopImpersonation): the session takes
// on the client's identity and scope, the admin stays the audited actor, and
// check() keeps validating the admin while letting a deactivated client be
// viewed. check() exits on a redirect, so those cases render a page in a
// child process (tests/render_page.php, role as_client) and look for a body.

use VulnDash\Lib\Auth;
use VulnDash\Lib\Database;
use VulnDash\Lib\UserRepository;

function admin_session(): void
{
    $_SESSION = ['user_id' => 1, 'username' => 'admin', 'is_admin' => true, 'tag_ids' => [],
                 'session_epoch' => 0, 'view_tag_id' => 2, 'show_hidden' => true];
}

/** Renders dashboard.php as admin-viewing-as-client; true if a full page came back (no redirect). */
function as_client_dashboard_renders(): bool
{
    $proc = proc_open([PHP_BINARY, __DIR__ . '/../render_page.php', 'dashboard.php', '', 'as_client'],
                      [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $out = stream_get_contents($pipes[1]);
    stream_get_contents($pipes[2]);
    proc_close($proc);
    // render_page.php has no real session, so a sign-out's session_destroy()
    // warns there - an artefact of the harness, not of the code under test.
    $out = preg_replace('/^PHPERR: session_destroy\(\): Trying to destroy uninitialized session.*$/m', '', $out);
    ok(!str_contains($out, 'PHPERR:'), 'page rendered without PHP errors: ' . substr($out, 0, 300));
    return str_contains($out, '</html>');
}

test('start swaps to the client, stop puts the admin back', function () {
    seed_estate();
    admin_session();
    Auth::startImpersonation(2);

    eq([Auth::userId(), Auth::username(), Auth::isAdmin(), Auth::tagIds()], [2, 'client', false, [1]], 'client identity and scope');
    eq(Auth::isImpersonating(), true);
    eq(Auth::impersonator()['user_id'], 1);
    ok(!isset($_SESSION['view_tag_id']) && !isset($_SESSION['show_hidden']), "admin's UI state not carried into the client view");

    Auth::stopImpersonation();
    eq([Auth::userId(), Auth::username(), Auth::isAdmin(), Auth::isImpersonating()], [1, 'admin', true, false]);
    eq([$_SESSION['view_tag_id'], $_SESSION['show_hidden'], $_SESSION['session_epoch']], [2, true, 0], 'admin UI state and epoch restored');
});

test("the client's default tag is applied", function () {
    seed_estate();
    UserRepository::setDefaultTag(2, 1);
    admin_session();
    Auth::startImpersonation(2);
    eq($_SESSION['view_tag_id'], 1);
});

test('admins and missing accounts cannot be viewed as', function () {
    seed_estate();
    Database::getConnection()->exec("INSERT INTO users (id, username, email, password_hash, is_admin) VALUES (3,'admin2','a2@test','x',1)");
    foreach ([3, 1, 999] as $id) {
        admin_session();
        try {
            Auth::startImpersonation($id);
            throw new TestFailure("user $id should have been refused");
        } catch (\InvalidArgumentException) {
        }
        eq([Auth::userId(), Auth::isImpersonating()], [1, false], "session untouched after refusing $id");
    }
});

test('no nesting', function () {
    seed_estate();
    admin_session();
    Auth::startImpersonation(2);
    try {
        Auth::startImpersonation(2);
        throw new TestFailure('nested start should be refused');
    } catch (\InvalidArgumentException) {
    }
    eq(Auth::impersonator()['user_id'], 1, 'original admin still parked');
});

test('audit: admin is the actor throughout, annotated while viewing', function () {
    seed_estate();
    admin_session();
    Auth::startImpersonation(2);
    \VulnDash\Lib\AuditLog::record('finding.hidden', ['target_label' => 'host-a']);
    Auth::stopImpersonation();

    $rows = audit_rows();
    eq(array_column($rows, 0), ['admin.impersonation_started', 'finding.hidden', 'admin.impersonation_ended']);
    eq(array_column($rows, 1), ['admin', 'admin', 'admin'], 'never recorded as the client');
    eq([$rows[0][2], $rows[2][2]], ['client', 'client'], 'start/end target the client');
    eq($rows[1][3], ['viewing_as' => 'client'], 'action annotated with the viewed account');
    ok(!isset($rows[2][3]['viewing_as']), 'end row is the admin back as themselves');
});

test('check(): a deactivated client can still be viewed', function () {
    seed_estate();
    eq(as_client_dashboard_renders(), true, 'baseline');
    UserRepository::setActive(2, false);
    eq(as_client_dashboard_renders(), true, 'deactivated client');
});

test('check(): the client changing password does not end the view', function () {
    seed_estate();
    UserRepository::resetPassword(2, 'new-pw-123456789');
    eq(as_client_dashboard_renders(), true);
});

test('check(): admin losing rights, deactivated or password-changed ends the session', function () {
    seed_estate();
    UserRepository::setAdmin(1, false);
    eq(as_client_dashboard_renders(), false, 'admin demoted');

    seed_estate_fresh();
    UserRepository::setActive(1, false);
    eq(as_client_dashboard_renders(), false, 'admin deactivated');

    seed_estate_fresh();
    UserRepository::resetPassword(1, 'new-pw-123456789');
    eq(as_client_dashboard_renders(), false, 'admin password changed elsewhere');
});

test('check(): client made admin or deleted ends the view', function () {
    seed_estate();
    UserRepository::setAdmin(2, true);
    eq(as_client_dashboard_renders(), false, 'client promoted');

    seed_estate_fresh();
    UserRepository::deleteUser(2);
    eq(as_client_dashboard_renders(), false, 'client deleted');
});

function seed_estate_fresh(): void
{
    reset_db();
    seed_estate();
}
