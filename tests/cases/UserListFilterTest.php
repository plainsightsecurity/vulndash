<?php
declare(strict_types=1);

// Manage Users filter: search on username/email and filter by tag
// (UserRepository::listUsers() and public/admin/users.php).

use VulnDash\Lib\Database;
use VulnDash\Lib\UserRepository;

function seed_more_users(): void
{
    seed_estate(); // admin (no tags), client (ClientA)
    $pdo = Database::getConnection();
    $pdo->exec("INSERT INTO users (id, username, email, password_hash, is_admin) VALUES
        (3,'flennard','frank.l@millstreamtech.co.uk','x',0),
        (4,'jsmith','jane@acme.example.com','x',0),
        (5,'under_score','u@example.com','x',0)");
    $pdo->exec('INSERT INTO user_tags (user_id, tag_id) VALUES (3,1),(3,2),(4,2)');
}

function usernames(array $rows): array
{
    return array_column($rows, 'username');
}

test('no filter lists everyone', function () {
    seed_more_users();
    eq(usernames(UserRepository::listUsers()), ['admin', 'client', 'flennard', 'jsmith', 'under_score']);
    eq(UserRepository::countUsers(), 5);
});

test('search matches username or email, case-insensitively', function () {
    seed_more_users();
    eq(usernames(UserRepository::listUsers('FLEN')), ['flennard']);
    eq(usernames(UserRepository::listUsers('millstream')), ['flennard'], 'by email');
    eq(usernames(UserRepository::listUsers('acme')), ['jsmith']);
    eq(usernames(UserRepository::listUsers('nobody')), []);
});

test('LIKE wildcards in the search are taken literally', function () {
    seed_more_users();
    eq(usernames(UserRepository::listUsers('_')), ['under_score']);
    eq(usernames(UserRepository::listUsers('%')), []);
});

test('tag filter keeps all of a matching account\'s tags, and "No tags" works', function () {
    seed_more_users();
    $rows = UserRepository::listUsers(null, 2);
    eq(usernames($rows), ['flennard', 'jsmith']);
    eq($rows[0]['tag_names'], 'ClientA, ClientB', 'not just the filtered tag');
    eq(usernames(UserRepository::listUsers(null, UserRepository::TAG_FILTER_NONE)), ['admin', 'under_score']);
});

test('search and tag combine', function () {
    seed_more_users();
    eq(usernames(UserRepository::listUsers('j', 2)), ['jsmith']);
    eq(usernames(UserRepository::listUsers('client', 2)), []);
});

test('the page shows the filter, the match count and only matching rows', function () {
    seed_more_users();
    $out = render_page('admin/users.php', 'q=millstream');
    ok(!str_contains($out, 'PHPERR'), 'no PHP errors: ' . $out);
    ok(str_contains($out, '1 of 5 shown'), 'count');
    ok(str_contains($out, 'frank.l@millstreamtech.co.uk'), 'match shown');
    ok(!str_contains($out, 'jane@acme.example.com'), 'non-match hidden');
    ok(str_contains($out, 'Clear filters'), 'clear link');

    $out = render_page('admin/users.php', 'tag=1');
    ok(str_contains($out, '<option value="1" selected>ClientA</option>'), 'tag stays selected');
    ok(str_contains($out, '2 of 5 shown'), 'client + flennard');

    $out = render_page('admin/users.php', 'q=zzz');
    ok(str_contains($out, 'No users match these filters.'), 'empty message');

    $out = render_page('admin/users.php', 'tag=bogus');
    ok(str_contains($out, '5 total'), 'malformed tag ignored');
});
