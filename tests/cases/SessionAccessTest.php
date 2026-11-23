<?php
declare(strict_types=1);

// Auth::check() re-reads the account on every request (getSessionAccount), so
// deactivation, deletion and tag changes take effect immediately.

use VulnDash\Lib\UserRepository as U;

test('session account carries tags and flags', function () {
    seed_estate();
    $a = U::getSessionAccount(2);
    eq([(bool)$a['is_active'], (bool)$a['is_admin'], array_map('intval', $a['tag_ids'])], [true, false, [1]]);
});

test('tag changes show up straight away', function () {
    seed_estate();
    U::updateUserTags(2, [1, 2]);
    eq(array_map('intval', U::getSessionAccount(2)['tag_ids']), [1, 2]);
});

test('deactivated and deleted accounts', function () {
    seed_estate();
    U::setActive(2, false);
    eq((bool)U::getSessionAccount(2)['is_active'], false, 'deactivated');
    U::deleteUser(2);
    eq(U::getSessionAccount(2), null, 'deleted');
});
