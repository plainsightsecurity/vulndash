<?php
declare(strict_types=1);

require_once __DIR__ . '/../../src/bootstrap.php';

use VulnDash\Lib\Auth;
use VulnDash\Lib\Helpers;

// "View as": an admin starts seeing (and acting in) the dashboard exactly as
// a client account does, for troubleshooting, and returns to their own
// session from the banner in src/views/header.php. The mechanics - what's
// swapped, what's kept, who the audit log records - are in Auth.
//
// POST only: starting or stopping changes whose identity the session carries,
// so it must never be triggerable by a link or an embedded image.

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /admin/users');
    exit;
}

$action = (string)($_POST['action'] ?? '');

if ($action === 'stop') {
    // Plain check(), not requireAdmin(): while viewing as a client this
    // session isn't an admin, and the way back has to stay open. check()
    // still confirms the admin behind it is valid.
    Auth::check();
    if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
        Helpers::setFlash('Your session expired - please try that again.', 'error');
        header('Location: /dashboard');
        exit;
    }
    Auth::stopImpersonation();
    header('Location: /admin/users');
    exit;
}

Auth::requireAdmin();
if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
    Helpers::setFlash('Your session expired - please try that again.', 'error');
    header('Location: /admin/users');
    exit;
}

if ($action !== 'start') {
    header('Location: /admin/users');
    exit;
}

try {
    Auth::startImpersonation((int)($_POST['user_id'] ?? 0));
} catch (\InvalidArgumentException $e) {
    Helpers::setFlash($e->getMessage(), 'error');
    header('Location: /admin/users');
    exit;
}

header('Location: /dashboard');
exit;
