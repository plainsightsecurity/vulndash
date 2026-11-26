<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\AuditLog;
use VulnDash\Lib\Config;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\PasswordResetRepository;
use VulnDash\Lib\TrustedDeviceRepository;
use VulnDash\Lib\UserRepository;

// Someone already fully logged in should use public/password.php instead.
if (!empty($_SESSION['user_id'])) {
    header('Location: /dashboard');
    exit;
}

// The token travels as a GET param on the initial link click, and as a
// hidden POST field from then on (see the form below) - re-validated fresh
// on every request rather than trusted across the request/response cycle,
// since nothing about this page's own state can be relied on to persist
// (no session identifies the account yet - that's the whole point).
$token = (string)($_POST['token'] ?? $_GET['token'] ?? '');
$tokenInfo = $token !== '' ? PasswordResetRepository::validate($token) : null;

$error = null;
$done = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $tokenInfo !== null) {
    if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
        $error = 'Your session expired. Please try again.';
    } else {
        $password = (string)($_POST['password'] ?? '');
        $confirm  = (string)($_POST['password_confirm'] ?? '');

        if (strlen($password) < 12) {
            $error = 'Password must be at least 12 characters.';
        } elseif ($password !== $confirm) {
            $error = "Passwords don't match.";
        } else {
            UserRepository::resetPassword($tokenInfo['user_id'], $password);
            PasswordResetRepository::consume($tokenInfo['id']);

            // Revoke any trusted-device grants on this account - this link
            // proves control of the mailbox, not the device it's opened
            // on, and a forgotten/reset password is often exactly the
            // situation where an old trusted-device grant shouldn't be
            // assumed safe to keep honouring. Harmless no-op for a brand
            // new account, which has none yet.
            TrustedDeviceRepository::revokeAllForUser($tokenInfo['user_id']);
            AuditLog::record('account.password_reset', [
                'user_id'  => (int)$tokenInfo['user_id'],
                'username' => UserRepository::getUser((int)$tokenInfo['user_id'])['username'] ?? null,
                'details'  => ['purpose' => $tokenInfo['purpose'] ?? 'reset'],
            ]);

            $done = true;
        }
    }
}

$csrfToken = Helpers::csrfToken();
$appName = Config::get('app.name') ?? 'Vulnerability Management Dashboard';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <script>
    // Same no-flash theme init as src/views/header.php - this page has its
    // own standalone <head> rather than including that shared header
    // (same reasoning as login.php: nobody is logged in yet at this
    // point), so it needs its own copy of this snippet.
    (function () {
        try {
            var stored = window.localStorage.getItem('vulndash-theme');
            document.documentElement.setAttribute('data-theme', stored === 'light' ? 'light' : 'dark');
        } catch (e) {
            document.documentElement.setAttribute('data-theme', 'dark');
        }
    })();
    </script>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Set your password - <?= htmlspecialchars($appName) ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body class="login-body">
<main class="login-wrap">
    <?php if ($done): ?>
    <div class="login-card">
        <div class="login-brand">
            <span class="brand-mark" aria-hidden="true"></span>
            <span><?= htmlspecialchars($appName) ?></span>
        </div>
        <p class="page-subtitle" style="margin: 0;">Your password has been set. You can now sign in.</p>
        <a class="btn btn-primary btn-block" href="/login">Sign in</a>
    </div>

    <?php elseif ($tokenInfo === null): ?>
    <div class="login-card">
        <div class="login-brand">
            <span class="brand-mark" aria-hidden="true"></span>
            <span><?= htmlspecialchars($appName) ?></span>
        </div>
        <p class="form-error" role="alert">
            This link is invalid, expired, or has already been used.
        </p>
        <a class="btn btn-primary btn-block" href="/forgot_password">Request a new link</a>
        <a class="btn btn-secondary btn-block" href="/login" style="margin-top: 0.5rem;">Back to sign in</a>
    </div>

    <?php else: ?>
    <form class="login-card" method="post" action="/reset_password" novalidate>
        <div class="login-brand">
            <span class="brand-mark" aria-hidden="true"></span>
            <span><?= htmlspecialchars($appName) ?></span>
            <button type="button" class="theme-toggle theme-toggle-login" id="themeToggle" aria-label="Toggle light and dark mode" title="Toggle light and dark mode">
                <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><line x1="12" y1="2" x2="12" y2="4"></line><line x1="12" y1="20" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="6.34" y2="6.34"></line><line x1="17.66" y1="17.66" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="4" y2="12"></line><line x1="20" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="6.34" y2="17.66"></line><line x1="17.66" y1="6.34" x2="19.07" y2="4.93"></line></svg>
                <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
            </button>
        </div>

        <p class="page-subtitle" style="margin: -0.5rem 0 0.25rem;">
            <?= $tokenInfo['purpose'] === PasswordResetRepository::PURPOSE_SETUP
                ? 'Choose a password to finish setting up your account.'
                : 'Choose a new password for your account.' ?>
        </p>

        <?php if ($error !== null): ?>
        <p class="form-error" role="alert"><?= htmlspecialchars($error) ?></p>
        <?php endif; ?>

        <label class="field">
            <span>New password</span>
            <input type="password" name="password" minlength="12" autocomplete="new-password" required autofocus>
        </label>

        <label class="field">
            <span>Confirm new password</span>
            <input type="password" name="password_confirm" minlength="12" autocomplete="new-password" required>
        </label>
        <p class="checkbox-hint" style="margin: -0.6rem 0 0;">At least 12 characters.</p>

        <input type="hidden" name="token" value="<?= htmlspecialchars($token) ?>">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">

        <button type="submit" class="btn btn-primary btn-block">Set password</button>
    </form>
    <?php endif; ?>
</main>
<script>
(function () {
    var btn = document.getElementById('themeToggle');
    if (!btn) {
        return;
    }
    btn.addEventListener('click', function () {
        var isLight = document.documentElement.getAttribute('data-theme') === 'light';
        var next = isLight ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', next);
        try {
            window.localStorage.setItem('vulndash-theme', next);
        } catch (e) {
            // No persistence available - the choice still applies to this
            // page view, it just won't be remembered on the next one.
        }
    });
})();
</script>
</body>
</html>
