<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Config;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\Mailer;
use VulnDash\Lib\PasswordResetRepository;
use VulnDash\Lib\UserRepository;

// Someone already fully logged in should use public/password.php instead.
if (!empty($_SESSION['user_id'])) {
    header('Location: /dashboard');
    exit;
}

$error = null;
$submitted = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
        $error = 'Your session expired. Please try again.';
    } else {
        $identifier = trim((string)($_POST['identifier'] ?? ''));

        if ($identifier === '') {
            $error = 'Enter your username or email address.';
        } else {
            // Always show the same generic "submitted" state below,
            // whether or not this identifier actually matches an account -
            // a different message for "no such account" would let this
            // form be used to test which usernames/emails are registered.
            $user = UserRepository::findByUsernameOrEmail($identifier);
            if ($user && (int)$user['is_active'] === 1) {
                $token = PasswordResetRepository::issue((int)$user['id'], PasswordResetRepository::PURPOSE_RESET);
                $baseUrl = rtrim((string)(Config::get('app.base_url') ?? ''), '/');
                $link = $baseUrl . '/reset_password?token=' . urlencode($token);
                Mailer::sendPasswordResetEmail($user['email'], $user['username'], $link);
            }
            $submitted = true;
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
    <title>Forgot password — <?= htmlspecialchars($appName) ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body class="login-body">
<main class="login-wrap">
    <?php if ($submitted): ?>
    <div class="login-card">
        <div class="login-brand">
            <span class="brand-mark" aria-hidden="true"></span>
            <span><?= htmlspecialchars($appName) ?></span>
        </div>
        <p class="page-subtitle" style="margin: 0;">
            If an account exists for that username or email, we've sent a link to reset the password.
            The link expires in 1 hour.
        </p>
        <a class="btn btn-primary btn-block" href="/login">Back to sign in</a>
    </div>
    <?php else: ?>
    <form class="login-card" method="post" action="/forgot_password" novalidate>
        <div class="login-brand">
            <span class="brand-mark" aria-hidden="true"></span>
            <span><?= htmlspecialchars($appName) ?></span>
            <button type="button" class="theme-toggle theme-toggle-login" id="themeToggle" aria-label="Toggle light and dark mode" title="Toggle light and dark mode">
                <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><line x1="12" y1="2" x2="12" y2="4"></line><line x1="12" y1="20" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="6.34" y2="6.34"></line><line x1="17.66" y1="17.66" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="4" y2="12"></line><line x1="20" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="6.34" y2="17.66"></line><line x1="17.66" y1="6.34" x2="19.07" y2="4.93"></line></svg>
                <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
            </button>
        </div>

        <p class="page-subtitle" style="margin: -0.5rem 0 0.25rem;">
            Enter your username or email and we'll send you a link to reset your password.
        </p>

        <?php if ($error !== null): ?>
        <p class="form-error" role="alert"><?= htmlspecialchars($error) ?></p>
        <?php endif; ?>

        <label class="field">
            <span>Username or email</span>
            <input type="text" name="identifier" autocomplete="username" required autofocus>
        </label>

        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">

        <button type="submit" class="btn btn-primary btn-block">Send reset link</button>
        <a class="btn btn-secondary btn-block" href="/login" style="margin-top: 0.5rem;">Back to sign in</a>
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
