<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Auth;
use VulnDash\Lib\Config;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\SessionTimeout;

// An expired session must not be bounced straight back to the dashboard.
SessionTimeout::enforce();
$signedOutMessage = SessionTimeout::takeSignedOutMessage();

if (!empty($_SESSION['user_id'])) {
    header('Location: /dashboard');
    exit;
}

$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
        $error = 'Your session expired. Please try again.';
    } else {
        $username = trim((string)($_POST['username'] ?? ''));
        $password = (string)($_POST['password'] ?? '');

        if ($username === '' || $password === '') {
            $error = 'Enter your username or email and your password.';
        } else {
            $result = Auth::attemptLogin($username, $password);
            if ($result === Auth::RESULT_SUCCESS) {
                header('Location: /dashboard');
                exit;
            } elseif ($result === Auth::RESULT_MFA_REQUIRED) {
                header('Location: /mfa_verify');
                exit;
            } elseif ($result === Auth::RESULT_THROTTLED) {
                // Too many failed attempts from this IP within the window (see
                // LoginThrottleRepository). Deliberately vague and not
                // account-specific - it says nothing about whether the
                // username or password was right.
                $error = 'Too many failed sign-in attempts from your network. Please wait a few minutes and try again.';
            } else {
                $error = 'Incorrect username or password.';
            }
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
    // own standalone <head> rather than including that shared header, so it
    // needs its own copy of this snippet.
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
    <title>Sign in — <?= htmlspecialchars($appName) ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body class="login-body">
<main class="login-wrap">
    <!-- Login-only lockup: Nexus emblem stacked above the sign-in card. The
         .login-stack wrapper keeps this change scoped to this page - the other
         auth pages (forgot/reset/mfa) still use the bare .login-wrap > .login-card
         layout, so nothing here touches their markup or the shared .login-wrap rule. -->
    <div class="login-stack">
        <img class="login-logo" src="/assets/img/nexus-logo.png?v=<?= @filemtime(__DIR__ . '/assets/img/nexus-logo.png') ?: time() ?>" alt="Nexus">
    <form class="login-card" method="post" action="/login" novalidate>
        <div class="login-brand">
            <!-- Green .brand-mark square removed here per request; the emblem
                 above now carries the branding. .brand-mark itself is left in
                 the stylesheet because the other auth pages still render it. -->
            <span><?= htmlspecialchars($appName) ?></span>
            <button type="button" class="theme-toggle theme-toggle-login" id="themeToggle" aria-label="Toggle light and dark mode" title="Toggle light and dark mode">
                <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><line x1="12" y1="2" x2="12" y2="4"></line><line x1="12" y1="20" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="6.34" y2="6.34"></line><line x1="17.66" y1="17.66" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="4" y2="12"></line><line x1="20" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="6.34" y2="17.66"></line><line x1="17.66" y1="6.34" x2="19.07" y2="4.93"></line></svg>
                <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
            </button>
        </div>

        <?php if ($signedOutMessage !== null && $error === null): ?>
        <p class="form-notice" role="status"><?= htmlspecialchars($signedOutMessage) ?></p>
        <?php endif; ?>
        <?php if ($error !== null): ?>
        <p class="form-error" role="alert"><?= htmlspecialchars($error) ?></p>
        <?php endif; ?>

        <label class="field">
            <span>Username or Email</span>
            <input type="text" name="username" autocomplete="username" required autofocus>
        </label>

        <label class="field">
            <span>Password</span>
            <input type="password" name="password" autocomplete="current-password" required>
        </label>

        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">

        <button type="submit" class="btn btn-primary btn-block">Sign in</button>
        <a href="/forgot_password" class="checkbox-hint" style="text-align: center; margin-top: 0.4rem;">Forgot your password?</a>
    </form>
    </div>
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
