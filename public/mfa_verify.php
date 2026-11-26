<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Auth;
use VulnDash\Lib\Config;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\MfaService;

// Someone already fully logged in has no business here.
if (!empty($_SESSION['user_id'])) {
    header('Location: /dashboard');
    exit;
}

// Nothing pending (never started, already completed, or the 5-minute
// window in Auth::pendingMfaUserId() expired) - back to the start.
if (Auth::pendingMfaUserId() === null) {
    Helpers::setFlash('Your sign-in attempt expired. Please sign in again.', 'error');
    header('Location: /login');
    exit;
}

$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
        $error = 'Your session expired. Please try again.';
    } elseif (!empty($_POST['cancel'])) {
        Auth::cancelMfaChallenge();
        header('Location: /login');
        exit;
    } else {
        $code = trim((string)($_POST['code'] ?? ''));
        $trustDevice = !empty($_POST['trust_device']);

        if ($code === '') {
            $error = 'Enter the 6-digit code from your authenticator app.';
        } else {
            try {
                $result = Auth::completeMfaChallenge($code, $trustDevice);
            } catch (\Throwable $e) {
                // Almost certainly security.mfa_encryption_key is missing or
                // has changed since this account's secret was confirmed -
                // an admin needs to fix the key or reset this account's MFA
                // (Manage Users -> Reset MFA), not something to fail silently
                // or expose details of to the person trying to sign in.
                error_log('MFA: login verification failed unexpectedly: ' . $e->getMessage());
                $result = null;
            }

            if ($result === MfaService::VERIFY_OK) {
                header('Location: /dashboard');
                exit;
            } elseif ($result === MfaService::VERIFY_LOCKED) {
                $error = 'Too many incorrect codes. Try again in a few minutes.';
            } elseif ($result === MfaService::VERIFY_INVALID) {
                $error = 'Incorrect code. Please try again.';
            } else {
                $error = 'Something went wrong verifying your code. Please contact an admin if this continues.';
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
    <title>Verify it's you - <?= htmlspecialchars($appName) ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body class="login-body">
<main class="login-wrap">
    <form class="login-card" method="post" action="/mfa_verify" novalidate>
        <div class="login-brand">
            <span class="brand-mark" aria-hidden="true"></span>
            <span><?= htmlspecialchars($appName) ?></span>
            <button type="button" class="theme-toggle theme-toggle-login" id="themeToggle" aria-label="Toggle light and dark mode" title="Toggle light and dark mode">
                <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><line x1="12" y1="2" x2="12" y2="4"></line><line x1="12" y1="20" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="6.34" y2="6.34"></line><line x1="17.66" y1="17.66" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="4" y2="12"></line><line x1="20" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="6.34" y2="17.66"></line><line x1="17.66" y1="6.34" x2="19.07" y2="4.93"></line></svg>
                <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
            </button>
        </div>

        <p class="page-subtitle" style="margin: -0.5rem 0 0.25rem;">Enter the 6-digit code from your authenticator app.</p>

        <?php if ($error !== null): ?>
        <p class="form-error" role="alert"><?= htmlspecialchars($error) ?></p>
        <?php endif; ?>

        <label class="field">
            <span>Authentication code</span>
            <input type="text" name="code" class="totp-input" inputmode="numeric" pattern="[0-9]*"
                autocomplete="one-time-code" maxlength="6" required autofocus>
        </label>

        <label class="checkbox-field">
            <input type="checkbox" name="trust_device" value="1">
            <span>Trust this device for 30 days <span class="checkbox-hint">(skip this step next time)</span></span>
        </label>

        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">

        <button type="submit" class="btn btn-primary btn-block">Verify</button>
        <button type="submit" name="cancel" value="1" class="btn btn-secondary btn-block" style="margin-top: 0.5rem;">
            Cancel and sign in as someone else
        </button>
    </form>
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
