<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\AuditLog;
use VulnDash\Lib\Auth;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\UserRepository;

Auth::check();

$userId = Auth::userId();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
        Helpers::setFlash('Your session expired - please try that again.', 'error');
        header('Location: /password');
        exit;
    }

    try {
        $current = (string)($_POST['current_password'] ?? '');
        $new     = (string)($_POST['new_password'] ?? '');
        $confirm = (string)($_POST['new_password_confirm'] ?? '');

        if (!UserRepository::checkPassword($userId, $current)) {
            throw new \RuntimeException('Your current password is incorrect.');
        }
        if (strlen($new) < 12) {
            throw new \RuntimeException('New password must be at least 12 characters.');
        }
        if ($new !== $confirm) {
            throw new \RuntimeException("New passwords don't match.");
        }

        UserRepository::resetPassword($userId, $new);
        AuditLog::record('account.password_changed');

        // resetPassword() bumped this account's session_epoch, which will sign
        // out every OTHER open session for it on their next request (see
        // Auth::check()). Keep THIS session - the one that made the change -
        // signed in by re-seeding its stored epoch to the new value, and
        // rotate the session ID as good hygiene after a credential change.
        // Trusted devices are deliberately NOT revoked here: changing your
        // password drops other sessions but leaves your known browsers able to
        // skip the MFA prompt.
        session_regenerate_id(true);
        $_SESSION['session_epoch'] = UserRepository::getSessionEpoch($userId) ?? 0;

        Helpers::setFlash('Your password has been changed. Any other signed-in sessions have been logged out.');
    } catch (\RuntimeException $e) {
        Helpers::setFlash($e->getMessage(), 'error');
    }

    header('Location: /password');
    exit;
}

$csrfToken = Helpers::csrfToken();
$flash = Helpers::getFlash();

$pageTitle = 'Change Password';
require __DIR__ . '/../src/views/header.php';
?>

<div class="page-heading">
    <h1>Change Password</h1>
    <p class="page-subtitle">Update the password you use to sign in.</p>
</div>

<?php if ($flash): ?>
<div class="flash flash-<?= Helpers::e($flash['type']) ?>"><?= Helpers::e($flash['message']) ?></div>
<?php endif; ?>

<div class="panel edit-panel">
    <form method="post">
        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">

        <label class="field" style="margin-bottom: 0.9rem;">
            <span>Current password</span>
            <input type="password" name="current_password" autocomplete="current-password" required autofocus>
        </label>

        <label class="field" style="margin-bottom: 0.9rem;">
            <span>New password</span>
            <input type="password" name="new_password" minlength="12" autocomplete="new-password" required>
        </label>

        <label class="field">
            <span>Confirm new password</span>
            <input type="password" name="new_password_confirm" minlength="12" autocomplete="new-password" required>
        </label>
        <p class="checkbox-hint" style="margin: 0.4rem 0 1rem;">At least 12 characters.</p>

        <button type="submit" class="btn btn-primary">Change password</button>
    </form>
</div>

<?php require __DIR__ . '/../src/views/footer.php'; ?>
