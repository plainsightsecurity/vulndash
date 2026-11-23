<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Auth;
use VulnDash\Lib\Config;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\MfaService;
use VulnDash\Lib\TrustedDeviceRepository;
use VulnDash\Lib\UserRepository;

Auth::check();

$userId = Auth::userId();
$username = Auth::username();
$appName = (string)(Config::get('app.name') ?? 'Vulnerability Management Dashboard');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
        Helpers::setFlash('Your session expired - please try that again.', 'error');
        header('Location: /mfa');
        exit;
    }

    $action = (string)($_POST['action'] ?? '');

    try {
        switch ($action) {
            case 'start_enrollment':
                MfaService::beginEnrollment($userId, $username, $appName);
                break;

            case 'confirm_enrollment':
                $code = trim((string)($_POST['code'] ?? ''));
                if (!MfaService::confirmEnrollment($userId, $code)) {
                    throw new \RuntimeException('Incorrect code - check the time on your phone and try again.');
                }
                Helpers::setFlash('Two-factor authentication is now enabled on your account.');
                break;

            case 'cancel_enrollment':
                MfaService::cancelEnrollment($userId);
                break;

            case 'disable':
                $password = (string)($_POST['password'] ?? '');
                if (!UserRepository::checkPassword($userId, $password)) {
                    throw new \RuntimeException('Incorrect password - two-factor authentication was not disabled.');
                }
                MfaService::disable($userId);
                TrustedDeviceRepository::clearCookie();
                Helpers::setFlash('Two-factor authentication has been disabled.');
                break;

            case 'revoke_device':
                $deviceId = (int)($_POST['device_id'] ?? 0);
                if (TrustedDeviceRepository::revoke($deviceId, $userId, $userId)) {
                    Helpers::setFlash('Device trust revoked.');
                } else {
                    throw new \RuntimeException('That device was not found - it may already be revoked.');
                }
                break;

            case 'revoke_all_devices':
                TrustedDeviceRepository::revokeAllForUser($userId, $userId);
                TrustedDeviceRepository::clearCookie();
                Helpers::setFlash('All trusted devices have been revoked. You will be asked for a code on every device next time, including this one.');
                break;

            default:
                throw new \RuntimeException('Unknown action.');
        }
    } catch (\RuntimeException $e) {
        Helpers::setFlash($e->getMessage(), 'error');
    }

    header('Location: /mfa');
    exit;
}

$user = UserRepository::getUser($userId);
$mfaEnabled = (bool)($user['mfa_enabled'] ?? false);

$pendingEnrollment = null;
$trustedDevices = [];

if ($mfaEnabled) {
    $trustedDevices = TrustedDeviceRepository::listForUser($userId);
} else {
    try {
        $pendingEnrollment = MfaService::pendingEnrollment($userId, $username, $appName);
    } catch (\Throwable $e) {
        // Almost certainly means security.mfa_encryption_key has changed
        // (or broken) since this pending secret was created - it was never
        // confirmed/enabled, so the safe response is to discard it and let
        // the person just start over, rather than showing a fatal error.
        error_log('MFA: failed to load pending enrollment for user ' . $userId . ': ' . $e->getMessage());
        MfaService::cancelEnrollment($userId);
        Helpers::setFlash('Your in-progress setup could not be loaded and was cleared - please start again.', 'error');
    }
}

$csrfToken = Helpers::csrfToken();
$flash = Helpers::getFlash();

$pageTitle = 'Two-Factor Authentication';
require __DIR__ . '/../src/views/header.php';
?>

<div class="page-heading">
    <h1>Two-Factor Authentication</h1>
    <p class="page-subtitle">Add a one-time code from an authenticator app as a second step when signing in.</p>
</div>

<?php if ($flash): ?>
<div class="flash flash-<?= Helpers::e($flash['type']) ?>"><?= Helpers::e($flash['message']) ?></div>
<?php endif; ?>

<?php if ($mfaEnabled): ?>

<div class="panel">
    <div class="mfa-status-badge-row">
        <span class="badge badge-active">Enabled</span>
        <span class="page-subtitle" style="margin: 0;">
            Confirmed <?= Helpers::e($user['mfa_confirmed_at'] ? Helpers::relativeTime($user['mfa_confirmed_at']) : 'recently') ?>.
        </span>
    </div>
    <p class="page-subtitle" style="margin-bottom: 1rem;">
        Every sign-in now asks for a code from your authenticator app, unless you're on a device you've chosen to trust below.
    </p>

    <details>
        <summary class="checkbox-hint" style="cursor: pointer;">Turn off two-factor authentication</summary>
        <form method="post" class="inline-form-row" style="margin-top: 0.75rem;"
              onsubmit="return confirm('Turn off two-factor authentication for your account? Anyone who has your password would then be able to sign in with just that.');">
            <input type="hidden" name="action" value="disable">
            <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
            <label class="field">
                <span>Confirm your current password</span>
                <input type="password" name="password" autocomplete="current-password" required>
            </label>
            <button type="submit" class="btn btn-sm btn-danger">Disable MFA</button>
        </form>
    </details>
</div>

<div class="panel">
    <h2>Trusted devices</h2>
    <p class="page-subtitle" style="margin-bottom: 0.75rem;">
        Devices where you checked "Trust this device" at the sign-in code step. Trust lasts 30 days from when it was
        granted and only ever skips the code step - your password is always still required. An admin can also revoke
        any of these from Manage Users.
    </p>

    <?php if (empty($trustedDevices)): ?>
    <p class="no-tags">No devices are currently trusted - you'll be asked for a code every time you sign in.</p>
    <?php else: ?>
    <div class="table-wrap" style="margin-bottom: 1rem;">
        <table class="vuln-table admin-table">
            <thead>
                <tr>
                    <th>Device</th>
                    <th>IP address</th>
                    <th>Trusted since</th>
                    <th>Last used</th>
                    <th>Expires</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($trustedDevices as $device): ?>
                <tr>
                    <td><?= Helpers::e($device['device_label'] ?? 'Unknown device') ?></td>
                    <td class="mono"><?= Helpers::e($device['ip_address'] ?? '—') ?></td>
                    <td class="mono"><?= Helpers::e($device['created_at']) ?></td>
                    <td class="mono"><?= $device['last_used_at'] ? Helpers::e($device['last_used_at']) : '—' ?></td>
                    <td class="mono"><?= Helpers::e($device['expires_at']) ?></td>
                    <td>
                        <form method="post" onsubmit="return confirm('Revoke trust for this device? It will need a code again next time.');">
                            <input type="hidden" name="action" value="revoke_device">
                            <input type="hidden" name="device_id" value="<?= (int)$device['id'] ?>">
                            <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                            <button type="submit" class="btn btn-sm btn-danger">Revoke</button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <form method="post" onsubmit="return confirm('Revoke trust for every device, including this one? You will need a code on your very next sign-in.');">
        <input type="hidden" name="action" value="revoke_all_devices">
        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
        <button type="submit" class="btn btn-sm btn-secondary">Revoke all trusted devices</button>
    </form>
    <?php endif; ?>
</div>

<?php elseif ($pendingEnrollment): ?>

<div class="panel edit-panel">
    <h2>Finish setting up two-factor authentication</h2>
    <p class="page-subtitle" style="margin-bottom: 1rem;">
        Scan this with an authenticator app (Google Authenticator, Authy, 1Password, etc), or enter the key manually,
        then enter the 6-digit code it shows to confirm.
    </p>

    <div class="mfa-setup-grid">
        <div class="mfa-qr-box" id="mfaQr" aria-label="QR code for authenticator app setup"></div>
        <div>
            <p class="page-subtitle" style="margin: 0 0 0.4rem;">Can't scan? Enter this key manually:</p>
            <div class="mfa-secret-box">
                <span id="mfaSecretText"><?= Helpers::e($pendingEnrollment['secret']) ?></span>
                <button type="button" class="btn btn-sm btn-secondary" id="mfaCopyBtn">Copy</button>
            </div>
            <p class="checkbox-hint" style="margin-top: 0.5rem;">Time-based, 6 digits, 30-second refresh.</p>
        </div>
    </div>

    <form method="post" class="inline-form-row" style="margin-bottom: 0.75rem;">
        <input type="hidden" name="action" value="confirm_enrollment">
        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
        <label class="field">
            <span>Code from your app</span>
            <input type="text" name="code" class="totp-input" inputmode="numeric" pattern="[0-9]*"
                autocomplete="one-time-code" maxlength="6" required autofocus>
        </label>
        <button type="submit" class="btn btn-primary">Confirm and enable</button>
    </form>

    <form method="post">
        <input type="hidden" name="action" value="cancel_enrollment">
        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
        <button type="submit" class="btn btn-sm btn-secondary">Cancel setup</button>
    </form>
</div>

<script src="/assets/js/qrcode.js"></script>
<script>
(function () {
    var uri = <?= json_encode($pendingEnrollment['uri']) ?>;
    var target = document.getElementById('mfaQr');
    if (target && window.qrcode) {
        var qr = qrcode(0, 'M');
        qr.addData(uri);
        qr.make();
        target.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true });
    }

    var copyBtn = document.getElementById('mfaCopyBtn');
    var secretEl = document.getElementById('mfaSecretText');
    if (copyBtn && secretEl) {
        copyBtn.addEventListener('click', function () {
            var text = secretEl.textContent || '';
            var done = function () {
                var original = copyBtn.textContent;
                copyBtn.textContent = 'Copied';
                setTimeout(function () { copyBtn.textContent = original; }, 1500);
            };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(done, function () {
                    // Clipboard permission denied or unavailable - the key is
                    // already shown as selectable text, so this is a
                    // convenience feature only, not a requirement.
                });
            }
        });
    }
})();
</script>

<?php else: ?>

<div class="panel">
    <h2>Set up two-factor authentication</h2>
    <p class="page-subtitle" style="margin-bottom: 1rem;">
        Not currently enabled on your account. Once set up, signing in will ask for a 6-digit code from an
        authenticator app (Google Authenticator, Authy, 1Password, etc) in addition to your password.
    </p>
    <form method="post">
        <input type="hidden" name="action" value="start_enrollment">
        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
        <button type="submit" class="btn btn-primary">Enable two-factor authentication</button>
    </form>
</div>

<?php endif; ?>

<?php require __DIR__ . '/../src/views/footer.php'; ?>
