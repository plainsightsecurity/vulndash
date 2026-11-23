<?php
declare(strict_types=1);

require_once __DIR__ . '/../../src/bootstrap.php';

use VulnDash\Lib\Auth;
use VulnDash\Lib\Config;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\Mailer;
use VulnDash\Lib\MfaService;
use VulnDash\Lib\PasswordResetRepository;
use VulnDash\Lib\TrustedDeviceRepository;
use VulnDash\Lib\UserRepository;

/**
 * Builds the public reset_password.php link embedded in the setup/reset
 * emails, and sends it via Mailer - shared by the create_user and
 * send_password_reset actions below, and by the difference between them
 * is only $purpose (which email copy Mailer sends and how long the link
 * lives - see PasswordResetRepository).
 */
function sendPasswordLink(int $userId, string $email, string $username, string $purpose): bool
{
    $token = PasswordResetRepository::issue($userId, $purpose);
    $baseUrl = rtrim((string)(Config::get('app.base_url') ?? ''), '/');
    $link = $baseUrl . '/reset_password?token=' . urlencode($token);

    return $purpose === PasswordResetRepository::PURPOSE_SETUP
        ? Mailer::sendPasswordSetupEmail($email, $username, $link)
        : Mailer::sendPasswordResetEmail($email, $username, $link);
}

Auth::requireAdmin();

$currentUserId = (int)($_SESSION['user_id'] ?? 0);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
        Helpers::setFlash('Your session expired - please try that again.', 'error');
        header('Location: /admin/users');
        exit;
    }

    $action = (string)($_POST['action'] ?? '');

    try {
        switch ($action) {
            case 'create_user':
                $username      = trim((string)($_POST['username'] ?? ''));
                $email         = trim((string)($_POST['email'] ?? ''));
                $isAdmin       = !empty($_POST['is_admin']);
                $canUninstall  = !empty($_POST['can_uninstall']);
                $tagIds        = array_map('intval', (array)($_POST['tag_ids'] ?? []));

                if ($username === '' || $email === '') {
                    throw new \RuntimeException('Username and email are both required.');
                }
                if (!$isAdmin && empty($tagIds)) {
                    throw new \RuntimeException('Assign at least one tag, or make this an admin account - otherwise the account will see no data at all.');
                }

                $userId = UserRepository::createUser($username, $email, $isAdmin, $tagIds, $canUninstall);

                if (sendPasswordLink($userId, $email, $username, PasswordResetRepository::PURPOSE_SETUP)) {
                    Helpers::setFlash("Account '{$username}' created - an email with a link to set a password has been sent to {$email}.");
                } else {
                    Helpers::setFlash(
                        "Account '{$username}' created, but the setup email could not be sent - check src/config/config.php's " .
                        "resend settings and the server error log. Use \"Email password reset link\" below to retry once fixed, " .
                        "or \"Reset password\" to set one directly.",
                        'error'
                    );
                }
                break;

            case 'update_tags':
                $userId = (int)($_POST['user_id'] ?? 0);
                $tagIds = array_map('intval', (array)($_POST['tag_ids'] ?? []));
                $user = UserRepository::getUser($userId);
                if ($user && !$user['is_admin'] && empty($tagIds)) {
                    throw new \RuntimeException('This account has no admin flag, so it needs at least one tag or it will see no data.');
                }
                UserRepository::updateUserTags($userId, $tagIds);
                Helpers::setFlash('Tag assignments updated.');
                break;

            case 'toggle_admin':
                $userId = (int)($_POST['user_id'] ?? 0);
                if ($userId === $currentUserId) {
                    throw new \RuntimeException("You can't change your own admin status.");
                }
                $user = UserRepository::getUser($userId);
                if ($user) {
                    UserRepository::setAdmin($userId, !$user['is_admin']);
                    Helpers::setFlash('Admin status updated.');
                }
                break;

            case 'toggle_uninstall':
                // Grant/revoke the agent-uninstall capability for a client
                // account. Admins are always capable in code (Auth::canUninstall),
                // so this toggle is only meaningful for non-admins; the button is
                // hidden for admins in the table below. Revoking takes effect on
                // the account's next dashboard action (public/assets.php re-reads
                // the flag from the DB before queueing anything).
                $userId = (int)($_POST['user_id'] ?? 0);
                $user = UserRepository::getUser($userId);
                if ($user) {
                    UserRepository::setCanUninstall($userId, !UserRepository::getCanUninstall($userId));
                    Helpers::setFlash('Agent-uninstall permission updated.');
                }
                break;

            case 'toggle_active':
                $userId = (int)($_POST['user_id'] ?? 0);
                if ($userId === $currentUserId) {
                    throw new \RuntimeException("You can't deactivate your own account.");
                }
                $user = UserRepository::getUser($userId);
                if ($user) {
                    UserRepository::setActive($userId, !$user['is_active']);
                    Helpers::setFlash('Account status updated.');
                }
                break;

            case 'reset_password':
                $userId   = (int)($_POST['user_id'] ?? 0);
                $password = (string)($_POST['password'] ?? '');
                if (strlen($password) < 12) {
                    throw new \RuntimeException('Password must be at least 12 characters.');
                }
                UserRepository::resetPassword($userId, $password);
                Helpers::setFlash('Password reset.');
                break;

            case 'send_password_reset':
                $userId = (int)($_POST['user_id'] ?? 0);
                $user = UserRepository::getUser($userId);
                if (!$user) {
                    throw new \RuntimeException('That account no longer exists.');
                }
                if (sendPasswordLink($userId, $user['email'], $user['username'], PasswordResetRepository::PURPOSE_RESET)) {
                    Helpers::setFlash("Password reset email sent to {$user['email']}.");
                } else {
                    Helpers::setFlash(
                        "Could not send the reset email - check src/config/config.php's resend settings and the server error log.",
                        'error'
                    );
                }
                break;

            case 'delete_user':
                $userId = (int)($_POST['user_id'] ?? 0);
                if ($userId === $currentUserId) {
                    throw new \RuntimeException("You can't delete your own account.");
                }
                UserRepository::deleteUser($userId);
                Helpers::setFlash('Account deleted.');
                break;

            case 'reset_mfa':
                $userId = (int)($_POST['user_id'] ?? 0);
                MfaService::disable($userId);
                Helpers::setFlash('Two-factor authentication has been reset for this account - they will need to set it up again. Any trusted devices were revoked at the same time.');
                break;

            case 'revoke_trusted_device':
                $userId = (int)($_POST['user_id'] ?? 0);
                $deviceId = (int)($_POST['device_id'] ?? 0);
                if (TrustedDeviceRepository::revoke($deviceId, $userId, $currentUserId)) {
                    Helpers::setFlash('Device trust revoked.');
                } else {
                    throw new \RuntimeException('That device was not found - it may already be revoked.');
                }
                break;

            case 'revoke_all_trusted_devices':
                $userId = (int)($_POST['user_id'] ?? 0);
                TrustedDeviceRepository::revokeAllForUser($userId, $currentUserId);
                Helpers::setFlash('All trusted devices revoked for this account.');
                break;

            case 'create_tag':
                $qualysTagId = trim((string)($_POST['qualys_tag_id'] ?? ''));
                $name = trim((string)($_POST['name'] ?? ''));
                if ($name === '') {
                    throw new \RuntimeException('A tag name is required.');
                }
                if (strlen($qualysTagId) > 191) {
                    throw new \RuntimeException('That identifier is too long (max 191 characters).');
                }
                // Empty identifier = a "pending" tag: assignable to an account
                // now, its Qualys ID filled in automatically the first time an
                // agent carrying a tag of this name reports (see
                // UserRepository::resolveSyncedTagId()).
                UserRepository::createTag($qualysTagId !== '' ? $qualysTagId : null, $name);
                Helpers::setFlash(
                    $qualysTagId !== ''
                        ? "Tag '{$name}' created."
                        : "Pending tag '{$name}' created. Assign it to an account now if you like - it'll "
                          . "start showing data automatically once an agent carrying a tag named "
                          . "\"{$name}\" first reports in."
                );
                break;

            case 'delete_tag':
                $tagId = (int)($_POST['tag_id'] ?? 0);
                UserRepository::deleteTag($tagId);
                Helpers::setFlash('Tag deleted.');
                break;

            default:
                throw new \RuntimeException('Unknown action.');
        }
    } catch (\RuntimeException $e) {
        Helpers::setFlash($e->getMessage(), 'error');
    }

    header('Location: /admin/users');
    exit;
}

$users = UserRepository::listUsers();
$tags  = UserRepository::listTags();

// One extra query for every MFA-enabled account's trusted devices, rather
// than one query per row - see TrustedDeviceRepository::listForUsers().
$mfaUserIds = array_column(array_filter($users, static fn(array $u): bool => (bool)$u['mfa_enabled']), 'id');
$trustedDevicesByUser = TrustedDeviceRepository::listForUsers($mfaUserIds);

// Every asset is agent-scoped now (scripts/lib/QualysApiClient.php's agent
// scope filter), so there's just one flat tag list to assign from - no more
// Agent Tags/Scans split.

$editUserId    = isset($_GET['edit']) ? (int)$_GET['edit'] : null;
$editUser      = $editUserId ? UserRepository::getUser($editUserId) : null;
$editUserTagIds = $editUserId ? UserRepository::getUserTagIds($editUserId) : [];

$csrfToken = Helpers::csrfToken();
$flash = Helpers::getFlash();

/**
 * Renders one tag-selection combobox - a labelled button that opens a
 * searchable, checkbox-based panel. This replaces the older flat wall-of-
 * checkboxes now that there can be far more tags than comfortably fit as a
 * static grid: the panel has its own filter box and a scrolling list
 * instead of growing the page indefinitely.
 *
 * Used to be rendered twice per form (an "Agent Tags" bucket and a "Scans"
 * bucket - see UserRepository's former tagTypeJoinSql(), removed 2026-07
 * when this became an agent-only internal tool); with only one kind of tag
 * left there's just the one combo now.
 *
 * Still just checkboxes named tag_ids[] underneath - the open/close
 * behaviour, filtering, and the "N selected" summary are all handled by
 * the one shared script in src/views/footer.php, which finds every
 * .tag-combo on the page and wires it up generically.
 *
 * @param array<int, array<string, mixed>> $tagGroup
 * @param int[] $checkedTagIds
 */
$renderTagCombo = static function (array $tagGroup, string $heading, array $checkedTagIds): void {
    if (empty($tagGroup)) {
        return;
    }
    ?>
    <div class="tag-combo">
        <button type="button" class="tag-combo-toggle" aria-expanded="false">
            <span class="tag-combo-toggle-label"><?= Helpers::e($heading) ?></span>
            <span class="tag-combo-summary"></span>
        </button>
        <div class="tag-combo-panel" hidden>
            <input type="text" class="tag-combo-search" placeholder="Filter…" aria-label="Filter <?= Helpers::e($heading) ?>">
            <div class="tag-combo-actions">
                <button type="button" class="tag-combo-selectall">Select all</button>
                <button type="button" class="tag-combo-clear">Clear</button>
            </div>
            <div class="tag-combo-list">
                <?php foreach ($tagGroup as $tag): ?>
                <label class="tag-combo-option">
                    <input type="checkbox" name="tag_ids[]" value="<?= (int)$tag['id'] ?>"
                        <?= in_array((int)$tag['id'], $checkedTagIds, true) ? 'checked' : '' ?>>
                    <span>
                        <?= Helpers::e($tag['name']) ?>
                        <?php if (($tag['qualys_tag_id'] ?? null) === null): ?><span class="checkbox-hint">(pending)</span><?php endif; ?>
                    </span>
                </label>
                <?php endforeach; ?>
            </div>
            <p class="tag-combo-empty" hidden>No matches.</p>
        </div>
    </div>
    <?php
};

$pageTitle = 'Manage Users';
require __DIR__ . '/../../src/views/header.php';
?>

<div class="page-heading">
    <h1>Manage Users</h1>
    <p class="page-subtitle">Create accounts and control which Qualys tags each one can see.</p>
</div>

<?php if ($flash): ?>
<div class="flash flash-<?= Helpers::e($flash['type']) ?>"><?= Helpers::e($flash['message']) ?></div>
<?php endif; ?>

<?php if ($editUser): ?>
<div class="panel edit-panel">
    <h2>Edit tags for <?= Helpers::e($editUser['username']) ?></h2>
    <form method="post">
        <input type="hidden" name="action" value="update_tags">
        <input type="hidden" name="user_id" value="<?= (int)$editUser['id'] ?>">
        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">

        <?php if (empty($tags)): ?>
        <p class="no-tags">No tags exist yet - add one in the "Tags" section below first.</p>
        <?php else: ?>
        <div class="tag-combo-row">
            <?php $renderTagCombo($tags, 'Tags', $editUserTagIds); ?>
        </div>
        <?php endif; ?>

        <button type="submit" class="btn btn-primary btn-sm">Save tags</button>
        <a class="btn btn-secondary btn-sm" href="/admin/users">Cancel</a>
    </form>
</div>
<?php endif; ?>

<div class="panel">
    <h2>Add a new user</h2>
    <form method="post">
        <input type="hidden" name="action" value="create_user">
        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">

        <div class="inline-form-row">
            <label class="field">
                <span>Username</span>
                <input type="text" name="username" required>
            </label>
            <label class="field">
                <span>Email</span>
                <input type="email" name="email" required>
            </label>
        </div>
        <p class="checkbox-hint" style="margin: 0.4rem 0 0;">
            No password to set here - they'll get an email with a link to create their own once the account is created.
        </p>

        <label class="checkbox-field" style="margin: 0.75rem 0 0.4rem;">
            <input type="checkbox" name="is_admin" value="1">
            <span>Admin account <span class="checkbox-hint">(sees everything, no tag scoping)</span></span>
        </label>

        <label class="checkbox-field" style="margin: 0 0 0.75rem;">
            <input type="checkbox" name="can_uninstall" value="1">
            <span>Can uninstall agents <span class="checkbox-hint">(may queue Cloud Agent uninstalls from the Assets page; admins always can)</span></span>
        </label>

        <p class="page-subtitle" style="margin: 0 0 0.25rem;">Tag scope (ignored for admin accounts):</p>
        <?php if (empty($tags)): ?>
        <p class="no-tags">No tags exist yet - add one in the "Tags" section below first, or check "Admin account" above.</p>
        <?php else: ?>
        <div class="tag-combo-row">
            <?php $renderTagCombo($tags, 'Tags', []); ?>
        </div>
        <?php endif; ?>

        <button type="submit" class="btn btn-primary">Create account</button>
    </form>
</div>

<div class="panel">
    <h2>Users</h2>
    <div class="table-wrap">
    <table class="vuln-table admin-table">
        <thead>
            <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Tags</th>
                <th>MFA</th>
                <th>Last login</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php if (empty($users)): ?>
            <tr class="empty-row"><td colspan="7">No users yet.</td></tr>
            <?php else: foreach ($users as $u):
                $userMfaEnabled = (bool)$u['mfa_enabled'];
                $userDevices = $trustedDevicesByUser[(int)$u['id']] ?? [];
            ?>
            <tr class="user-row<?= $u['is_active'] ? '' : ' user-inactive' ?>">
                <td class="nowrap"><?= Helpers::e($u['username']) ?><?= (int)$u['id'] === $currentUserId ? ' <span class="checkbox-hint">(you)</span>' : '' ?><?php if (!$u['is_active']): // active is the norm, so only the exception is shown ?> <span class="badge badge-inactive">Inactive</span><?php endif; ?></td>
                <td><?= Helpers::e($u['email']) ?></td>
                <td class="nowrap">
                    <span class="badge <?= $u['is_admin'] ? 'badge-accent' : 'badge-neutral' ?>"><?= $u['is_admin'] ? 'Admin' : 'Client' ?></span>
                    <?php if (!$u['is_admin'] && !empty($u['can_uninstall_agents'])): // admins can always uninstall, so only a client's grant is worth showing ?>
                    <span class="badge badge-neutral" title="May queue Cloud Agent uninstalls from the Assets page">Uninstall</span>
                    <?php endif; ?>
                </td>
                <td>
                    <?php if (!empty($u['tag_names'])): ?>
                    <div class="tag-chip-list">
                        <?php foreach (explode(', ', $u['tag_names']) as $tagName): ?>
                        <span class="tag-chip tag-chip-clip" title="<?= Helpers::e($tagName) ?>"><?= Helpers::e($tagName) ?></span>
                        <?php endforeach; ?>
                    </div>
                    <?php elseif ($u['is_admin']): ?>
                    <span class="no-tags">all data (admin)</span>
                    <?php else: ?>
                    <span class="no-tags">none - sees nothing</span>
                    <?php endif; ?>
                </td>
                <td class="nowrap">
                    <span class="badge <?= $userMfaEnabled ? 'badge-active' : 'badge-neutral' ?>"<?= $userMfaEnabled ? ' title="' . count($userDevices) . ' trusted device' . (count($userDevices) === 1 ? '' : 's') . '"' : '' ?>><?= $userMfaEnabled ? 'On' : 'Off' ?></span>
                </td>
                <td class="mono nowrap" title="<?= Helpers::e(Helpers::displayDateTime($u['last_login_at'])) ?>"><?php
                    // Short form: time this year, year for anything older. Full value on hover.
                    $loginShortFormat = $u['last_login_at'] !== null && substr((string)$u['last_login_at'], 0, 4) === date('Y') ? 'j M H:i' : 'j M Y';
                    echo Helpers::e(Helpers::displayDateTime($u['last_login_at'], $loginShortFormat));
                ?></td>
                <td>
                    <div class="actions-cell actions-nowrap">
                        <a class="btn btn-sm btn-secondary" href="/admin/users?edit=<?= (int)$u['id'] ?>">Edit tags</a>
                        <button type="button" class="btn btn-sm btn-secondary manage-toggle" data-manage-toggle aria-expanded="false" aria-controls="manage-<?= (int)$u['id'] ?>">Manage <span class="manage-caret" aria-hidden="true">&#9662;</span></button>
                    </div>
                </td>
            </tr>
            <tr class="user-manage-row" id="manage-<?= (int)$u['id'] ?>" hidden>
                <td colspan="7">
                    <div class="user-manage">
                        <?php if ((int)$u['id'] !== $currentUserId): ?>
                        <div class="user-manage-group">
                            <h3>Access</h3>
                            <div class="actions-cell">
                                <form method="post" onsubmit="return confirm(<?= Helpers::jsAttr('Toggle admin status for ' . $u['username'] . '?') ?>);">
                                    <input type="hidden" name="action" value="toggle_admin">
                                    <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                    <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                                    <button type="submit" class="btn btn-sm btn-secondary"><?= $u['is_admin'] ? 'Remove admin' : 'Make admin' ?></button>
                                </form>

                                <?php if (!$u['is_admin']): // admins are always capable, so the toggle only applies to client accounts ?>
                                <form method="post" onsubmit="return confirm(<?= Helpers::jsAttr((!empty($u['can_uninstall_agents']) ? 'Revoke agent-uninstall permission from ' : 'Allow ') . $u['username'] . (!empty($u['can_uninstall_agents']) ? '' : ' to uninstall agents') . '?') ?>);">
                                    <input type="hidden" name="action" value="toggle_uninstall">
                                    <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                    <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                                    <button type="submit" class="btn btn-sm btn-secondary"><?= !empty($u['can_uninstall_agents']) ? 'Revoke uninstall' : 'Allow uninstall' ?></button>
                                </form>
                                <?php endif; ?>
                            </div>
                        </div>
                        <?php endif; ?>

                        <div class="user-manage-group">
                            <h3>Password</h3>
                            <div class="actions-cell">
                                <form method="post">
                                    <input type="hidden" name="action" value="send_password_reset">
                                    <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                    <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                                    <button type="submit" class="btn btn-sm btn-secondary">Email reset link</button>
                                </form>
                            </div>
                            <form method="post" class="inline-form-row user-manage-password">
                                <input type="hidden" name="action" value="reset_password">
                                <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                                <input type="password" name="password" minlength="12" placeholder="Or set one (12+ chars)" required>
                                <button type="submit" class="btn btn-sm btn-secondary">Set</button>
                            </form>
                        </div>

                        <?php if ($userMfaEnabled): ?>
                        <div class="user-manage-group">
                            <h3>MFA</h3>
                            <?php if (!empty($userDevices)): ?>
                            <ul class="user-manage-devices">
                                <?php foreach ($userDevices as $device): ?>
                                <li>
                                    <?= Helpers::e($device['device_label'] ?? 'Unknown device') ?>
                                    <span class="checkbox-hint">
                                        (<?= Helpers::e($device['ip_address'] ?? 'unknown IP') ?>,
                                        last used <?= $device['last_used_at'] ? Helpers::e(Helpers::relativeTime($device['last_used_at'])) : 'never' ?>)
                                    </span>
                                    <form method="post" style="display: inline;" onsubmit="return confirm('Revoke trust for this device?');">
                                        <input type="hidden" name="action" value="revoke_trusted_device">
                                        <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                        <input type="hidden" name="device_id" value="<?= (int)$device['id'] ?>">
                                        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                                        <button type="submit" class="btn btn-sm btn-danger" style="margin-left: 0.4rem;">Revoke</button>
                                    </form>
                                </li>
                                <?php endforeach; ?>
                            </ul>
                            <?php else: ?>
                            <p class="no-tags" style="margin: 0 0 0.5rem;">No trusted devices.</p>
                            <?php endif; ?>
                            <div class="actions-cell">
                                <?php if (!empty($userDevices)): ?>
                                <form method="post" onsubmit="return confirm(<?= Helpers::jsAttr('Revoke every trusted device for ' . $u['username'] . '?') ?>);">
                                    <input type="hidden" name="action" value="revoke_all_trusted_devices">
                                    <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                    <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                                    <button type="submit" class="btn btn-sm btn-secondary">Revoke all devices</button>
                                </form>
                                <?php endif; ?>
                                <form method="post" onsubmit="return confirm(<?= Helpers::jsAttr('Reset MFA for ' . $u['username'] . '? They will need to set up two-factor authentication again from scratch, and any trusted devices will be revoked. Use this if they lost their authenticator device.') ?>);">
                                    <input type="hidden" name="action" value="reset_mfa">
                                    <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                    <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                                    <button type="submit" class="btn btn-sm btn-danger">Reset MFA</button>
                                </form>
                            </div>
                        </div>
                        <?php endif; ?>

                        <?php if ((int)$u['id'] !== $currentUserId): ?>
                        <div class="user-manage-group">
                            <h3>Account</h3>
                            <div class="actions-cell">
                                <form method="post" onsubmit="return confirm(<?= Helpers::jsAttr(($u['is_active'] ? 'Deactivate ' : 'Reactivate ') . $u['username'] . '?') ?>);">
                                    <input type="hidden" name="action" value="toggle_active">
                                    <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                    <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                                    <button type="submit" class="btn btn-sm btn-secondary"><?= $u['is_active'] ? 'Deactivate' : 'Reactivate' ?></button>
                                </form>

                                <form method="post" onsubmit="return confirm(<?= Helpers::jsAttr('Permanently delete ' . $u['username'] . '? This cannot be undone.') ?>);">
                                    <input type="hidden" name="action" value="delete_user">
                                    <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                    <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                                    <button type="submit" class="btn btn-sm btn-danger">Delete</button>
                                </form>
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>
                </td>
            </tr>
            <?php endforeach; endif; ?>
        </tbody>
    </table>
    </div>
</div>

<div class="panel">
    <h2>Tags</h2>
    <p class="page-subtitle" style="margin-bottom: 0.75rem;">
        Tags are normally created automatically the first time an agent carrying one reports in.
        To onboard a client <em>before</em> their agents exist, add the tag here by name and leave the
        Qualys identifier blank - it becomes a <strong>pending</strong> tag you can assign to an account
        straight away, and it links to Qualys automatically the first time an agent carrying a tag of that
        exact name reports (matched case-insensitively). The name must match the Qualys tag name exactly
        apart from case. If you already know the Qualys identifier (the numeric tag ID, a tag name, or an
        Activation UUID), enter it and the tag is live immediately.
    </p>

    <?php if (!empty($tags)): ?>
    <div class="table-wrap" style="margin-bottom: 1.25rem;">
        <table class="vuln-table admin-table">
            <thead><tr><th>Name</th><th>Qualys identifier</th><th>Users</th><th>Assets</th><th>Actions</th></tr></thead>
            <tbody>
                <?php foreach ($tags as $tag):
                    $tagUserCount  = (int)($tag['user_count'] ?? 0);
                    $tagAssetCount = (int)($tag['asset_count'] ?? 0);
                    $tagInUse = $tagUserCount > 0 || $tagAssetCount > 0;
                    $confirmMsg = $tagInUse
                        ? "Delete tag \"{$tag['name']}\"? It's currently assigned to {$tagUserCount} user(s) and {$tagAssetCount} asset(s) - removing it may leave some accounts unable to see any data until reassigned. This cannot be undone."
                        : "Delete tag \"{$tag['name']}\"? This cannot be undone.";
                ?>
                <tr>
                    <td><?= Helpers::e($tag['name']) ?></td>
                    <td class="mono">
                        <?php if ($tag['qualys_tag_id'] === null): ?>
                        <span class="tag-pending" title="Waiting for the first agent carrying a tag named &quot;<?= Helpers::e($tag['name']) ?>&quot; to report. Its Qualys ID will be filled in automatically then.">pending</span>
                        <?php else: ?>
                        <?= Helpers::e($tag['qualys_tag_id']) ?>
                        <?php endif; ?>
                    </td>
                    <td class="mono"><?= $tagUserCount ?></td>
                    <td class="mono"><?= $tagAssetCount ?></td>
                    <td>
                        <form method="post" onsubmit="return confirm(<?= Helpers::jsAttr($confirmMsg) ?>);">
                            <input type="hidden" name="action" value="delete_tag">
                            <input type="hidden" name="tag_id" value="<?= (int)$tag['id'] ?>">
                            <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                            <button type="submit" class="btn btn-sm btn-danger">Delete</button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>

    <form method="post" class="inline-form-row">
        <input type="hidden" name="action" value="create_tag">
        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
        <label class="field">
            <span>Tag name</span>
            <input type="text" name="name" placeholder="e.g. Acme Corp - Production" required>
        </label>
        <label class="field">
            <span>Qualys identifier <span class="checkbox-hint">(optional - leave blank for a pending tag)</span></span>
            <input type="text" name="qualys_tag_id" placeholder="e.g. 101516261 - or blank to link on first agent report" maxlength="191">
        </label>
        <button type="submit" class="btn btn-secondary">Add tag</button>
    </form>
</div>

<noscript><style>.user-manage-row { display: table-row; } .manage-toggle { display: none; }</style></noscript>
<script>
// Each user row's "Manage" button shows or hides the full-width row of
// less-used actions beneath it. A row rather than a dropdown because the
// table's horizontal-scroll wrapper would clip anything positioned over it.
document.querySelectorAll('[data-manage-toggle]').forEach(function (btn) {
    btn.addEventListener('click', function () {
        var row = document.getElementById(btn.getAttribute('aria-controls'));
        if (!row) { return; }
        var opening = row.hidden;
        row.hidden = !opening;
        btn.setAttribute('aria-expanded', opening ? 'true' : 'false');
    });
});
</script>
<?php require __DIR__ . '/../../src/views/footer.php'; ?>
