<?php
declare(strict_types=1);

require_once __DIR__ . '/../../src/bootstrap.php';

use VulnDash\Lib\AuditLog;
use VulnDash\Lib\Auth;
use VulnDash\Lib\Config;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\Mailer;
use VulnDash\Lib\OrganisationRepository;
use VulnDash\Lib\PasswordResetRepository;
use VulnDash\Lib\UserRepository;

/**
 * "My organisation" - an organisation admin manages their own
 * organisation's accounts (2026-11). Deliberately narrow:
 *
 *   - invite: username + email; the new account joins this organisation
 *     with no extra tags, no admin or organisation-admin rights and no
 *     uninstall grant, and is emailed a setup link
 *   - deactivate / reactivate members (not themselves, not other
 *     organisation admins - only a Plainsight Security admin can change those)
 *   - send a member a fresh password link, to the address already on file
 *
 * Nothing here can change tags, emails, roles or another organisation. Every
 * action re-reads the target account and refuses it unless it is a member
 * of the caller's organisation. Inviting and reactivating are refused once
 * the organisation has max_users ACTIVE accounts.
 */
$orgId = Auth::requireOrgAdmin();
$myId  = (int)$_SESSION['user_id'];

/** A member of this organisation that this organisation admin may act on. */
function orgMember(int $userId, int $orgId, int $myId): array
{
    $user = UserRepository::getUser($userId);
    if ($user === null || (int)$user['organisation_id'] !== $orgId || $user['is_admin']) {
        throw new \RuntimeException('That account is not in your organisation.');
    }
    if ($userId === $myId) {
        throw new \RuntimeException("You can't change your own account here.");
    }
    if ((int)$user['is_org_admin'] === 1) {
        throw new \RuntimeException('Organisation admins can only be changed by Plainsight Security.');
    }
    return $user;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
        Helpers::setFlash('Your session expired - please try that again.', 'error');
        header('Location: /org/users');
        exit;
    }
    $action = (string)($_POST['action'] ?? '');
    $target = static fn (int $id, string $name): array => ['target_type' => 'user', 'target_id' => $id, 'target_label' => $name];
    $sendLink = static function (int $userId, string $email, string $username, bool $setup): bool {
        $purpose = $setup ? PasswordResetRepository::PURPOSE_SETUP : PasswordResetRepository::PURPOSE_RESET;
        $link = rtrim((string)(Config::get('app.base_url') ?? ''), '/') . '/reset_password?token=' . urlencode(PasswordResetRepository::issue($userId, $purpose));
        return $setup ? Mailer::sendPasswordSetupEmail($email, $username, $link) : Mailer::sendPasswordResetEmail($email, $username, $link);
    };

    try {
        $org = OrganisationRepository::get($orgId) ?? throw new \RuntimeException('Your organisation no longer exists.');
        switch ($action) {
            case 'invite':
                $username = trim((string)($_POST['username'] ?? ''));
                $email    = trim((string)($_POST['email'] ?? ''));
                if ($username === '' || mb_strlen($username) > 64) {
                    throw new \RuntimeException('Enter a username (up to 64 characters).');
                }
                if (($error = Helpers::emailError($email)) !== null) {
                    throw new \RuntimeException($error);
                }
                if (!OrganisationRepository::hasRoom($orgId)) {
                    throw new \RuntimeException("Your organisation has reached its limit of {$org['max_users']} active users. Deactivate someone first, or ask Plainsight Security to raise the limit.");
                }
                $userId = UserRepository::createUser($username, $email, false, [], false, $orgId, false);
                AuditLog::record('org.user_invited', $target($userId, $username) + ['details' => ['email' => $email, 'organisation' => $org['name']]]);
                $sent = $sendLink($userId, $email, $username, true);
                if ($sent) {
                    Helpers::setFlash("Invited {$username} - they've been emailed a link to set their password.");
                } else {
                    Helpers::setFlash("Created {$username}, but the invitation email couldn't be sent. Try \"Send password link\" shortly, or contact Plainsight Security.", 'error');
                }
                break;

            case 'toggle_active':
                $user = orgMember((int)($_POST['user_id'] ?? 0), $orgId, $myId);
                $activate = !$user['is_active'];
                if ($activate && !OrganisationRepository::hasRoom($orgId)) {
                    throw new \RuntimeException("Your organisation has reached its limit of {$org['max_users']} active users, so {$user['username']} can't be reactivated until someone else is deactivated.");
                }
                UserRepository::setActive((int)$user['id'], $activate);
                AuditLog::record('org.user_active_changed', $target((int)$user['id'], $user['username']) + ['details' => ['active' => $activate]]);
                Helpers::setFlash($activate ? "{$user['username']} reactivated." : "{$user['username']} deactivated - they're signed out and can't sign in.");
                break;

            case 'send_link':
                $user = orgMember((int)($_POST['user_id'] ?? 0), $orgId, $myId);
                if (!$user['is_active']) {
                    throw new \RuntimeException("{$user['username']} is deactivated - reactivate them first.");
                }
                $setup = $user['last_login_at'] === null;
                if (!$sendLink((int)$user['id'], $user['email'], $user['username'], $setup)) {
                    throw new \RuntimeException("The email to {$user['username']} couldn't be sent - please try again shortly.");
                }
                AuditLog::record('org.setup_link_sent', $target((int)$user['id'], $user['username']) + ['details' => ['purpose' => $setup ? 'setup' : 'reset']]);
                Helpers::setFlash("Sent {$user['username']} a " . ($setup ? 'password setup' : 'password reset') . ' link.');
                break;

            default:
                throw new \RuntimeException('Unknown action.');
        }
    } catch (\RuntimeException $e) {
        Helpers::setFlash($e->getMessage(), 'error');
    }
    header('Location: /org/users');
    exit;
}

$org = OrganisationRepository::get($orgId);
$members = UserRepository::listUsers(null, null, 'username', 'asc', $orgId);
$full = $org['max_users'] !== null && $org['active_users'] >= $org['max_users'];
$csrfToken = Helpers::csrfToken();
$flash = Helpers::getFlash();

$pageTitle = 'My organisation';
require __DIR__ . '/../../src/views/header.php';
?>

<div class="page-heading">
    <h1><?= Helpers::e($org['name']) ?></h1>
    <p class="page-subtitle">
        <?= $org['active_users'] ?> active user<?= $org['active_users'] === 1 ? '' : 's' ?><?= $org['max_users'] !== null ? ' of ' . $org['max_users'] . ' allowed' : '' ?>.
        Everyone here sees the same systems; Plainsight Security manages which those are.
    </p>
</div>

<?php if ($flash): ?>
<div class="flash flash-<?= Helpers::e($flash['type']) ?>"><?= Helpers::e($flash['message']) ?></div>
<?php endif; ?>

<div class="panel">
    <h2>Invite someone</h2>
    <?php if ($full): ?>
    <p class="no-tags">You've reached your limit of <?= (int)$org['max_users'] ?> active users. Deactivate someone below to make room, or ask Plainsight Security to raise the limit.</p>
    <?php else: ?>
    <form method="post" class="inline-form-row" style="align-items: flex-end;">
        <input type="hidden" name="action" value="invite">
        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
        <label class="field"><span>Username</span><input type="text" name="username" maxlength="64" required autocomplete="off"></label>
        <label class="field"><span>Email</span><input type="email" name="email" required pattern="<?= Helpers::e(Helpers::EMAIL_INPUT_PATTERN) ?>" title="A full email address, e.g. name@company.co.uk" autocomplete="off"></label>
        <button type="submit" class="btn btn-primary">Send invitation</button>
    </form>
    <p class="checkbox-hint" style="margin: 0.5rem 0 0;">They'll get an email with a link to set their password, valid for 7 days.</p>
    <?php endif; ?>
</div>

<div class="panel">
    <h2>People</h2>
    <div class="table-wrap">
    <table class="vuln-table admin-table">
        <thead><tr><th>Username</th><th>Email</th><th>Status</th><th>Last sign-in</th><th>Actions</th></tr></thead>
        <tbody>
            <?php foreach ($members as $m):
                $mine = (int)$m['id'] === $myId;
                $orgAdmin = (int)$m['is_org_admin'] === 1;
            ?>
            <tr class="<?= $m['is_active'] ? '' : 'user-inactive' ?>">
                <td class="nowrap"><?= Helpers::e($m['username']) ?><?= $mine ? ' <span class="checkbox-hint">(you)</span>' : '' ?><?= $orgAdmin ? ' <span class="badge badge-accent">Org admin</span>' : '' ?></td>
                <td><?= Helpers::e($m['email']) ?></td>
                <td><span class="badge <?= $m['is_active'] ? 'badge-active' : 'badge-inactive' ?>"><?= $m['is_active'] ? 'Active' : 'Deactivated' ?></span></td>
                <td class="mono"><?= $m['last_login_at'] !== null ? Helpers::e(Helpers::displayDateTime($m['last_login_at'])) : '<span class="no-tags">not yet</span>' ?></td>
                <td>
                    <?php if (!$mine && !$orgAdmin): ?>
                    <div class="actions-cell">
                        <?php if ($m['is_active']): ?>
                        <form method="post">
                            <input type="hidden" name="action" value="send_link">
                            <input type="hidden" name="user_id" value="<?= (int)$m['id'] ?>">
                            <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                            <button type="submit" class="btn btn-sm btn-secondary">Send password link</button>
                        </form>
                        <?php endif; ?>
                        <form method="post" onsubmit="return confirm(<?= Helpers::jsAttr(($m['is_active'] ? 'Deactivate ' : 'Reactivate ') . $m['username'] . '?') ?>);">
                            <input type="hidden" name="action" value="toggle_active">
                            <input type="hidden" name="user_id" value="<?= (int)$m['id'] ?>">
                            <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                            <button type="submit" class="btn btn-sm <?= $m['is_active'] ? 'btn-danger' : 'btn-secondary' ?>" <?= !$m['is_active'] && $full ? 'disabled title="At your user limit"' : '' ?>><?= $m['is_active'] ? 'Deactivate' : 'Reactivate' ?></button>
                        </form>
                    </div>
                    <?php else: ?>
                    <span class="no-tags">—</span>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    </div>
</div>

<?php require __DIR__ . '/../../src/views/footer.php'; ?>
