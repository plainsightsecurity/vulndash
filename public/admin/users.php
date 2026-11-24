<?php
declare(strict_types=1);

require_once __DIR__ . '/../../src/bootstrap.php';

use VulnDash\Lib\AgentInstall;
use VulnDash\Lib\AuditLog;
use VulnDash\Lib\Auth;
use VulnDash\Lib\Config;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\Mailer;
use VulnDash\Lib\MfaService;
use VulnDash\Lib\OrganisationRepository;
use VulnDash\Lib\PasswordResetRepository;
use VulnDash\Lib\TrustedDeviceRepository;
use VulnDash\Lib\UserImport;
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

/**
 * The Users list filter (search + tag) from a query array - $_GET, or the
 * query string of the page an action was posted from. Unknown keys and
 * malformed values are dropped, so the result is safe to rebuild a URL from.
 *
 * Sort column/direction ride along too, so an action keeps the order as well.
 *
 * @return array{q?: string, tag?: string, sort?: string, dir?: string}
 */
function userListFilter(array $query): array
{
    $filter = [];
    $q = trim((string)($query['q'] ?? ''));
    if ($q !== '') {
        $filter['q'] = mb_substr($q, 0, 100);
    }
    $tag = (string)($query['tag'] ?? '');
    if ($tag === UserRepository::TAG_FILTER_NONE || ctype_digit($tag)) {
        $filter['tag'] = $tag;
    }
    $org = (string)($query['org'] ?? '');
    if ($org === UserRepository::TAG_FILTER_NONE || ctype_digit($org)) {
        $filter['org'] = $org;
    }
    $sort = (string)($query['sort'] ?? '');
    if (isset(UserRepository::USER_SORT_COLUMNS[$sort])) {
        $filter['sort'] = $sort;
        $filter['dir'] = strtolower((string)($query['dir'] ?? '')) === 'desc' ? 'desc' : 'asc';
    }
    return $filter;
}

// Every action posts back here and then redirects; keep the admin on the
// filtered list they acted from rather than dropping them back on everyone.
$refererQuery = [];
parse_str((string)parse_url((string)($_SERVER['HTTP_REFERER'] ?? ''), PHP_URL_QUERY), $refererQuery);
$keptFilter = userListFilter($refererQuery);
$usersUrl = '/admin/users' . ($keptFilter !== [] ? '?' . http_build_query($keptFilter) : '');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
        Helpers::setFlash('Your session expired - please try that again.', 'error');
        header('Location: ' . $usersUrl);
        exit;
    }

    $action = (string)($_POST['action'] ?? '');

    // For the audit log: tag ids -> names, and the account being acted on
    // (looked up before the change, so a deleted account keeps its name).
    $tagNamesFor = static function (array $ids): array {
        $byId = array_column(UserRepository::listTags(), 'name', 'id');
        $names = array_map(static fn ($id) => (string)($byId[(int)$id] ?? "#{$id}"), $ids);
        sort($names);
        return $names;
    };
    $auditTarget = static function (int $userId): array {
        $u = UserRepository::getUser($userId);
        return ['target_type' => 'user', 'target_id' => $userId, 'target_label' => $u['username'] ?? "#{$userId}"];
    };

    try {
        switch ($action) {
            case 'create_user':
                $username      = trim((string)($_POST['username'] ?? ''));
                $email         = trim((string)($_POST['email'] ?? ''));
                $isAdmin       = !empty($_POST['is_admin']);
                $canUninstall  = !empty($_POST['can_uninstall']);
                $tagIds        = array_map('intval', (array)($_POST['tag_ids'] ?? []));
                $orgId         = (int)($_POST['organisation_id'] ?? 0) ?: null;
                $isOrgAdmin    = $orgId !== null && !empty($_POST['is_org_admin']);
                $org           = $orgId !== null ? OrganisationRepository::get($orgId) : null;
                if ($orgId !== null && $org === null) {
                    throw new \RuntimeException('That organisation no longer exists.');
                }

                if ($username === '' || $email === '') {
                    throw new \RuntimeException('Username and email are both required.');
                }
                if (($emailError = Helpers::emailError($email)) !== null) {
                    throw new \RuntimeException($emailError . ' The account was not created.');
                }
                if (!$isAdmin && empty($tagIds) && ($org === null || $org['tag_ids'] === [])) {
                    throw new \RuntimeException('Assign at least one tag, or an organisation that has tags, or make this an admin account - otherwise the account will see no data at all.');
                }

                $userId = UserRepository::createUser($username, $email, $isAdmin, $tagIds, $canUninstall, $isAdmin ? null : $orgId, !$isAdmin && $isOrgAdmin);
                AuditLog::record('admin.user_created', $auditTarget($userId) + ['details' => [
                    'email' => $email, 'admin' => $isAdmin, 'can_uninstall' => $canUninstall, 'tags' => $tagNamesFor($tagIds),
                    'organisation' => $org['name'] ?? null, 'org_admin' => $isOrgAdmin,
                ]]);

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
                $userOrg = $user && $user['organisation_id'] !== null ? OrganisationRepository::get((int)$user['organisation_id']) : null;
                if ($user && !$user['is_admin'] && empty($tagIds) && ($userOrg === null || $userOrg['tag_ids'] === [])) {
                    throw new \RuntimeException('This account has no admin flag and no organisation with tags, so it needs at least one tag or it will see no data.');
                }
                $tagsBefore = $tagNamesFor(UserRepository::getUserTagIds($userId));
                UserRepository::updateUserTags($userId, $tagIds);
                AuditLog::record('admin.user_tags_changed', $auditTarget($userId) + ['details' => [
                    'before' => $tagsBefore, 'after' => $tagNamesFor($tagIds),
                ]]);
                Helpers::setFlash('Tag assignments updated.');
                break;

            case 'import_csv':
                $file = $_FILES['csv'] ?? null;
                if (!is_array($file) || ($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK || !is_uploaded_file((string)$file['tmp_name'])) {
                    throw new \RuntimeException('Choose a CSV file to import.');
                }
                $parsed = UserImport::parse((string)file_get_contents((string)$file['tmp_name'], false, null, 0, UserImport::MAX_BYTES + 1));
                if ($parsed['errors'] !== []) {
                    $_SESSION['import_result'] = ['errors' => $parsed['errors']];
                    Helpers::setFlash('Nothing was imported - fix the problems listed under "Import from CSV" and try again.', 'error');
                    break;
                }
                $sendEmails = !empty($_POST['send_emails']);
                $result = UserImport::run($parsed['rows'], $sendEmails, static fn (int $id, string $email, string $username): bool
                    => sendPasswordLink($id, $email, $username, PasswordResetRepository::PURPOSE_SETUP));
                AuditLog::record('admin.users_imported', ['details' => [
                    'created' => $result['created'], 'failed' => $result['failed'], 'emails_sent' => $sendEmails,
                    'email_failed' => $result['email_failed'],
                ]]);
                $_SESSION['import_result'] = $result + ['warnings' => $parsed['warnings'], 'emails' => $sendEmails];
                Helpers::setFlash('Imported ' . count($result['created']) . ' account(s)'
                    . ($sendEmails ? ', each emailed a password setup link' : ' - no emails sent; use "Email reset link" on each when ready')
                    . '. Details under "Import from CSV".', $result['failed'] === [] && $result['email_failed'] === [] ? 'success' : 'error');
                break;

            case 'set_organisation':
                $userId = (int)($_POST['user_id'] ?? 0);
                $user = UserRepository::getUser($userId) ?? throw new \RuntimeException('That account no longer exists.');
                if ($user['is_admin']) {
                    throw new \RuntimeException('Admin accounts see everything and are not members of an organisation.');
                }
                $orgId = (int)($_POST['organisation_id'] ?? 0) ?: null;
                $org = $orgId !== null ? (OrganisationRepository::get($orgId) ?? throw new \RuntimeException('That organisation no longer exists.')) : null;
                $isOrgAdmin = $orgId !== null && !empty($_POST['is_org_admin']);
                $before = $user['organisation_id'] !== null ? (OrganisationRepository::get((int)$user['organisation_id'])['name'] ?? null) : null;
                if ($org === null && UserRepository::getUserTagIds($userId) === []) {
                    throw new \RuntimeException("{$user['username']} has no tags of their own, so removing their organisation would leave them seeing nothing. Give them a tag first, or deactivate the account.");
                }
                UserRepository::setOrganisation($userId, $orgId, $isOrgAdmin);
                AuditLog::record('admin.user_org_changed', $auditTarget($userId) + ['details' => [
                    'before' => ['organisation' => $before, 'org_admin' => (bool)$user['is_org_admin']],
                    'after'  => ['organisation' => $org['name'] ?? null, 'org_admin' => $isOrgAdmin],
                ]]);
                $over = $org !== null && $org['max_users'] !== null && $user['is_active'] && (int)$user['organisation_id'] !== $orgId
                    && $org['active_users'] + 1 > $org['max_users'];
                Helpers::setFlash($org === null
                    ? "{$user['username']} is no longer in an organisation."
                    : "{$user['username']} is now in {$org['name']}" . ($isOrgAdmin ? ' as an organisation admin' : '') . '.'
                      . ($over ? " That takes {$org['name']} over its limit of {$org['max_users']} active users; its organisation admins can't add anyone until it's back under." : ''));
                break;

            case 'update_email':
                $userId = (int)($_POST['user_id'] ?? 0);
                $email  = trim((string)($_POST['email'] ?? ''));
                $user   = UserRepository::getUser($userId);
                if (!$user) {
                    throw new \RuntimeException('That account no longer exists.');
                }
                if (($emailError = Helpers::emailError($email)) !== null) {
                    throw new \RuntimeException($emailError);
                }
                if ($email === $user['email']) {
                    Helpers::setFlash("No change - {$user['username']}'s email is already {$email}.");
                    break;
                }
                UserRepository::updateEmail($userId, $email);
                AuditLog::record('admin.user_email_changed', $auditTarget($userId) + ['details' => [
                    'before' => $user['email'], 'after' => $email,
                ]]);

                if (empty($_POST['send_link'])) {
                    Helpers::setFlash("Email for '{$user['username']}' changed to {$email}.");
                    break;
                }
                // An account that has never signed in is still waiting on its
                // setup email (typically why the address is being corrected),
                // so it gets the 7-day setup link; otherwise a 1-hour reset.
                $purpose = $user['last_login_at'] === null
                    ? PasswordResetRepository::PURPOSE_SETUP
                    : PasswordResetRepository::PURPOSE_RESET;
                if (sendPasswordLink($userId, $email, $user['username'], $purpose)) {
                    AuditLog::record('admin.password_reset_sent', $auditTarget($userId) + ['details' => ['email' => $email]]);
                    Helpers::setFlash(
                        "Email for '{$user['username']}' changed to {$email}, and a "
                        . ($purpose === PasswordResetRepository::PURPOSE_SETUP ? 'password setup' : 'password reset')
                        . ' link has been sent to it.'
                    );
                } else {
                    Helpers::setFlash(
                        "Email for '{$user['username']}' changed to {$email}, but the password link could not be sent - "
                        . "check the server error log, then use \"Email reset link\" to retry.",
                        'error'
                    );
                }
                break;

            case 'toggle_admin':
                $userId = (int)($_POST['user_id'] ?? 0);
                if ($userId === $currentUserId) {
                    throw new \RuntimeException("You can't change your own admin status.");
                }
                $user = UserRepository::getUser($userId);
                if ($user) {
                    UserRepository::setAdmin($userId, !$user['is_admin']);
                    AuditLog::record('admin.user_admin_changed', $auditTarget($userId) + ['details' => ['admin' => !$user['is_admin']]]);
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
                    $canNow = !UserRepository::getCanUninstall($userId);
                    UserRepository::setCanUninstall($userId, $canNow);
                    AuditLog::record('admin.user_uninstall_changed', $auditTarget($userId) + ['details' => ['can_uninstall' => $canNow]]);
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
                    AuditLog::record('admin.user_active_changed', $auditTarget($userId) + ['details' => ['active' => !$user['is_active']]]);
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
                AuditLog::record('admin.user_password_set', $auditTarget($userId));
                Helpers::setFlash('Password reset.');
                break;

            case 'send_password_reset':
                $userId = (int)($_POST['user_id'] ?? 0);
                $user = UserRepository::getUser($userId);
                if (!$user) {
                    throw new \RuntimeException('That account no longer exists.');
                }
                if (sendPasswordLink($userId, $user['email'], $user['username'], PasswordResetRepository::PURPOSE_RESET)) {
                    AuditLog::record('admin.password_reset_sent', $auditTarget($userId) + ['details' => ['email' => $user['email']]]);
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
                $target = $auditTarget($userId);
                UserRepository::deleteUser($userId);
                AuditLog::record('admin.user_deleted', $target);
                Helpers::setFlash('Account deleted.');
                break;

            case 'reset_mfa':
                $userId = (int)($_POST['user_id'] ?? 0);
                MfaService::disable($userId);
                AuditLog::record('admin.mfa_reset', $auditTarget($userId));
                Helpers::setFlash('Two-factor authentication has been reset for this account - they will need to set it up again. Any trusted devices were revoked at the same time.');
                break;

            case 'revoke_trusted_device':
                $userId = (int)($_POST['user_id'] ?? 0);
                $deviceId = (int)($_POST['device_id'] ?? 0);
                if (TrustedDeviceRepository::revoke($deviceId, $userId, $currentUserId)) {
                    AuditLog::record('admin.trusted_device_revoked', $auditTarget($userId) + ['details' => ['device_id' => $deviceId]]);
                    Helpers::setFlash('Device trust revoked.');
                } else {
                    throw new \RuntimeException('That device was not found - it may already be revoked.');
                }
                break;

            case 'revoke_all_trusted_devices':
                $userId = (int)($_POST['user_id'] ?? 0);
                TrustedDeviceRepository::revokeAllForUser($userId, $currentUserId);
                AuditLog::record('admin.trusted_devices_revoked', $auditTarget($userId));
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
                $newTagId = UserRepository::createTag($qualysTagId !== '' ? $qualysTagId : null, $name);
                AuditLog::record('admin.tag_created', [
                    'target_type' => 'tag', 'target_id' => $newTagId, 'target_label' => $name,
                    'details' => ['qualys_tag_id' => $qualysTagId !== '' ? $qualysTagId : 'pending'],
                ]);
                Helpers::setFlash(
                    $qualysTagId !== ''
                        ? "Tag '{$name}' created."
                        : "Pending tag '{$name}' created. Assign it to an account now if you like - it'll "
                          . "start showing data automatically once an agent carrying a tag named "
                          . "\"{$name}\" first reports in."
                );
                break;

            case 'set_activation_id':
                // Blank clears it, which removes the tag from the Assets
                // page's "Install agent" overlay.
                $tagId = (int)($_POST['tag_id'] ?? 0);
                $raw = trim((string)($_POST['agent_activation_id'] ?? ''));
                $activationId = AgentInstall::normaliseActivationId($raw);
                if ($raw !== '' && $activationId === null) {
                    throw new \RuntimeException('That is not a valid activation ID - it should look like 0888d22d-c088-4e0e-85c3-e4f60f3f3582.');
                }
                if (UserRepository::getTagsByIds([$tagId]) === []) {
                    throw new \RuntimeException('That tag no longer exists.');
                }
                $tagName = $tagNamesFor([$tagId])[0];
                UserRepository::setAgentActivationId($tagId, $activationId);
                AuditLog::record('admin.tag_activation_id', [
                    'target_type' => 'tag', 'target_id' => $tagId, 'target_label' => $tagName,
                    'details' => ['activation_id' => $activationId],
                ]);
                Helpers::setFlash($activationId === null
                    ? "Activation ID cleared for '{$tagName}'."
                    : "Activation ID for '{$tagName}' saved - accounts with this tag can now get the install command from the Assets page.");
                break;

            case 'delete_tag':
                $tagId = (int)($_POST['tag_id'] ?? 0);
                $tagName = $tagNamesFor([$tagId])[0];
                UserRepository::deleteTag($tagId);
                AuditLog::record('admin.tag_deleted', ['target_type' => 'tag', 'target_id' => $tagId, 'target_label' => $tagName]);
                Helpers::setFlash('Tag deleted.');
                break;

            default:
                throw new \RuntimeException('Unknown action.');
        }
    } catch (\RuntimeException $e) {
        Helpers::setFlash($e->getMessage(), 'error');
    }

    header('Location: ' . $usersUrl);
    exit;
}

$userFilter = userListFilter($_GET);
$filterTag = isset($userFilter['tag'])
    ? ($userFilter['tag'] === UserRepository::TAG_FILTER_NONE ? UserRepository::TAG_FILTER_NONE : (int)$userFilter['tag'])
    : null;
$userSort = $userFilter['sort'] ?? 'username';
$userDir  = $userFilter['dir'] ?? 'asc';
$filterOrg = isset($userFilter['org'])
    ? ($userFilter['org'] === UserRepository::TAG_FILTER_NONE ? UserRepository::TAG_FILTER_NONE : (int)$userFilter['org'])
    : null;
$users = UserRepository::listUsers($userFilter['q'] ?? null, $filterTag, $userSort, $userDir, $filterOrg);
$isFiltered = isset($userFilter['q']) || isset($userFilter['tag']) || isset($userFilter['org']);
$organisations = OrganisationRepository::listAll();
$importResult = $_SESSION['import_result'] ?? null;
unset($_SESSION['import_result']);
$totalUsers = $isFiltered ? UserRepository::countUsers() : count($users);
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
// The Users table has eight columns - give it the room so it doesn't scroll.
$wideLayout = true;
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
                <input type="email" name="email" required pattern="<?= Helpers::e(Helpers::EMAIL_INPUT_PATTERN) ?>" title="A full email address, e.g. name@company.co.uk">
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

        <?php if ($organisations !== []): ?>
        <div class="inline-form-row" style="margin: 0 0 0.75rem; align-items: flex-end;">
            <label class="field">
                <span>Organisation <span class="checkbox-hint">(ignored for admin accounts)</span></span>
                <select name="organisation_id">
                    <option value="">None</option>
                    <?php foreach ($organisations as $o): ?>
                    <option value="<?= $o['id'] ?>"><?= Helpers::e($o['name']) ?><?= $o['is_active'] ? '' : ' (suspended)' ?></option>
                    <?php endforeach; ?>
                </select>
            </label>
            <label class="checkbox-field">
                <input type="checkbox" name="is_org_admin" value="1">
                <span>Organisation admin <span class="checkbox-hint">(may add and deactivate its users)</span></span>
            </label>
        </div>
        <?php endif; ?>

        <p class="page-subtitle" style="margin: 0 0 0.25rem;">Extra tags <span class="checkbox-hint">(on top of the organisation's; ignored for admin accounts)</span>:</p>
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
    <details<?= $importResult !== null ? ' open' : '' ?>>
        <summary><h2 style="display: inline;">Import from CSV</h2> <span class="checkbox-hint">add many client accounts at once</span></summary>

        <?php if ($importResult !== null): ?>
        <div style="margin: 0.75rem 0;">
            <?php if (!empty($importResult['errors'])): ?>
            <p class="form-error" style="margin-bottom: 0.5rem;">Nothing was imported. Problems found:</p>
            <ul class="import-problems"><?php foreach ($importResult['errors'] as $e): ?><li><?= Helpers::e($e) ?></li><?php endforeach; ?></ul>
            <?php else: ?>
            <p>Created <?= count($importResult['created']) ?> account(s)<?= $importResult['created'] !== [] ? ': ' . Helpers::e(implode(', ', $importResult['created'])) : '' ?>.</p>
            <?php foreach (array_merge($importResult['warnings'] ?? [], $importResult['failed'] ?? []) as $w): ?><p class="checkbox-hint"><?= Helpers::e($w) ?></p><?php endforeach; ?>
            <?php if (!empty($importResult['email_failed'])): ?>
            <p class="form-error">Setup email failed for: <?= Helpers::e(implode(', ', $importResult['email_failed'])) ?> - check the server error log, then use "Email reset link" on each.</p>
            <?php endif; ?>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <p class="checkbox-hint" style="margin: 0.75rem 0 0.4rem;">
            First row must be a header. <strong>username</strong> and <strong>email</strong> are required; <strong>organisation</strong> (an existing organisation's name),
            <strong>tags</strong> (extra tag names separated by <code>;</code>) and <strong>org_admin</strong> (yes/no) are optional.
            Every row is checked first - if any has a problem, nothing is created. Imported accounts are clients, never admins. Up to <?= UserImport::MAX_ROWS ?> rows.
        </p>
        <pre class="import-example">username,email,organisation,tags,org_admin
jsmith,jane.smith@wavehill.co.uk,Wavehill Ltd,,yes
bjones,bob.jones@wavehill.co.uk,Wavehill Ltd,Wavehill-DMZ,no</pre>
        <form method="post" enctype="multipart/form-data" class="inline-form-row" style="align-items: center;">
            <input type="hidden" name="action" value="import_csv">
            <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
            <input type="file" name="csv" accept=".csv,text/csv" required>
            <label class="checkbox-field">
                <input type="checkbox" name="send_emails" value="1" checked>
                <span>Email each a password setup link <span class="checkbox-hint">(untick to send later)</span></span>
            </label>
            <button type="submit" class="btn btn-primary">Import</button>
        </form>
    </details>
</div>

<div class="panel" id="users">
    <h2>Users <span class="checkbox-hint"><?= $isFiltered ? count($users) . ' of ' . $totalUsers . ' shown' : $totalUsers . ' total' ?></span></h2>

    <form method="get" action="/admin/users#users" class="filter-bar user-filter-bar">
        <label class="field field-inline">
            <span>Search</span>
            <span class="search-input-wrap">
                <input type="text" name="q" class="search-debounce-input" value="<?= Helpers::e($userFilter['q'] ?? '') ?>" placeholder="Username or email…" autocomplete="off">
                <button type="button" class="search-clear" aria-label="Clear search" title="Clear search" <?= empty($userFilter['q']) ? 'hidden' : '' ?>>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                </button>
            </span>
        </label>
        <label class="field field-inline">
            <span>Tag</span>
            <select name="tag" onchange="this.form.submit();">
                <option value="">Any tag</option>
                <option value="<?= UserRepository::TAG_FILTER_NONE ?>" <?= $filterTag === UserRepository::TAG_FILTER_NONE ? 'selected' : '' ?>>No tags</option>
                <?php foreach ($tags as $tag): ?>
                <option value="<?= (int)$tag['id'] ?>" <?= $filterTag === (int)$tag['id'] ? 'selected' : '' ?>><?= Helpers::e($tag['name']) ?></option>
                <?php endforeach; ?>
            </select>
        </label>
        <label class="field field-inline">
            <span>Organisation</span>
            <select name="org" onchange="this.form.submit();">
                <option value="">Any</option>
                <option value="<?= UserRepository::TAG_FILTER_NONE ?>" <?= $filterOrg === UserRepository::TAG_FILTER_NONE ? 'selected' : '' ?>>No organisation</option>
                <?php foreach ($organisations as $o): ?>
                <option value="<?= $o['id'] ?>" <?= $filterOrg === $o['id'] ? 'selected' : '' ?>><?= Helpers::e($o['name']) ?></option>
                <?php endforeach; ?>
            </select>
        </label>
        <?php if (isset($userFilter['sort'])): ?>
        <input type="hidden" name="sort" value="<?= Helpers::e($userSort) ?>">
        <input type="hidden" name="dir" value="<?= Helpers::e($userDir) ?>">
        <?php endif; ?>
        <?php if ($isFiltered): ?>
        <a class="btn btn-secondary btn-sm" href="<?= Helpers::e('/admin/users' . (isset($userFilter['sort']) ? '?' . http_build_query(['sort' => $userSort, 'dir' => $userDir]) : '') . '#users') ?>">Clear filters</a>
        <?php endif; ?>
        <noscript><button type="submit" class="btn btn-secondary">Apply</button></noscript>
    </form>

    <div class="table-wrap">
    <table class="vuln-table admin-table">
        <thead>
            <tr>
                <th><?= Helpers::sortLink('Username', 'username', $userSort, $userDir, '#users') ?></th>
                <th><?= Helpers::sortLink('Email', 'email', $userSort, $userDir, '#users') ?></th>
                <th><?= Helpers::sortLink('Role', 'role', $userSort, $userDir, '#users') ?></th>
                <th><?= Helpers::sortLink('Organisation', 'organisation', $userSort, $userDir, '#users') ?></th>
                <th><?= Helpers::sortLink('Extra tags', 'tags', $userSort, $userDir, '#users') ?></th>
                <th><?= Helpers::sortLink('MFA', 'mfa', $userSort, $userDir, '#users') ?></th>
                <th><?= Helpers::sortLink('Last login', 'last_login', $userSort, $userDir, '#users') ?></th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php if (empty($users)): ?>
            <tr class="empty-row"><td colspan="8"><?= $isFiltered ? 'No users match these filters.' : 'No users yet.' ?></td></tr>
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
                <td class="nowrap">
                    <?php if ($u['organisation_name'] !== null): ?>
                    <?= Helpers::e($u['organisation_name']) ?>
                    <?php if ((int)$u['organisation_active'] !== 1): ?><span class="badge badge-danger">Suspended</span><?php endif; ?>
                    <?php if ((int)$u['is_org_admin'] === 1): ?><div class="checkbox-hint">org admin</div><?php endif; ?>
                    <?php else: ?><span class="no-tags">—</span><?php endif; ?>
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
                    <?php elseif ($u['organisation_name'] !== null): ?>
                    <span class="no-tags">organisation's only</span>
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
                        <button type="button" class="btn btn-sm btn-secondary manage-toggle" data-manage-toggle aria-expanded="false" aria-controls="manage-<?= (int)$u['id'] ?>">Manage <span class="manage-caret" aria-hidden="true">&#9662;</span></button>
                    </div>
                </td>
            </tr>
            <tr class="user-manage-row" id="manage-<?= (int)$u['id'] ?>" hidden>
                <td colspan="8">
                    <div class="user-manage">
                        <div class="user-manage-group user-manage-group-wide">
                            <h3>Email</h3>
                            <form method="post" class="user-manage-email">
                                <input type="hidden" name="action" value="update_email">
                                <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                                <div class="user-manage-inline">
                                    <input type="email" name="email" value="<?= Helpers::e($u['email']) ?>" required
                                        pattern="<?= Helpers::e(Helpers::EMAIL_INPUT_PATTERN) ?>" title="A full email address, e.g. name@company.co.uk"
                                        aria-label="Email address for <?= Helpers::e($u['username']) ?>">
                                    <button type="submit" class="btn btn-sm btn-secondary">Save email</button>
                                </div>
                                <label class="checkbox-field">
                                    <input type="checkbox" name="send_link" value="1"<?= $u['last_login_at'] === null ? ' checked' : '' ?>>
                                    <span>Email a password link to the new address <span class="checkbox-hint">(<?= $u['last_login_at'] === null ? 'setup link, 7 days - not signed in yet' : 'reset link, 1 hour' ?>)</span></span>
                                </label>
                            </form>
                        </div>

                        <?php if ((int)$u['id'] !== $currentUserId): ?>
                        <?php if (!$u['is_admin'] && $organisations !== []): ?>
                        <div class="user-manage-group">
                            <h3>Organisation</h3>
                            <form method="post" class="user-manage-stack">
                                <input type="hidden" name="action" value="set_organisation">
                                <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                                <select name="organisation_id" aria-label="Organisation for <?= Helpers::e($u['username']) ?>">
                                    <option value="">None</option>
                                    <?php foreach ($organisations as $o): ?>
                                    <option value="<?= $o['id'] ?>" <?= (int)$u['organisation_id'] === $o['id'] ? 'selected' : '' ?>><?= Helpers::e($o['name']) ?></option>
                                    <?php endforeach; ?>
                                </select>
                                <div class="user-manage-inline">
                                    <label class="checkbox-field">
                                        <input type="checkbox" name="is_org_admin" value="1" <?= (int)$u['is_org_admin'] === 1 ? 'checked' : '' ?>>
                                        <span>Organisation admin</span>
                                    </label>
                                    <button type="submit" class="btn btn-sm btn-secondary">Save</button>
                                </div>
                            </form>
                        </div>
                        <?php endif; ?>

                        <div class="user-manage-group">
                            <h3>Access</h3>
                            <div class="actions-cell">
                                <?php if (!$u['is_admin']): ?>
                                <a class="btn btn-sm btn-secondary" href="/admin/users?edit=<?= (int)$u['id'] ?>">Edit extra tags</a>
                                <?php endif; ?>
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
                            <form method="post" class="user-manage-inline">
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
                        <div class="user-manage-group user-manage-group-danger">
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
    <p class="page-subtitle" style="margin-bottom: 0.75rem;">
        Set a tag's <strong>agent activation ID</strong> and every account with that tag gets an
        "Install agent" button on the Assets page, showing the Windows and macOS/Linux install
        commands with the ID filled in. Leave it blank to offer no install command for the tag.
    </p>

    <?php if (!empty($tags)): ?>
    <div class="table-wrap" style="margin-bottom: 1.25rem;">
        <table class="vuln-table admin-table">
            <thead><tr><th>Name</th><th>Qualys identifier</th><th>Agent activation ID</th><th>Users</th><th>Assets</th><th>Actions</th></tr></thead>
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
                    <td>
                        <form method="post" class="activation-id-form">
                            <input type="hidden" name="action" value="set_activation_id">
                            <input type="hidden" name="tag_id" value="<?= (int)$tag['id'] ?>">
                            <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                            <input type="text" name="agent_activation_id" class="mono" value="<?= Helpers::e($tag['agent_activation_id'] ?? '') ?>"
                                placeholder="none" maxlength="64" spellcheck="false" autocomplete="off"
                                aria-label="Agent activation ID for <?= Helpers::e($tag['name']) ?>">
                            <button type="submit" class="btn btn-sm btn-secondary">Save</button>
                        </form>
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
