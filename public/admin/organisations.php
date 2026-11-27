<?php
declare(strict_types=1);

require_once __DIR__ . '/../../src/bootstrap.php';
require_once __DIR__ . '/../../src/views/tag_combo.php';

use VulnDash\Lib\AccessExpiry;
use VulnDash\Lib\AuditLog;
use VulnDash\Lib\Auth;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\OrganisationRepository;
use VulnDash\Lib\UserRepository;

/**
 * Client organisations (admin) - see src/Lib/OrganisationRepository.php.
 * Create, edit (name, tags, user limit, access end date), suspend /
 * reactivate and delete.
 * Members are assigned on Manage Users; organisation admins manage their own
 * organisation's accounts on /org/users.
 */
Auth::requireAdmin();

/** "" = no limit; otherwise a whole number 1-10000. */
function parseUserLimit(string $raw): ?int
{
    $raw = trim($raw);
    if ($raw === '') {
        return null;
    }
    if (!ctype_digit($raw) || (int)$raw < 1 || (int)$raw > 10000) {
        throw new \RuntimeException('The user limit must be a whole number from 1 to 10,000, or blank for no limit.');
    }
    return (int)$raw;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
        Helpers::setFlash('Your session expired - please try that again.', 'error');
        header('Location: /admin/organisations');
        exit;
    }
    $action = (string)($_POST['action'] ?? '');
    $orgId  = (int)($_POST['organisation_id'] ?? 0);
    $redirect = '/admin/organisations';

    try {
        $tagIds = array_map('intval', (array)($_POST['tag_ids'] ?? []));
        $target = static function (int $id, string $name): array {
            return ['target_type' => 'organisation', 'target_id' => $id, 'target_label' => $name];
        };
        switch ($action) {
            case 'create':
                $name = trim((string)($_POST['name'] ?? ''));
                if ($name === '' || mb_strlen($name) > 191) {
                    throw new \RuntimeException('Enter an organisation name (up to 191 characters).');
                }
                $limit = parseUserLimit((string)($_POST['max_users'] ?? ''));
                $expires = AccessExpiry::parse((string)($_POST['expires_on'] ?? ''));
                $id = OrganisationRepository::create($name, $tagIds, $limit);
                if ($expires !== null) {
                    OrganisationRepository::setExpiresOn($id, $expires);
                }
                AuditLog::record('admin.org_created', $target($id, $name) + ['details' => ['tags' => $tagIds, 'max_users' => $limit, 'access_until' => $expires]]);
                Helpers::setFlash("Organisation '{$name}' created. Assign people to it on Manage Users.");
                break;

            case 'update':
                $org = OrganisationRepository::get($orgId) ?? throw new \RuntimeException('That organisation no longer exists.');
                $name = trim((string)($_POST['name'] ?? ''));
                if ($name === '' || mb_strlen($name) > 191) {
                    throw new \RuntimeException('Enter an organisation name (up to 191 characters).');
                }
                $limit = parseUserLimit((string)($_POST['max_users'] ?? ''));
                $expires = AccessExpiry::parse((string)($_POST['expires_on'] ?? ''));
                OrganisationRepository::update($orgId, $name, $tagIds, $limit);
                OrganisationRepository::setExpiresOn($orgId, $expires);
                AuditLog::record('admin.org_updated', $target($orgId, $name) + ['details' => [
                    'before' => ['name' => $org['name'], 'tags' => $org['tag_ids'], 'max_users' => $org['max_users'], 'access_until' => $org['expires_on']],
                    'after'  => ['name' => $name, 'tags' => array_values(array_unique($tagIds)), 'max_users' => $limit, 'access_until' => $expires],
                ]]);
                Helpers::setFlash("Organisation '{$name}' updated."
                    . ($limit !== null && $org['active_users'] > $limit ? " It has {$org['active_users']} active users - over the new limit of {$limit}, so its organisation admins can't add or reactivate anyone until it's back under." : '')
                    . ($expires !== $org['expires_on'] && AccessExpiry::isExpired($expires) ? " Its access end date has passed, so its members are signed out and can't sign in." : '')
                    . ($expires !== $org['expires_on'] && AccessExpiry::isExpired($org['expires_on']) && !AccessExpiry::isExpired($expires) ? ' Its members can sign in again.' : ''));
                break;

            case 'toggle_active':
                $org = OrganisationRepository::get($orgId) ?? throw new \RuntimeException('That organisation no longer exists.');
                OrganisationRepository::setActive($orgId, !$org['is_active']);
                AuditLog::record($org['is_active'] ? 'admin.org_suspended' : 'admin.org_reactivated', $target($orgId, $org['name']));
                Helpers::setFlash($org['is_active']
                    ? "Organisation '{$org['name']}' suspended - its members are signed out and can't sign in until it's reactivated."
                    : "Organisation '{$org['name']}' reactivated.");
                break;

            case 'delete':
                $org = OrganisationRepository::get($orgId) ?? throw new \RuntimeException('That organisation no longer exists.');
                OrganisationRepository::delete($orgId);
                AuditLog::record('admin.org_deleted', $target($orgId, $org['name']) + ['details' => ['members' => $org['total_users']]]);
                Helpers::setFlash("Organisation '{$org['name']}' deleted. Its {$org['total_users']} account(s) remain, with only their own extra tags.");
                break;

            default:
                throw new \RuntimeException('Unknown action.');
        }
    } catch (\RuntimeException $e) {
        Helpers::setFlash($e->getMessage(), 'error');
        if ($action === 'update' && $orgId > 0) {
            $redirect .= '?edit=' . $orgId;
        }
    }
    header('Location: ' . $redirect);
    exit;
}

$orgs = OrganisationRepository::listAll();
$tags = UserRepository::listTags();
$editOrg = isset($_GET['edit']) ? OrganisationRepository::get((int)$_GET['edit']) : null;
$csrfToken = Helpers::csrfToken();
$flash = Helpers::getFlash();

$pageTitle = 'Organisations';
require __DIR__ . '/../../src/views/header.php';
?>

<div class="page-heading">
    <h1>Organisations</h1>
    <p class="page-subtitle">Group each client's accounts and the tags they all see. Members see their organisation's tags plus any extra tags set on them individually.</p>
</div>

<?php if ($flash): ?>
<div class="flash flash-<?= Helpers::e($flash['type']) ?>"><?= Helpers::e($flash['message']) ?></div>
<?php endif; ?>

<?php if ($editOrg): ?>
<div class="panel edit-panel">
    <h2>Edit <?= Helpers::e($editOrg['name']) ?></h2>
    <form method="post">
        <input type="hidden" name="action" value="update">
        <input type="hidden" name="organisation_id" value="<?= $editOrg['id'] ?>">
        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
        <div class="inline-form-row">
            <label class="field"><span>Name</span><input type="text" name="name" value="<?= Helpers::e($editOrg['name']) ?>" maxlength="191" required></label>
            <label class="field"><span>User limit <span class="checkbox-hint">(active accounts; blank = none)</span></span>
                <input type="number" name="max_users" min="1" max="10000" value="<?= $editOrg['max_users'] ?? '' ?>"></label>
            <label class="field"><span>Access until <span class="checkbox-hint">(last day members can sign in; blank = no end)</span></span>
                <input type="date" name="expires_on" value="<?= Helpers::e((string)($editOrg['expires_on'] ?? '')) ?>"></label>
        </div>
        <p class="page-subtitle" style="margin: 0.75rem 0 0.25rem;">Tags every member sees:</p>
        <div class="tag-combo-row"><?php render_tag_combo($tags, 'Tags', $editOrg['tag_ids']); ?></div>
        <button type="submit" class="btn btn-primary btn-sm">Save</button>
        <a class="btn btn-secondary btn-sm" href="/admin/organisations">Cancel</a>
    </form>
</div>
<?php endif; ?>

<div class="panel">
    <h2>Add an organisation</h2>
    <form method="post">
        <input type="hidden" name="action" value="create">
        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
        <div class="inline-form-row">
            <label class="field"><span>Name</span><input type="text" name="name" maxlength="191" placeholder="e.g. Wavehill Ltd" required></label>
            <label class="field"><span>User limit <span class="checkbox-hint">(active accounts; blank = none)</span></span>
                <input type="number" name="max_users" min="1" max="10000" placeholder="e.g. 10"></label>
            <label class="field"><span>Access until <span class="checkbox-hint">(e.g. the CE+ expiry; blank = no end)</span></span>
                <input type="date" name="expires_on"></label>
        </div>
        <p class="page-subtitle" style="margin: 0.75rem 0 0.25rem;">Tags every member sees:</p>
        <div class="tag-combo-row"><?php render_tag_combo($tags, 'Tags', []); ?></div>
        <button type="submit" class="btn btn-primary">Create organisation</button>
    </form>
</div>

<div class="panel">
    <h2>Organisations <span class="checkbox-hint"><?= count($orgs) ?> total</span></h2>
    <div class="table-wrap">
    <table class="vuln-table admin-table">
        <thead>
            <tr><th>Name</th><th>Tags</th><th>Active users</th><th>Org admins</th><th>Status</th><th>Actions</th></tr>
        </thead>
        <tbody>
            <?php if ($orgs === []): ?>
            <tr class="empty-row"><td colspan="6">No organisations yet.</td></tr>
            <?php else: foreach ($orgs as $org):
                $confirmDelete = "Delete organisation \"{$org['name']}\"? Its {$org['total_users']} account(s) stay, but lose its tags and keep only their own extra tags. This cannot be undone.";
                $confirmToggle = $org['is_active']
                    ? "Suspend \"{$org['name']}\"? All {$org['total_users']} of its members will be signed out and unable to sign in until you reactivate it."
                    : "Reactivate \"{$org['name']}\"?";
            ?>
            <tr>
                <td><strong><?= Helpers::e($org['name']) ?></strong></td>
                <td>
                    <?php if ($org['tag_names'] !== ''): ?>
                    <div class="tag-chip-list"><?php foreach (explode(', ', $org['tag_names']) as $t): ?><span class="tag-chip"><?= Helpers::e($t) ?></span><?php endforeach; ?></div>
                    <?php else: ?><span class="no-tags">none - members see only their own extra tags</span><?php endif; ?>
                </td>
                <td class="mono">
                    <?= $org['active_users'] ?><?= $org['max_users'] !== null ? ' of ' . $org['max_users'] : '' ?>
                    <?php if ($org['max_users'] !== null && $org['active_users'] >= $org['max_users']): ?><span class="badge badge-warn">full</span><?php endif; ?>
                    <?php if ($org['total_users'] > $org['active_users']): ?><div class="checkbox-hint">+<?= $org['total_users'] - $org['active_users'] ?> deactivated</div><?php endif; ?>
                </td>
                <td class="mono"><?= $org['org_admins'] ?></td>
                <td class="nowrap">
                    <?php if (!$org['is_active']): ?><span class="badge badge-danger">Suspended</span>
                    <?php elseif (AccessExpiry::isExpired($org['expires_on'])): ?><span class="badge badge-danger">Expired</span>
                    <?php else: ?><span class="badge badge-active">Active</span><?php endif; ?>
                    <?php if ($org['expires_on'] !== null): ?>
                    <div class="checkbox-hint"><?= AccessExpiry::isExpired($org['expires_on']) ? 'ended' : 'until' ?> <?= Helpers::e(AccessExpiry::display($org['expires_on'])) ?><?= AccessExpiry::isEnding($org['expires_on']) ? ' <span class="badge badge-warn">' . AccessExpiry::daysLeft($org['expires_on']) . 'd left</span>' : '' ?></div>
                    <?php endif; ?>
                </td>
                <td>
                    <div class="actions-cell">
                        <a class="btn btn-sm btn-secondary" href="/admin/organisations?edit=<?= $org['id'] ?>">Edit</a>
                        <a class="btn btn-sm btn-secondary" href="/admin/users?org=<?= $org['id'] ?>#users">Members</a>
                        <form method="post" onsubmit="return confirm(<?= Helpers::jsAttr($confirmToggle) ?>);">
                            <input type="hidden" name="action" value="toggle_active">
                            <input type="hidden" name="organisation_id" value="<?= $org['id'] ?>">
                            <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                            <button type="submit" class="btn btn-sm btn-secondary"><?= $org['is_active'] ? 'Suspend' : 'Reactivate' ?></button>
                        </form>
                        <form method="post" onsubmit="return confirm(<?= Helpers::jsAttr($confirmDelete) ?>);">
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="organisation_id" value="<?= $org['id'] ?>">
                            <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                            <button type="submit" class="btn btn-sm btn-danger">Delete</button>
                        </form>
                    </div>
                </td>
            </tr>
            <?php endforeach; endif; ?>
        </tbody>
    </table>
    </div>
</div>

<?php require __DIR__ . '/../../src/views/footer.php'; ?>
