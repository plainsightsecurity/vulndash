<?php
declare(strict_types=1);

require_once __DIR__ . '/../../src/bootstrap.php';
require_once __DIR__ . '/../../src/views/access_until.php';
require_once __DIR__ . '/../../scripts/lib/QualysApiClient.php';

use VulnDash\Lib\AgentProvisioner;
use VulnDash\Lib\AgentTagExistsException;
use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\AuditLog;
use VulnDash\Lib\Auth;
use VulnDash\Lib\Config;
use VulnDash\Lib\Helpers;
use VulnDash\Scripts\QualysApiClient;

/**
 * Agent Setup (admin) - creates each client organisation's Qualys tag and
 * activation key and wires them into VulnDash. See src/Lib/AgentProvisioner.php.
 *
 * Unlike scans and uninstalls, which queue for a cron worker, this calls
 * Qualys during the request: an admin is waiting on the answer, and a
 * duplicate tag needs their decision before anything else happens. The
 * client fails fast on a rate-limit wait instead of sleeping (see
 * QualysApiClient::setMaxRateLimitWaitSec()), and every call is logged for
 * the API Usage page like any other.
 */
Auth::requireAdmin();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
        Helpers::setFlash('Your session expired - please try that again.', 'error');
        header('Location: /admin/agent_setup');
        exit;
    }
    $action = (string)($_POST['action'] ?? '');
    $provId = (int)($_POST['provisioning_id'] ?? 0);
    $client = null;
    $setup = null;
    $before = $provId > 0 ? AgentProvisioner::get($provId) : null;

    $newClient = static function () use (&$client): AgentProvisioner {
        $client = new QualysApiClient(
            (string)Config::get('qualys.api_base_url'),
            (string)Config::get('qualys.username'),
            (string)Config::get('qualys.password'),
            (string)(Config::get('qualys.api_version') ?? '4.0')
        );
        $client->setMaxRateLimitWaitSec(0);
        @set_time_limit(180);
        return new AgentProvisioner($client);
    };

    try {
        switch ($action) {
            case 'start':
                $orgId = (int)($_POST['organisation_id'] ?? 0);
                $tagName = trim((string)($_POST['tag_name'] ?? ''));
                // Validated before any Qualys call, so a bad name costs nothing.
                if (($error = AgentProvisioner::tagNameError($tagName)) !== null) {
                    throw new \RuntimeException($error);
                }
                AgentProvisioner::modules();
                $setup = $newClient()->start($orgId, $tagName, isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null);
                break;

            case 'retry':
                $before ?? throw new \RuntimeException('That set-up no longer exists.');
                $setup = $newClient()->resume($provId);
                break;

            case 'use_existing':
                $before ?? throw new \RuntimeException('That set-up no longer exists.');
                $setup = $newClient()->resume($provId, (int)($_POST['qualys_tag_id'] ?? 0));
                break;

            case 'link':
                $orgId = (int)($_POST['organisation_id'] ?? 0);
                $setup = $newClient()->linkExisting($orgId, (int)($_POST['tag_id'] ?? 0), isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null);
                break;

            case 'unlink':
                $row = AgentProvisioner::unlink($provId);
                unset($_SESSION['agent_setup_existing'][$provId]);
                AuditLog::record('admin.agent_setup_unlinked', [
                    'target_type' => 'organisation', 'target_id' => $row['organisation_id'], 'target_label' => $row['tag_name'],
                    'details' => ['qualys_tag_id' => $row['qualys_tag_id'], 'activation_key_id' => $row['activation_key_id']],
                ]);
                Helpers::setFlash("Set-up for {$row['tag_name']} unlinked. Nothing changed in Qualys"
                    . ($row['local_tag_id'] !== null ? ', and the organisation keeps its tag and Install agent button' : '') . '.');
                break;

            case 'delete':
                $before ?? throw new \RuntimeException('That set-up no longer exists.');
                $newClient()->deleteSetup($provId, (string)($_POST['confirm_tag_name'] ?? ''));
                unset($_SESSION['agent_setup_existing'][$provId]);
                AuditLog::record('admin.agent_setup_deleted', [
                    'target_type' => 'organisation', 'target_id' => $before['organisation_id'], 'target_label' => $before['tag_name'],
                    'details' => ['qualys_tag_id' => $before['qualys_tag_id'], 'activation_key_id' => $before['activation_key_id'],
                                  'activation_key' => $before['activation_key'], 'origin' => $before['origin']],
                ]);
                Helpers::setFlash("Set-up for {$before['tag_name']} deleted: its activation key and tag are gone from Qualys and from VulnDash. "
                    . 'The organisation is still there and the name can be used again.');
                break;

            default:
                throw new \RuntimeException('Unknown action.');
        }

        if ($setup !== null) {
            unset($_SESSION['agent_setup_existing'][$setup['id']]);
            AuditLog::record($action === 'link' ? 'admin.agent_setup_linked' : 'admin.agent_setup', [
                'target_type' => 'organisation', 'target_id' => $setup['organisation_id'], 'target_label' => $setup['tag_name'],
                'details' => [
                    'qualys_tag_id'     => $setup['qualys_tag_id'],
                    'activation_key_id' => $setup['activation_key_id'],
                    'activation_key'    => $setup['activation_key'],
                    'used_existing_tag' => $action === 'use_existing',
                ],
            ]);
            Helpers::setFlash($action === 'link'
                ? "{$setup['tag_name']} linked: Qualys tag {$setup['qualys_tag_id']}, activation key {$setup['activation_key_id']}. Nothing was created or changed."
                : "{$setup['tag_name']} is set up: Qualys tag {$setup['qualys_tag_id']}, activation key {$setup['activation_key_id']}. "
                  . "The organisation's members now get the Install agent button on the Assets page.");
        }
    } catch (AgentTagExistsException $e) {
        // Kept for the page to offer as "use this tag" buttons - only the
        // fields it shows, and only until the set-up moves on.
        $_SESSION['agent_setup_existing'][$e->provisioningId] = array_map(
            static fn (array $t): array => ['name' => (string)$t['name'], 'static' => $t['ruleType'] === null && $t['srcAssetGroupId'] === null],
            $e->matches
        );
        Helpers::setFlash($e->getMessage(), 'error');
    } catch (\RuntimeException $e) {
        Helpers::setFlash($e->getMessage(), 'error');
    } finally {
        if ($client !== null) {
            try {
                ApiCallLogRepository::recordCalls($client->getCallLog());
            } catch (\Throwable $logError) {
                error_log('Agent setup: failed to persist API call log: ' . $logError->getMessage());
            }
        }
    }
    header('Location: /admin/agent_setup');
    exit;
}

$orgs = AgentProvisioner::listForAdmin();
$existingChoices = (array)($_SESSION['agent_setup_existing'] ?? []);
try {
    $modules = implode(', ', AgentProvisioner::modules());
    $modulesError = null;
} catch (\RuntimeException $e) {
    $modules = '';
    $modulesError = $e->getMessage();
}
$csrfToken = Helpers::csrfToken();
$flash = Helpers::getFlash();

/** A one-button form posting $action for a set-up, with an optional confirm prompt. */
$button = static function (string $action, int $provId, string $label, string $class, ?string $confirm = null, array $extra = []) use ($csrfToken): void {
    ?>
    <form method="post"<?= $confirm !== null ? ' onsubmit="return confirm(' . Helpers::jsAttr($confirm) . ');"' : '' ?>>
        <input type="hidden" name="action" value="<?= Helpers::e($action) ?>">
        <input type="hidden" name="provisioning_id" value="<?= $provId ?>">
        <?php foreach ($extra as $k => $v): ?><input type="hidden" name="<?= Helpers::e($k) ?>" value="<?= Helpers::e((string)$v) ?>"><?php endforeach; ?>
        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
        <button type="submit" class="btn btn-sm <?= $class ?>"><?= Helpers::e($label) ?></button>
    </form>
    <?php
};

/**
 * Delete, behind a disclosure: what it removes, then a box the tag name has
 * to be typed into - checked by AgentProvisioner::deleteSetup() before any
 * Qualys call.
 */
$deleteForm = static function (array $s) use ($csrfToken): void {
    $what = array_filter([
        $s['activation_key_id'] !== null ? "activation key {$s['activation_key_id']}" : null,
        $s['qualys_tag_id'] !== null ? "tag {$s['tag_name']} (id {$s['qualys_tag_id']})" : null,
    ]);
    ?>
    <details class="delete-setup">
        <summary class="btn btn-sm btn-danger">Delete&hellip;</summary>
        <form method="post">
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="provisioning_id" value="<?= $s['id'] ?>">
            <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
            <p class="checkbox-hint">
                Deletes <?= $what !== [] ? Helpers::e(implode(' and ', $what)) . ' in Qualys' : 'nothing in Qualys' ?>, and the tag in VulnDash<?php if ($s['qualys_tag_id'] !== null): ?> - Qualys removes the tag from every asset carrying it<?php endif; ?><?php if ($s['asset_count'] > 0): ?> (<strong><?= $s['asset_count'] ?></strong> here)<?php endif; ?>,
                and this organisation's members lose access to those assets and the Install agent button.
                Qualys won't delete a key that agents are still using. This can't be undone.
            </p>
            <label class="field"><span>Type <strong class="mono"><?= Helpers::e($s['tag_name']) ?></strong> to confirm</span>
                <input type="text" name="confirm_tag_name" class="mono" autocomplete="off" spellcheck="false" required></label>
            <button type="submit" class="btn btn-sm btn-danger">Delete permanently</button>
        </form>
    </details>
    <?php
};

$pageTitle = 'Agent Setup';
require __DIR__ . '/../../src/views/header.php';
?>

<div class="page-heading">
    <h1>Agent Setup</h1>
    <p class="page-subtitle">Create each client's Qualys tag and activation key. Agents installed with the key get the tag, and the organisation's members get the Install agent button with the key filled in.</p>
</div>

<?php if ($flash): ?>
<div class="flash flash-<?= Helpers::e($flash['type']) ?>"><?= Helpers::e($flash['message']) ?></div>
<?php endif; ?>
<?php if ($modulesError !== null): ?>
<div class="flash flash-error"><?= Helpers::e($modulesError) ?></div>
<?php endif; ?>

<div class="panel">
    <h2>Organisations <span class="checkbox-hint"><?= count($orgs) ?> total</span></h2>
    <p class="page-subtitle" style="margin-top: 0;">Tag names can use letters, numbers and hyphens only - no spaces. The suggested name can be changed before you create it. Nothing is created if Qualys already has a tag with that name; you'll be asked what to do. Organisations that already have a tag with an activation ID are linked rather than set up again. <strong>Delete</strong> removes a set-up with its tag and key in Qualys, after you type the tag name; <strong>Unlink</strong> only forgets the record. New keys: unlimited, licensed for <?= Helpers::e($modules !== '' ? $modules : '-') ?>.</p>
    <div class="table-wrap">
    <table class="vuln-table admin-table">
        <thead>
            <tr><th>Organisation</th><th>Tag</th><th>Activation ID</th><th title="Last day client accounts can see this tag's assets - set in the Tags table on Manage Users">Access until</th><th>Status</th></tr>
        </thead>
        <tbody>
            <?php if ($orgs === []): ?>
            <tr class="empty-row"><td colspan="5">No organisations yet - add one on <a href="/admin/organisations">Organisations</a> first.</td></tr>
            <?php else: foreach ($orgs as $org): $s = $org['setup']; ?>
            <tr>
                <td><strong><?= Helpers::e($org['name']) ?></strong></td>
                <?php if ($s === null && $org['linkable'] !== []): ?>
                <td colspan="4">
                    <div class="checkbox-hint">Already has a tag with an activation ID - record it rather than create another:</div>
                    <div class="actions-cell">
                        <?php foreach ($org['linkable'] as $t): ?>
                        <form method="post" onsubmit="return confirm(<?= Helpers::jsAttr("Link {$t['name']} as this organisation's set-up? Qualys is checked (one call) that activation key {$t['activation_id']} applies this tag; nothing is created or changed.") ?>);">
                            <input type="hidden" name="action" value="link">
                            <input type="hidden" name="organisation_id" value="<?= $org['id'] ?>">
                            <input type="hidden" name="tag_id" value="<?= $t['id'] ?>">
                            <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                            <button type="submit" class="btn btn-sm btn-primary">Link existing: <?= Helpers::e($t['name']) ?></button>
                        </form>
                        <?php endforeach; ?>
                    </div>
                    <div class="checkbox-hint mono"><?php foreach ($org['linkable'] as $t): ?><?= Helpers::e($t['name']) ?>: tag <?= Helpers::e($t['qualys_tag_id']) ?>, <?= Helpers::e($t['activation_id']) ?><br><?php endforeach; ?></div>
                </td>
                <?php elseif ($s === null): $suggested = AgentProvisioner::suggestTagName($org['name']); ?>
                <td colspan="4">
                    <?php if ($org['tags'] !== []): ?>
                    <div class="checkbox-hint">Its current tags (<?= Helpers::e(implode(', ', array_column($org['tags'], 'name'))) ?>) have no activation ID, so this adds a new tag alongside them.</div>
                    <?php endif; ?>
                    <form method="post" class="inline-form-row" onsubmit="return confirm('Create this tag and an activation key in Qualys?');">
                        <input type="hidden" name="action" value="start">
                        <input type="hidden" name="organisation_id" value="<?= $org['id'] ?>">
                        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
                        <input type="text" name="tag_name" class="mono" value="<?= Helpers::e($suggested) ?>" maxlength="<?= AgentProvisioner::MAX_NAME_LENGTH ?>"
                               pattern="[A-Za-z0-9\-]+" title="Letters, numbers and hyphens only - no spaces" required
                               aria-label="Tag name for <?= Helpers::e($org['name']) ?>">
                        <button type="submit" class="btn btn-sm btn-primary"<?= $modulesError !== null ? ' disabled' : '' ?>>Create tag and key</button>
                    </form>
                </td>
                <?php else: ?>
                <td class="mono"><?= Helpers::e($s['tag_name']) ?><?php if ($s['qualys_tag_id'] !== null): ?><div class="checkbox-hint">Qualys tag <?= $s['qualys_tag_id'] ?></div><?php endif; ?></td>
                <td class="mono"><?= $s['activation_key'] !== null ? Helpers::e($s['activation_key']) . '<div class="checkbox-hint">Key ' . $s['activation_key_id'] . '</div>' : '-' ?></td>
                <td class="nowrap"><?php render_access_until($s['tag_expires_on'], $s['local_tag_id'] !== null ? 'No end date' : '-'); ?></td>
                <td>
                    <?php if ($s['status'] === 'complete'): ?>
                    <span class="badge badge-active"><?= $s['origin'] === 'linked' ? 'Linked' : 'Set up' ?></span>
                    <div class="checkbox-hint"><?= Helpers::e(Helpers::displayDateTime($s['completed_at'], 'Y-m-d H:i')) ?></div>
                    <?php else: ?>
                    <div class="checkbox-hint">Stopped partway<?= $s['qualys_tag_id'] !== null ? ' - tag ' . $s['qualys_tag_id'] . ($s['origin'] === 'existing_tag' ? ' chosen' : ' created') : '' ?><?= $s['activation_key_id'] !== null ? ', key ' . $s['activation_key_id'] . ' created' : '' ?>.</div>
                    <?php endif; ?>
                    <?php if ($s['last_error'] !== null): ?><div class="checkbox-hint"><?= Helpers::e($s['last_error']) ?></div><?php endif; ?>
                    <div class="actions-cell">
                        <?php if ($s['status'] !== 'complete'):
                            if ($s['qualys_tag_id'] === null) {
                                foreach ((array)($existingChoices[$s['id']] ?? []) as $qid => $t) {
                                    if ($t['static']) {
                                        $button('use_existing', $s['id'], "Use existing tag {$qid}", 'btn-secondary',
                                            "Use the existing Qualys tag {$t['name']} (id {$qid}) for this client? Every agent already carrying it will count as this client's.",
                                            ['qualys_tag_id' => $qid]);
                                    }
                                }
                            }
                            $button('retry', $s['id'], 'Retry', 'btn-primary');
                        endif; ?>
                        <?php $deleteForm($s); ?>
                        <?php if ($s['status'] === 'complete') {
                            $button('unlink', $s['id'], 'Unlink', 'btn-secondary', "Unlink {$s['tag_name']}? Only this page's record is removed: the tag, key and the organisation's Install agent button stay as they are.");
                        } ?>
                    </div>
                </td>
                <?php endif; ?>
            </tr>
            <?php endforeach; endif; ?>
        </tbody>
    </table>
    </div>
</div>

<?php require __DIR__ . '/../../src/views/footer.php'; ?>
