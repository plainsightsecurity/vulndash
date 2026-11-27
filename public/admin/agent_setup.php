<?php
declare(strict_types=1);

require_once __DIR__ . '/../../src/bootstrap.php';
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

            case 'cancel':
                $row = AgentProvisioner::cancel($provId);
                unset($_SESSION['agent_setup_existing'][$provId]);
                AuditLog::record('admin.agent_setup_cancelled', [
                    'target_type' => 'organisation', 'target_id' => $row['organisation_id'], 'target_label' => $row['tag_name'],
                    'details' => ['qualys_tag_id' => $row['qualys_tag_id'], 'activation_key_id' => $row['activation_key_id']],
                ]);
                $left = array_filter([
                    $row['qualys_tag_id'] !== null ? "tag {$row['tag_name']} (id {$row['qualys_tag_id']})" : null,
                    $row['activation_key_id'] !== null ? "activation key {$row['activation_key_id']}" : null,
                ]);
                Helpers::setFlash("Set-up for {$row['tag_name']} cancelled."
                    . ($left !== [] ? ' Still in Qualys, to delete there if not wanted: ' . implode(' and ', $left) . '.' : ' Nothing had been created in Qualys.'));
                break;

            default:
                throw new \RuntimeException('Unknown action.');
        }

        if ($setup !== null) {
            unset($_SESSION['agent_setup_existing'][$setup['id']]);
            AuditLog::record('admin.agent_setup', [
                'target_type' => 'organisation', 'target_id' => $setup['organisation_id'], 'target_label' => $setup['tag_name'],
                'details' => [
                    'qualys_tag_id'     => $setup['qualys_tag_id'],
                    'activation_key_id' => $setup['activation_key_id'],
                    'activation_key'    => $setup['activation_key'],
                    'used_existing_tag' => $action === 'use_existing',
                ],
            ]);
            Helpers::setFlash("{$setup['tag_name']} is set up: Qualys tag {$setup['qualys_tag_id']}, activation key {$setup['activation_key_id']}. "
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

$list = AgentProvisioner::listForAdmin();
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

/** Status cell and actions for an unfinished set-up - shared by both tables. */
$renderInProgress = static function (array $s) use ($csrfToken, $existingChoices): void {
    ?>
    <div class="checkbox-hint">Stopped partway<?= $s['qualys_tag_id'] !== null ? ' - tag ' . (int)$s['qualys_tag_id'] . ' created' : '' ?><?= $s['activation_key_id'] !== null ? ', key ' . (int)$s['activation_key_id'] . ' created' : '' ?>.</div>
    <?php if ($s['last_error'] !== null): ?><div class="checkbox-hint"><?= Helpers::e($s['last_error']) ?></div><?php endif; ?>
    <div class="actions-cell">
        <?php if ($s['qualys_tag_id'] === null): foreach ((array)($existingChoices[$s['id']] ?? []) as $qid => $t): if (!$t['static']) { continue; } ?>
        <form method="post" onsubmit="return confirm(<?= Helpers::jsAttr("Use the existing Qualys tag {$t['name']} (id {$qid}) for this client? Every agent already carrying it will count as this client's.") ?>);">
            <input type="hidden" name="action" value="use_existing">
            <input type="hidden" name="provisioning_id" value="<?= $s['id'] ?>">
            <input type="hidden" name="qualys_tag_id" value="<?= (int)$qid ?>">
            <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
            <button type="submit" class="btn btn-sm btn-secondary">Use existing tag <?= (int)$qid ?></button>
        </form>
        <?php endforeach; endif; ?>
        <form method="post">
            <input type="hidden" name="action" value="retry">
            <input type="hidden" name="provisioning_id" value="<?= $s['id'] ?>">
            <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
            <button type="submit" class="btn btn-sm btn-primary">Retry</button>
        </form>
        <form method="post" onsubmit="return confirm(<?= Helpers::jsAttr("Cancel the set-up for {$s['tag_name']}? Anything already created in Qualys stays there.") ?>);">
            <input type="hidden" name="action" value="cancel">
            <input type="hidden" name="provisioning_id" value="<?= $s['id'] ?>">
            <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
            <button type="submit" class="btn btn-sm btn-secondary">Cancel</button>
        </form>
    </div>
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
    <h2>Organisations <span class="checkbox-hint"><?= count($list['organisations']) ?> total</span></h2>
    <p class="page-subtitle" style="margin-top: 0;">Tag names can use letters, numbers and hyphens only - no spaces. The suggested name can be changed before you create it. Nothing is created if Qualys already has a tag with that name; you'll be asked what to do. New keys: unlimited, licensed for <?= Helpers::e($modules !== '' ? $modules : '-') ?>.</p>
    <div class="table-wrap">
    <table class="vuln-table admin-table">
        <thead>
            <tr><th>Organisation</th><th>Tag</th><th>Activation ID</th><th>Status</th></tr>
        </thead>
        <tbody>
            <?php if ($list['organisations'] === []): ?>
            <tr class="empty-row"><td colspan="4">No organisations yet - add one on <a href="/admin/organisations">Organisations</a> first.</td></tr>
            <?php else: foreach ($list['organisations'] as $org): $s = $org['setup']; ?>
            <tr>
                <td><strong><?= Helpers::e($org['name']) ?></strong></td>
                <?php if ($s === null): $suggested = AgentProvisioner::suggestTagName($org['name']); ?>
                <td colspan="3">
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
                <td>
                    <?php if ($s['status'] === 'complete'): ?>
                    <span class="badge badge-active">Set up</span>
                    <div class="checkbox-hint"><?= Helpers::e(Helpers::displayDateTime($s['completed_at'], 'Y-m-d H:i')) ?></div>
                    <?php else: $renderInProgress($s); endif; ?>
                </td>
                <?php endif; ?>
            </tr>
            <?php endforeach; endif; ?>
        </tbody>
    </table>
    </div>
</div>

<?php if ($list['orphans'] !== []): ?>
<div class="panel">
    <h2>Set-ups for deleted organisations</h2>
    <p class="page-subtitle" style="margin-top: 0;">Their tags and keys still exist in Qualys, so these names stay taken.</p>
    <div class="table-wrap">
    <table class="vuln-table admin-table">
        <thead><tr><th>Tag</th><th>Activation ID</th><th>Status</th></tr></thead>
        <tbody>
            <?php foreach ($list['orphans'] as $s): ?>
            <tr>
                <td class="mono"><?= Helpers::e($s['tag_name']) ?><?php if ($s['qualys_tag_id'] !== null): ?><div class="checkbox-hint">Qualys tag <?= $s['qualys_tag_id'] ?></div><?php endif; ?></td>
                <td class="mono"><?= $s['activation_key'] !== null ? Helpers::e($s['activation_key']) : '-' ?></td>
                <td><?php if ($s['status'] === 'complete'): ?><span class="badge badge-active">Set up</span><?php else: $renderInProgress($s); endif; ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    </div>
</div>
<?php endif; ?>

<?php require __DIR__ . '/../../src/views/footer.php'; ?>
