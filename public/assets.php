<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\AgentInstall;
use VulnDash\Lib\AuditLog;
use VulnDash\Lib\AgentUninstallRepository;
use VulnDash\Lib\Auth;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\ScanRequestRepository;
use VulnDash\Lib\StaleAgent;
use VulnDash\Lib\UserRepository;
use VulnDash\Lib\VulnerabilityRepository;

Auth::check();

$tagIds  = Auth::tagIds();
$isAdmin = Auth::isAdmin();

// Rebuild the current filter/pagination query string so the redirect after a
// bulk action (uninstall or scan) keeps the user where they were.
$keepQuery = array_filter([
    'view_tag' => $_GET['view_tag'] ?? null,
    'q'        => $_GET['q'] ?? null,
    'stale'    => $_GET['stale'] ?? null,
    'sort'     => $_GET['sort'] ?? null,
    'dir'      => $_GET['dir'] ?? null,
    'page'     => $_GET['page'] ?? null,
], static fn ($v) => $v !== null && $v !== '');
$selfUrl = '/assets' . ($keepQuery ? '?' . http_build_query($keepQuery) : '');

// ---------------------------------------------------------------------------
// Queue an agent uninstall (permitted accounts only). Non-destructive here:
// this only writes 'pending' rows to agent_uninstall_queue; the cron worker
// (scripts/process_agent_uninstalls.php) is what actually calls Qualys. The
// selected assets vanish from every dashboard read immediately, though, via
// the suppression in VulnerabilityRepository - see AgentUninstallRepository.
// ---------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'uninstall_agents') {
    if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
        Helpers::setFlash('Your session expired - please try that again.', 'error');
        header('Location: ' . $selfUrl);
        exit;
    }

    // Authoritative capability check, read fresh from the DB rather than trusted
    // from the session, so an admin revoking the grant takes effect immediately.
    if (!$isAdmin && !UserRepository::getCanUninstall(Auth::userId())) {
        Helpers::setFlash('You do not have permission to uninstall agents.', 'error');
        header('Location: ' . $selfUrl);
        exit;
    }

    $assetIds = array_map('intval', (array)($_POST['asset_ids'] ?? []));
    if ($assetIds === []) {
        Helpers::setFlash('Select at least one asset to uninstall.', 'error');
        header('Location: ' . $selfUrl);
        exit;
    }

    $r = AgentUninstallRepository::enqueue($assetIds, Auth::userId(), $tagIds, $isAdmin);
    if ($r['queued'] > 0) {
        AuditLog::record('agent.uninstall_requested', [
            'target_type' => 'assets', 'target_label' => implode(', ', array_slice($r['hostnames'], 0, 10)) . (count($r['hostnames']) > 10 ? ', ...' : ''),
            'details' => ['queued' => $r['queued'], 'hosts' => $r['hostnames']],
        ]);
    }

    $parts = [];
    if ($r['queued'] > 0) {
        $names = implode(', ', array_slice($r['hostnames'], 0, 5));
        if (count($r['hostnames']) > 5) {
            $names .= ', …';
        }
        $parts[] = $r['queued'] . ' agent' . ($r['queued'] === 1 ? '' : 's')
            . ' queued for uninstall (' . $names . '). '
            . 'They have been removed from the dashboard and will be uninstalled on the next processing run.';
    }
    if ($r['already_queued'] > 0) {
        $parts[] = $r['already_queued'] . ' already queued.';
    }
    if ($r['not_permitted'] > 0) {
        $parts[] = $r['not_permitted'] . ' skipped (outside your access).';
    }

    Helpers::setFlash($parts === [] ? 'Nothing to queue.' : implode(' ', $parts), $r['queued'] > 0 ? 'success' : 'error');
    header('Location: ' . $selfUrl);
    exit;
}

// ---------------------------------------------------------------------------
// Queue an on-demand vulnerability scan (any account, within its own tag
// scope - see ScanRequestRepository::enqueue()). Writes 'pending' rows only;
// scripts/process_scan_requests.php sends them to Qualys in one bulk call,
// normally within about 10 minutes, under that endpoint's limit of 25 calls a
// day (see ScanRequestRepository::sendWindow()).
// ---------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'request_scan') {
    if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
        Helpers::setFlash('Your session expired - please try that again.', 'error');
        header('Location: ' . $selfUrl);
        exit;
    }

    $assetIds = array_map('intval', (array)($_POST['asset_ids'] ?? []));
    if ($assetIds === []) {
        Helpers::setFlash('Select at least one asset to scan.', 'error');
        header('Location: ' . $selfUrl);
        exit;
    }

    $r = ScanRequestRepository::enqueue($assetIds, Auth::userId(), $tagIds, $isAdmin);
    if ($r['queued'] > 0) {
        AuditLog::record('scan.requested', [
            'target_type' => 'assets', 'target_label' => implode(', ', array_slice($r['hostnames'], 0, 10)) . (count($r['hostnames']) > 10 ? ', ...' : ''),
            'details' => ['queued' => $r['queued'], 'hosts' => $r['hostnames']],
        ]);
    }

    $parts = [];
    if ($r['queued'] > 0) {
        $names = implode(', ', array_slice($r['hostnames'], 0, 5));
        if (count($r['hostnames']) > 5) {
            $names .= ', …';
        }
        $parts[] = $r['queued'] . ' asset' . ($r['queued'] === 1 ? '' : 's')
            . ' queued for an on-demand vulnerability scan (' . $names . '). '
            . 'Requests go to Qualys together, normally within about 10 minutes; new results show here once the agent has scanned and Qualys has processed them.';
    }
    if ($r['already_queued'] > 0) {
        $parts[] = $r['already_queued'] . ' already queued.';
    }
    if ($r['cooling_down'] > 0) {
        // See ScanRequestRepository's per-asset cooldown.
        $waits = [];
        foreach (array_slice($r['cooldown_until'], 0, 5, true) as $name => $until) {
            $waits[] = $name . ' from ' . $until;
        }
        $parts[] = $r['cooling_down'] . ' skipped - scanned on request within the last '
            . $r['cooldown_minutes'] . ' minutes, so not yet (' . implode(', ', $waits)
            . (count($r['cooldown_until']) > 5 ? ', …' : '') . ').';
    }
    if ($r['not_permitted'] > 0) {
        $parts[] = $r['not_permitted'] . ' skipped (outside your access).';
    }

    Helpers::setFlash($parts === [] ? 'Nothing to queue.' : implode(' ', $parts), $r['queued'] > 0 ? 'success' : 'error');
    header('Location: ' . $selfUrl);
    exit;
}

// Whether to show the uninstall controls at all (session view; the POST above
// is the authoritative gate). Admins are always capable.
$canUninstall = Auth::canUninstall();

// Every asset is agent-scoped now (scripts/lib/QualysApiClient.php's agent
// scope filter), so this is just one flat tag list - no more Agent
// Tags/Scans split.
$availableTags   = $isAdmin ? UserRepository::listTags() : UserRepository::getTagsByIds($tagIds);
$availableTagIds = array_map('intval', array_column($availableTags, 'id'));

// Persisted across pages (dashboard <-> assets <-> vulnerabilities) via the
// session - see Helpers::resolveViewTag() for exactly how.
$viewTagId = Helpers::resolveViewTag($availableTagIds);

// The tag whose install commands the "Install agent" overlay shows: only the
// one tag being viewed, and only if it has an agent activation ID (set by an
// admin in Manage Users > Tags). No button on the all-tags view. $viewTagId is
// already limited to $availableTags, so a client only ever gets its own IDs.
$installTag = null;
foreach (AgentInstall::installableTags($availableTags) as $it) {
    if ($it['id'] === $viewTagId) {
        $installTag = $it;
    }
}

$page    = max(1, (int)($_GET['page'] ?? 1));
$perPage = 50;

$search = isset($_GET['q']) && trim((string)$_GET['q']) !== '' ? trim((string)$_GET['q']) : null;
$sort   = isset($_GET['sort']) && $_GET['sort'] !== '' ? (string)$_GET['sort'] : null;
$dir    = isset($_GET['dir']) && strtolower((string)$_GET['dir']) === 'desc' ? 'desc' : 'asc';
// Assets whose agent hasn't reported within StaleAgent's threshold - the
// target of the dashboard's "Not reporting" card.
$staleOnly = !empty($_GET['stale']);
$staleAfterDays = StaleAgent::staleAfterDays();

$assets     = VulnerabilityRepository::getAssets($tagIds, $isAdmin, $viewTagId, $page, $perPage, $search, $sort, $dir, $staleOnly);
$totalCount = VulnerabilityRepository::getAssetCount($tagIds, $isAdmin, $viewTagId, $search, $staleOnly);
$totalPages = $totalCount > 0 ? (int)ceil($totalCount / $perPage) : 1;

// Each listed asset's latest scan request, if it's waiting or recent, and -
// only when something on this page is waiting - when the next send can go.
$scanRequests = ScanRequestRepository::latestForAssets(array_map(static fn ($a) => (int)$a['id'], $assets));
$scanWindow = null;
foreach ($scanRequests as $req) {
    if ($req['status'] === 'pending' || $req['status'] === 'processing') {
        $scanWindow = ScanRequestRepository::sendWindow();
        break;
    }
}

$flash     = Helpers::getFlash();
$colspan   = 9;
$csrfToken = Helpers::csrfToken();

$pageTitle = 'Assets';
require __DIR__ . '/../src/views/header.php';
?>

<div class="page-heading page-heading-actions">
    <div>
        <h1>Assets</h1>
        <p class="page-subtitle">
            <?= !$isAdmin ? 'Your assigned assets' : 'All assets' ?><?= $viewTagId !== null ? ', filtered to one tag' : '' ?> - click a hostname to see its open vulnerabilities.
        </p>
    </div>
    <?php if ($installTag !== null): ?>
    <button type="button" class="btn btn-primary" id="installAgentOpen" aria-haspopup="dialog">Install agent</button>
    <?php endif; ?>
</div>

<?php if ($installTag !== null): ?>
<!-- "Install agent" overlay: the same one-line install commands as the CE+
     onboarding instructions, for the tag being viewed. A native <dialog>
     gives focus trapping and Escape-to-close for free. -->
<dialog class="install-dialog" id="installAgentDialog" aria-labelledby="installAgentTitle">
    <div class="install-dialog-head">
        <h2 id="installAgentTitle">Install the Qualys agent</h2>
        <button type="button" class="install-dialog-close" data-install-close aria-label="Close">&times;</button>
    </div>
    <p class="install-intro">
        Pick the operating system, copy the command and run it in a terminal opened as an
        administrator. The new agent appears under Assets after it first reports to Qualys and
        the next dashboard sync runs.
    </p>
    <p class="install-activation">
        <?= Helpers::e($installTag['name']) ?> - activation ID
        <span class="mono"><?= Helpers::e($installTag['activation_id']) ?></span>, already built into the commands.
    </p>

    <h3>Windows</h3>
    <p>Paste into PowerShell opened as Administrator. Can also be deployed through an RMM tool.</p>
    <div class="install-command">
        <code><?= Helpers::e($installTag['windows']) ?></code>
        <button type="button" class="btn btn-sm btn-secondary" data-copy>Copy</button>
    </div>
    <details class="install-help">
        <summary>How do I open PowerShell as an Administrator?</summary>
        <ol>
            <li>Click Start and type <strong>PowerShell</strong>.</li>
            <li>Right-click <strong>Windows PowerShell</strong> and choose <strong>Run as administrator</strong>.</li>
            <li>When Windows asks for permission, enter the username and password of an administrator account and click <strong>Yes</strong>. You don't need to be signed in to Windows as an administrator.</li>
            <li>Paste the command (right-click or Ctrl+V) and press Enter.</li>
        </ol>
    </details>

    <h3>macOS / Linux</h3>
    <p>Paste into Terminal from an account with administrator (sudo) rights. It will ask for that account's password - nothing shows as you type it.</p>
    <div class="install-command">
        <code><?= Helpers::e($installTag['unix']) ?></code>
        <button type="button" class="btn btn-sm btn-secondary" data-copy>Copy</button>
    </div>
    <details class="install-help">
        <summary>How do I open Terminal?</summary>
        <ol>
            <li>macOS: press Cmd+Space, type <strong>Terminal</strong> and press Return.</li>
            <li>Linux: press Ctrl+Alt+T, or open <strong>Terminal</strong> from the applications menu.</li>
            <li>Paste the command (Cmd+V on macOS, Ctrl+Shift+V on Linux) and press Enter.</li>
        </ol>
    </details>

    <p class="install-note">Each command may wrap on screen, but Copy always copies it as one line.</p>
</dialog>
<?php endif; ?>

<?php if ($flash): ?>
<div class="flash flash-<?= Helpers::e($flash['type']) ?>"><?= Helpers::e($flash['message']) ?></div>
<?php endif; ?>

<form method="get" class="filter-bar">
    <?php if (!empty($availableTags)): ?>
    <label class="field field-inline">
        <span>Tags</span>
        <select name="view_tag" onchange="this.form.submit();">
            <option value="">All<?= $isAdmin ? ' tags' : ' your tags' ?></option>
            <?php foreach ($availableTags as $tag): ?>
            <option value="<?= (int)$tag['id'] ?>" <?= $viewTagId === (int)$tag['id'] ? 'selected' : '' ?>><?= Helpers::e($tag['name']) ?></option>
            <?php endforeach; ?>
        </select>
    </label>
    <?php endif; ?>
    <label class="field field-inline">
        <span>Search</span>
        <span class="search-input-wrap">
            <input type="text" name="q" class="search-debounce-input" value="<?= Helpers::e($search ?? '') ?>" placeholder="Hostname, IP, OS…" autocomplete="off">
            <button type="button" class="search-clear" aria-label="Clear search" title="Clear search" <?= ($search === null || $search === '') ? 'hidden' : '' ?>>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
            </button>
        </span>
    </label>
    <label class="checkbox-field">
        <input type="checkbox" name="stale" value="1" <?= $staleOnly ? 'checked' : '' ?> onchange="this.form.submit()">
        <span>Not reporting only <span class="checkbox-hint">(no agent report in <?= $staleAfterDays ?>+ days)</span></span>
    </label>
    <noscript><button type="submit" class="btn btn-secondary">Apply</button></noscript>
</form>

<p class="result-count"><?= number_format($totalCount) ?> asset<?= $totalCount === 1 ? '' : 's' ?></p>

<?php // The whole table is the bulk-action form. Row checkboxes name
      // asset_ids[]; each button carries its own action, and the confirm
      // step reads which one was pressed. Scans are open to every account;
      // the uninstall button only shows for accounts allowed to use it. ?>
<form method="post" id="bulk-asset-form" onsubmit="return confirmBulkAction(this, event.submitter);">
<input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">

<div class="bulk-actions">
    <button type="submit" name="action" value="request_scan" class="btn btn-sm btn-secondary">Scan selected now</button>
    <?php if ($canUninstall): ?>
    <button type="submit" name="action" value="uninstall_agents" class="btn btn-sm btn-danger">Uninstall agent on selected</button>
    <?php endif; ?>
    <span class="bulk-hint checkbox-hint">Select assets, then choose an action. Scan requests go to Qualys together, normally within about 10 minutes.<?= $canUninstall ? ' Assets queued for uninstall leave the dashboard until the agent is removed.' : '' ?></span>
</div>

<div class="table-wrap">
<table class="vuln-table">
    <thead>
        <tr>
            <th class="checkbox-col"><input type="checkbox" id="select-all-assets" aria-label="Select all assets on this page"></th>
            <th><?= Helpers::sortLink('Hostname', 'hostname', $sort, $dir) ?></th>
            <th><?= Helpers::sortLink('IP address', 'ip', $sort, $dir) ?></th>
            <th><?= Helpers::sortLink('OS', 'os', $sort, $dir) ?></th>
            <th><?= Helpers::sortLink('Last scan', 'last_scan', $sort, $dir) ?></th>
            <th><?= Helpers::sortLink('Critical', 'critical', $sort, $dir) ?></th>
            <th><?= Helpers::sortLink('High', 'high', $sort, $dir) ?></th>
            <th><?= Helpers::sortLink('CE+ fails', 'ce_plus', $sort, $dir) ?></th>
            <th><?= Helpers::sortLink('Open vulns', 'open_vulns', $sort, $dir) ?></th>
        </tr>
    </thead>
    <tbody>
        <?php if (empty($assets)): ?>
        <tr class="empty-row"><td colspan="<?= $colspan ?>">No assets match the current filter.</td></tr>
        <?php else: foreach ($assets as $row):
            $stale = StaleAgent::status($row['last_scan_date']);
            $scanChip = scanRequestChip($scanRequests[(int)$row['id']] ?? null, $row['last_scan_date'], $scanWindow);
        ?>
        <tr>
            <td class="checkbox-col"><input type="checkbox" class="asset-select" name="asset_ids[]" value="<?= (int)$row['id'] ?>" aria-label="Select <?= Helpers::e($row['hostname'] ?: $row['ip_address'] ?: 'host') ?>"></td>
            <td><a href="/vulnerabilities?asset_id=<?= (int)$row['id'] ?>"><?= Helpers::e($row['hostname'] ?: $row['ip_address'] ?: 'Unknown host') ?></a></td>
            <td class="mono"><?= Helpers::e($row['ip_address'] ?: '—') ?></td>
            <td><?= Helpers::e($row['os'] ?: '—') ?></td>
            <?php // Not reporting is a fact about the last scan, so it lives in this column - in place of the
                  // date - rather than beside the hostname, where its position depended on hostname length.
                  // Amber, like the other "treat with caution" chips: the counts on this row may be out of
                  // date. The exact date and full label() wording are in the tooltip. ?>
            <?php // A scan request's chip follows the date (or stale chip) in the
                  // same column, since it is about the next scan. ?>
            <td class="last-scan-cell">
                <?php if ($stale === null): ?>
                <span class="mono"><?= Helpers::e(Helpers::displayQualysDateTime($row['last_scan_date'])) ?></span>
                <?php else: ?>
                <span class="badge sev-medium badge-stale" title="<?= Helpers::e(StaleAgent::label($stale)) ?> - <?= $stale['days'] === null ? 'no scan results have been received from this agent yet' : 'last scan ' . Helpers::e(Helpers::displayQualysDateTime($row['last_scan_date'])) . ", over {$staleAfterDays} days ago, so this asset's findings may be out of date" ?>"><?= Helpers::e(StaleAgent::shortLabel($stale)) ?></span>
                <?php endif; ?>
                <?php if ($scanChip !== null): ?>
                <span class="badge badge-scan <?= Helpers::e($scanChip['class']) ?>" title="<?= Helpers::e($scanChip['title']) ?>"><?= Helpers::e($scanChip['label']) ?></span>
                <?php endif; ?>
            </td>
            <td class="mono"><?= (int)$row['critical_count'] ?></td>
            <td class="mono"><?= (int)$row['high_count'] ?></td>
            <td class="mono"><?= (int)$row['ce_plus_fail_count'] ?></td>
            <td class="mono"><?= (int)$row['open_vuln_count'] ?></td>
        </tr>
        <?php endforeach; endif; ?>
    </tbody>
</table>
</div>
</form>

<?php if ($totalPages > 1): ?>
<nav class="pagination" aria-label="Pagination">
    <?php for ($p = 1; $p <= $totalPages; $p++):
        $query = $_GET;
        $query['page'] = $p;
    ?>
        <a class="<?= $p === $page ? 'active' : '' ?>" href="?<?= htmlspecialchars(http_build_query($query)) ?>"><?= $p ?></a>
    <?php endfor; ?>
</nav>
<?php endif; ?>

<script>
// "Select all" checkbox toggles every row checkbox on the current page.
(function () {
    var master = document.getElementById('select-all-assets');
    if (!master) return;
    master.addEventListener('change', function () {
        document.querySelectorAll('.asset-select').forEach(function (cb) { cb.checked = master.checked; });
    });
})();

// Yes/no confirmation before queueing, worded for whichever button was
// pressed. Blocks submit if nothing is selected. A browser too old to report
// the pressed button gets the uninstall wording, the cautious choice.
function confirmBulkAction(form, submitter) {
    var checked = form.querySelectorAll('.asset-select:checked');
    if (checked.length === 0) {
        alert('Select at least one asset first.');
        return false;
    }
    var n = checked.length + ' asset' + (checked.length === 1 ? '' : 's');
    if (submitter && submitter.value === 'request_scan') {
        return confirm(
            'Request an on-demand vulnerability scan on ' + n + '?\n\n' +
            'Requests are sent to Qualys together, normally within about 10 minutes. New results appear once each agent has scanned and Qualys has processed them.'
        );
    }
    return confirm(
        'Queue agent uninstall for ' + n + '?\n\n' +
        'They will be removed from the dashboard immediately and the Cloud Agent will be uninstalled on the next processing run. ' +
        'If an agent is later re-installed, the asset will reappear.'
    );
}

// "Install agent" overlay: open/close, copy buttons.
(function () {
    var dialog = document.getElementById('installAgentDialog');
    var openBtn = document.getElementById('installAgentOpen');
    if (!dialog || !openBtn || typeof dialog.showModal !== 'function') return;

    openBtn.addEventListener('click', function () { dialog.showModal(); });
    dialog.querySelectorAll('[data-install-close]').forEach(function (b) {
        b.addEventListener('click', function () { dialog.close(); });
    });
    // A click on the backdrop lands on the <dialog> itself.
    dialog.addEventListener('click', function (e) {
        if (e.target === dialog) dialog.close();
    });

    // Copies the <code> text, which is always one line - the wrapping is CSS only.
    function fallbackCopy(text) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        dialog.appendChild(ta);
        ta.select();
        var done = false;
        try { done = document.execCommand('copy'); } catch (e) { done = false; }
        dialog.removeChild(ta);
        return done;
    }
    dialog.querySelectorAll('[data-copy]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var text = btn.parentNode.querySelector('code').textContent;
            function flash(label) {
                btn.textContent = label;
                setTimeout(function () { btn.textContent = 'Copy'; }, 2000);
            }
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(function () { flash('Copied'); }, function () {
                    flash(fallbackCopy(text) ? 'Copied' : 'Copy failed');
                });
            } else {
                flash(fallbackCopy(text) ? 'Copied' : 'Copy failed');
            }
        });
    });
})();
</script>

<?php require __DIR__ . '/../src/views/footer.php';

/**
 * The scan-request chip for one asset row, or null for none: "Scan queued"
 * while waiting to be sent, "Scan requested" once sent until the asset's
 * last scan date passes the send time (the results are in), and "Scan
 * failed" with the reason in the tooltip. ScanRequestRepository::
 * latestForAssets() already drops finished requests older than 24 hours.
 *
 * requested_at/processed_at are in the app's zone (MySQL NOW() under the
 * Europe/London session zone); last_scan_date is UTC, hence the ' UTC'.
 *
 * $window is ScanRequestRepository::sendWindow(), for saying when a waiting
 * request will go - the worker runs every 5 minutes, so a send allowed
 * within that needs no time quoting.
 *
 * @param array{status:string, requested_at:string, processed_at:?string, last_error:?string}|null $req
 * @param array{calls_24h:int, budget:int, min_gap_minutes:int, next_at:int}|null $window
 * @return array{label:string, class:string, title:string}|null
 */
function scanRequestChip(?array $req, ?string $lastScanDateUtc, ?array $window = null): ?array
{
    if ($req === null) {
        return null;
    }
    $requested = date('d M H:i', (int)strtotime($req['requested_at']));
    if ($req['status'] === 'pending' || $req['status'] === 'processing') {
        if ($window !== null && $window['next_at'] > time() + 300) {
            $when = 'next send from ' . date('H:i', $window['next_at'])
                . ($window['calls_24h'] >= $window['budget'] ? ", when today's on-demand scan budget frees up" : '');
        } else {
            $when = 'it goes on the next send, within about 5 minutes';
        }
        $title = 'On-demand scan requested ' . $requested . ' - waiting to be sent to Qualys (' . $when . ').';
        if ($req['last_error'] !== null) {
            $title .= ' ' . $req['last_error'];
        }
        return ['label' => 'Scan queued', 'class' => 'badge-accent', 'title' => $title];
    }
    if ($req['status'] === 'failed') {
        return ['label' => 'Scan failed', 'class' => 'badge-neutral', 'title' => 'On-demand scan requested ' . $requested . ' could not be sent. ' . (string)$req['last_error']];
    }
    $processedTs = $req['processed_at'] !== null ? (int)strtotime($req['processed_at']) : 0;
    $lastScanTs = $lastScanDateUtc !== null ? strtotime($lastScanDateUtc . ' UTC') : false;
    if ($lastScanTs !== false && $lastScanTs >= $processedTs) {
        return null;
    }
    return ['label' => 'Scan requested', 'class' => 'badge-accent', 'title' => 'On-demand scan sent to Qualys ' . date('d M H:i', $processedTs) . ' - the agent scans, uploads and Qualys processes the results, then the hourly sync brings them in.'];
}
?>
