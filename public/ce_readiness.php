<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Auth;
use VulnDash\Lib\CePlusDeadline;
use VulnDash\Lib\CePlusReadiness;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\StaleAgent;
use VulnDash\Lib\UserRepository;
use VulnDash\Lib\VulnerabilityRepository;

Auth::check();

$tagIds  = Auth::tagIds();
$isAdmin = Auth::isAdmin();
$userId  = Auth::userId();

// Same tag-scope pattern as the other data pages; the Tags dropdown shares the
// session-persisted view_tag preference (Helpers::resolveViewTag()).
$availableTags   = $isAdmin ? UserRepository::listTags() : UserRepository::getTagsByIds($tagIds);
$availableTagIds = array_map('intval', array_column($availableTags, 'id'));

// Host-list status filter, validated against a whitelist. "attention" (fail +
// at risk) is the default: a passing host needs no action, and at thousands of
// agents a full list would bury the ones that do.
$statusOptions = [
    'attention'              => 'Needs attention',
    CePlusReadiness::FAIL    => 'Failing',
    CePlusReadiness::AT_RISK => 'At risk',
    CePlusReadiness::PASS    => 'Passing',
    'all'                    => 'All hosts',
];
$statusFilter = (string)($_GET['status'] ?? 'attention');
if (!isset($statusOptions[$statusFilter])) {
    $statusFilter = 'attention';
}

// --- Admin: set or clear a tag's assessment date (post/redirect/get) ---------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $back = '/ce_readiness' . (isset($_POST['status']) && isset($statusOptions[(string)$_POST['status']]) ? '?status=' . rawurlencode((string)$_POST['status']) : '');

    if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
        Helpers::setFlash('Your session expired - please try that again.', 'error');
        header('Location: ' . $back);
        exit;
    }
    // Clients see the date read-only; the form isn't rendered for them, and
    // this refuses a hand-built post too.
    if (!$isAdmin) {
        Helpers::setFlash('Only an administrator can set assessment dates.', 'error');
        header('Location: ' . $back);
        exit;
    }

    $postTagId = (int)($_POST['tag_id'] ?? 0);
    $rawDate   = trim((string)($_POST['ce_date'] ?? ''));
    $date      = CePlusReadiness::parseDate($rawDate);
    $tagName   = null;
    foreach ($availableTags as $t) {
        if ((int)$t['id'] === $postTagId) {
            $tagName = (string)$t['name'];
        }
    }

    if ($tagName === null) {
        Helpers::setFlash('That tag no longer exists.', 'error');
    } elseif ($rawDate !== '' && $date === null) {
        Helpers::setFlash('That is not a valid date.', 'error');
    } else {
        UserRepository::setCeAssessmentDate($postTagId, $date);
        Helpers::setFlash($date === null
            ? "Assessment date cleared for {$tagName}."
            : "Assessment date for {$tagName} set to " . (new \DateTimeImmutable($date))->format('j M Y') . '.');
    }
    header('Location: ' . $back);
    exit;
}

$viewTagId = Helpers::resolveViewTag($availableTagIds);
$today     = CePlusReadiness::todayUk();

// --- Per-host status ---------------------------------------------------------
$hostRows = VulnerabilityRepository::getCePlusReadinessHosts($tagIds, $isAdmin, $viewTagId, $userId);

$hosts = [];
$counts = [CePlusReadiness::FAIL => 0, CePlusReadiness::AT_RISK => 0, CePlusReadiness::PASS => 0];
$staleCount = 0;
// CE+ findings this account has hidden on these hosts: counted here, left out
// of the dashboard cards and the vulnerability list by default.
$hiddenIncluded = 0;
foreach ($hostRows as $row) {
    $hiddenIncluded += (int)$row['hidden_count'];
    $row['status'] = CePlusReadiness::status($row);
    $row['next']   = CePlusReadiness::nextDeadline($row);
    $row['stale']  = StaleAgent::status($row['last_scan_date']);
    $counts[$row['status']]++;
    if ($row['stale'] !== null) {
        $staleCount++;
    }
    $hosts[(int)$row['id']] = $row;
}
$totalHosts = count($hosts);
$readyToday = $counts[CePlusReadiness::AT_RISK] + $counts[CePlusReadiness::PASS];
$readyPct   = $totalHosts > 0 ? (int)floor($readyToday * 100 / $totalHosts) : 0;

// --- Per-tag summary + assessment dates ---------------------------------------
// Tags shown: just the selected one, or every selectable tag that has at least
// one in-scope host. Membership is intersected with $hosts, which is already
// tag-scoped and uninstall-suppressed, so nothing here widens the view.
$summaryTags = $viewTagId !== null
    ? array_values(array_filter($availableTags, static fn(array $t): bool => (int)$t['id'] === $viewTagId))
    : $availableTags;
$summaryTagIds = array_map('intval', array_column($summaryTags, 'id'));
$assetIdsByTag = VulnerabilityRepository::getAssetIdsByTag($summaryTagIds);
$assessDates   = UserRepository::getCeAssessmentDates($summaryTagIds);

$tagSummaries = [];
foreach ($summaryTags as $tag) {
    $tid = (int)$tag['id'];
    $date = $assessDates[$tid] ?? null;
    $upcoming = $date !== null && $date >= $today;
    $s = ['id' => $tid, 'name' => (string)$tag['name'], 'date' => $date, 'upcoming' => $upcoming,
          'hosts' => 0, 'fail' => 0, 'at_risk' => 0, 'pass' => 0, 'projected_fail' => null];
    foreach (array_unique($assetIdsByTag[$tid] ?? []) as $aid) {
        if (!isset($hosts[$aid])) {
            continue;
        }
        $s['hosts']++;
        $s[$hosts[$aid]['status']]++;
        if ($upcoming) {
            $s['projected_fail'] = ($s['projected_fail'] ?? 0)
                + (CePlusReadiness::projectedStatus($hosts[$aid], $date) === CePlusReadiness::FAIL ? 1 : 0);
        }
    }
    if ($s['hosts'] > 0) {
        $tagSummaries[] = $s;
    }
}

// The host list gets a "Status on <date>" column when the view resolves to one
// tag with an upcoming date: the selected tag, or a client's only tag.
$projTagId = $viewTagId ?? (count($availableTags) === 1 ? (int)$availableTags[0]['id'] : null);
$projDate  = null;
$projSummary = null;
foreach ($tagSummaries as $s) {
    if ($s['id'] === $projTagId && $s['upcoming']) {
        $projDate = (string)$s['date'];
        $projSummary = $s;
    }
}

// --- Host list: filter, sort, paginate -----------------------------------------
$listed = array_values(array_filter($hosts, static function (array $h) use ($statusFilter): bool {
    return match ($statusFilter) {
        'all'       => true,
        'attention' => $h['status'] !== CePlusReadiness::PASS,
        default     => $h['status'] === $statusFilter,
    };
}));

// Failing first (most blocking findings first), then at risk by soonest
// deadline, then passing; hostname breaks ties so the order is stable.
$rank = [CePlusReadiness::FAIL => 0, CePlusReadiness::AT_RISK => 1, CePlusReadiness::PASS => 2];
usort($listed, static function (array $a, array $b) use ($rank): int {
    return [$rank[$a['status']], -CePlusReadiness::blockingCount($a), (string)($a['next_clock_start'] ?? '9999'), strtolower((string)($a['hostname'] ?: $a['ip_address']))]
       <=> [$rank[$b['status']], -CePlusReadiness::blockingCount($b), (string)($b['next_clock_start'] ?? '9999'), strtolower((string)($b['hostname'] ?: $b['ip_address']))];
});

$perPage    = 100;
$listCount  = count($listed);
$totalPages = $listCount > 0 ? (int)ceil($listCount / $perPage) : 1;
$page       = min(max(1, (int)($_GET['page'] ?? 1)), $totalPages);
$pageRows   = array_slice($listed, ($page - 1) * $perPage, $perPage);

// --- Next deadlines: in-window CE+ findings, soonest first, hides ignored -------
$deadlines = VulnerabilityRepository::getDetections($tagIds, $isAdmin, ['ce_in_window_only' => true], 1, 15, $viewTagId, 'ce_due', 'asc', true, $userId);

$flash = Helpers::getFlash();
$csrf  = Helpers::csrfToken();

$pageTitle = 'CE+ Readiness';
require __DIR__ . '/../src/views/header.php';
?>

<div class="page-heading">
    <h1>CE+ Readiness</h1>
    <p class="page-subtitle">Whether each host would pass a Cyber Essentials Plus assessment on what Qualys reports today. A host fails if it has any end-of-life software, or a CVSS 7.0+ finding whose patch was released more than <?= CePlusDeadline::PATCH_WINDOW_DAYS ?> days ago. Other findings with no vendor fix yet don't count. It is at risk if its CE+ findings are all still inside the <?= CePlusDeadline::PATCH_WINDOW_DAYS ?>-day window.</p>
</div>

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
    <input type="hidden" name="status" value="<?= Helpers::e($statusFilter) ?>">
    <noscript><button type="submit" class="btn btn-secondary">Apply</button></noscript>
</form>

<?php if ($totalHosts === 0): ?>
<p class="chart-empty">No active hosts<?= $viewTagId !== null ? ' for this tag' : '' ?> yet.</p>
<?php else: ?>

<div class="stat-grid readiness-grid">
    <div class="stat-card stat-card-primary">
        <span class="stat-number"><?= $readyPct ?>%</span>
        <span class="stat-label">Would pass today</span>
        <span class="movement-card-hint"><?= number_format($readyToday) ?> of <?= number_format($totalHosts) ?> host<?= $totalHosts === 1 ? '' : 's' ?></span>
    </div>
    <a class="stat-card readiness-fail" href="?status=<?= CePlusReadiness::FAIL ?>">
        <span class="stat-number"><?= number_format($counts[CePlusReadiness::FAIL]) ?></span>
        <span class="stat-label">Failing</span>
        <span class="movement-card-hint">End-of-life, or patch overdue →</span>
    </a>
    <a class="stat-card readiness-risk" href="?status=<?= CePlusReadiness::AT_RISK ?>">
        <span class="stat-number"><?= number_format($counts[CePlusReadiness::AT_RISK]) ?></span>
        <span class="stat-label">At risk</span>
        <span class="movement-card-hint">Pass today, patch due soon →</span>
    </a>
    <a class="stat-card readiness-pass" href="?status=<?= CePlusReadiness::PASS ?>">
        <span class="stat-number"><?= number_format($counts[CePlusReadiness::PASS]) ?></span>
        <span class="stat-label">Passing</span>
        <span class="movement-card-hint">Nothing to patch →</span>
    </a>
</div>

<?php if ($projSummary !== null):
    $daysTo = CePlusReadiness::daysUntil($projDate);
?>
<div class="readiness-projection">
    <strong>Assessment on <?= Helpers::e((new \DateTimeImmutable($projDate))->format('j M Y')) ?></strong>
    (<?= $daysTo === 0 ? 'today' : 'in ' . $daysTo . ' day' . ($daysTo === 1 ? '' : 's') ?>):
    <strong><?= number_format((int)$projSummary['projected_fail']) ?></strong> of <?= number_format($projSummary['hosts']) ?> host<?= $projSummary['hosts'] === 1 ? '' : 's' ?>
    projected to fail if nothing more is patched<?php
    $newlyFailing = (int)$projSummary['projected_fail'] - $projSummary['fail'];
    if ($newlyFailing > 0): ?> - <?= number_format($newlyFailing) ?> of them only at risk today<?php endif; ?>.
    <span class="readiness-note">New findings that appear before then aren't included.</span>
</div>
<?php endif; ?>

<?php if ($staleCount > 0 || $hiddenIncluded > 0): ?>
<ul class="readiness-caveats">
    <?php if ($staleCount > 0): ?>
    <li><span class="badge sev-medium badge-stale">Not reporting</span> <?= number_format($staleCount) ?> host<?= $staleCount === 1 ? "'s agent hasn't" : "s' agents haven't" ?> reported in <?= StaleAgent::staleAfterDays() ?>+ days. Their status uses the last data received and may be out of date. <a href="/assets?stale=1">View them →</a></li>
    <?php endif; ?>
    <?php if ($hiddenIncluded > 0): ?>
    <li>Includes <?= number_format($hiddenIncluded) ?> CE+ finding<?= $hiddenIncluded === 1 ? '' : 's' ?> you've hidden. The assessment runs in Qualys, which doesn't see dashboard hides. The vulnerability list leaves them out unless you show hidden findings.</li>
    <?php endif; ?>
</ul>
<?php endif; ?>

<?php if (!empty($tagSummaries)): ?>
<h2 class="section-heading">By tag <span class="section-heading-sub">assessment dates<?= $isAdmin ? ' (set by admins)' : '' ?></span></h2>
<div class="chart-panel">
    <div class="table-wrap">
    <table class="vuln-table readiness-tags">
        <thead>
            <tr>
                <th>Tag</th>
                <th class="col-num">Hosts</th>
                <th class="col-num">Failing</th>
                <th class="col-num">At risk</th>
                <th class="col-num">Passing</th>
                <th>Assessment date</th>
                <th class="col-num" title="Hosts projected to fail on the assessment date if nothing more is patched">Projected to fail</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($tagSummaries as $s): ?>
            <tr>
                <td><a href="?view_tag=<?= $s['id'] ?>&amp;status=<?= Helpers::e($statusFilter) ?>"><?= Helpers::e($s['name']) ?></a></td>
                <td class="col-num mono"><?= number_format($s['hosts']) ?></td>
                <td class="col-num mono"><?= number_format($s['fail']) ?></td>
                <td class="col-num mono"><?= number_format($s['at_risk']) ?></td>
                <td class="col-num mono"><?= number_format($s['pass']) ?></td>
                <td>
                    <?php if ($isAdmin): ?>
                    <form method="post" class="readiness-date-form">
                        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrf) ?>">
                        <input type="hidden" name="tag_id" value="<?= $s['id'] ?>">
                        <input type="hidden" name="status" value="<?= Helpers::e($statusFilter) ?>">
                        <input type="date" name="ce_date" value="<?= Helpers::e($s['date'] ?? '') ?>" aria-label="Assessment date for <?= Helpers::e($s['name']) ?>">
                        <button type="submit" class="btn btn-secondary btn-sm">Save</button>
                    </form>
                    <?php elseif ($s['date'] !== null): ?>
                    <span class="mono"><?= Helpers::e((new \DateTimeImmutable($s['date']))->format('j M Y')) ?></span>
                    <?php else: ?>
                    <span class="readiness-note">Not booked</span>
                    <?php endif; ?>
                    <?php if ($s['date'] !== null && !$s['upcoming']): ?>
                    <span class="badge badge-neutral" title="This date has passed - set the next assessment date to see a projection">Past</span>
                    <?php endif; ?>
                </td>
                <td class="col-num mono"><?= $s['projected_fail'] !== null ? number_format($s['projected_fail']) : '—' ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    </div>
    <?php if ($isAdmin): ?>
    <p class="readiness-note">Clear the date and save to remove it. Every account with access to the tag sees its date.</p>
    <?php endif; ?>
</div>
<?php endif; ?>

<h2 class="section-heading">Hosts <span class="section-heading-sub"><?= Helpers::e($statusOptions[$statusFilter]) ?> · <?= number_format($listCount) ?></span></h2>
<p class="readiness-status-links">
    <?php foreach ($statusOptions as $key => $label): ?>
    <a class="readiness-tab<?= $key === $statusFilter ? ' readiness-tab-active' : '' ?>" href="?status=<?= Helpers::e($key) ?>"><?= Helpers::e($label) ?></a>
    <?php endforeach; ?>
</p>
<div class="table-wrap">
<table class="vuln-table">
    <thead>
        <tr>
            <th>Host</th>
            <th>OS</th>
            <th>Today</th>
            <?php if ($projDate !== null): ?>
            <th>On <?= Helpers::e((new \DateTimeImmutable($projDate))->format('j M')) ?></th>
            <?php endif; ?>
            <th class="col-num" title="End-of-life software (Qualys EOL/Obsolete QIDs) - always fails, whatever the CVSS score">EOL</th>
            <th class="col-num" title="CE+ findings past the <?= CePlusDeadline::PATCH_WINDOW_DAYS ?>-day patch window">Overdue</th>
            <th class="col-num" title="CVSS 7.0+ findings with no vendor fix yet (Qualys PATCHABLE 0) - shown for information, they don't affect the host's status">No fix</th>
            <th class="col-num" title="CE+ findings still inside the <?= CePlusDeadline::PATCH_WINDOW_DAYS ?>-day patch window">In window</th>
            <th>Next deadline</th>
            <th>Last scan</th>
        </tr>
    </thead>
    <tbody>
        <?php if (empty($pageRows)): ?>
        <tr class="empty-row"><td colspan="<?= $projDate !== null ? 10 : 9 ?>">No hosts with this status.</td></tr>
        <?php else: foreach ($pageRows as $h):
            $hostLabel = $h['hostname'] ?: $h['ip_address'] ?: 'Unknown host';
            $noFix = (int)$h['no_fix_count'];
            $noDate = (int)$h['no_date_count'];
        ?>
        <tr>
            <td>
                <?php // An EOL finding can be below 7.0, so a host with one links to all its findings rather than the CE+-only filter. ?>
                <?php if ((int)$h['ce_total'] + (int)$h['eol_count'] > 0): ?>
                <a href="/vulnerabilities?<?= Helpers::e(http_build_query((int)$h['eol_count'] > 0 ? ['asset_id' => (int)$h['id']] : ['asset_id' => (int)$h['id'], 'ce_plus_only' => 1])) ?>"><?= Helpers::e($hostLabel) ?></a>
                <?php else: ?>
                <?= Helpers::e($hostLabel) ?>
                <?php endif; ?>
            </td>
            <td><?= Helpers::e($h['os'] ?: '—') ?></td>
            <td><span class="badge <?= CePlusReadiness::badgeClass($h['status']) ?>"><?= CePlusReadiness::label($h['status']) ?></span></td>
            <?php if ($projDate !== null):
                $proj = CePlusReadiness::projectedStatus($h, $projDate);
            ?>
            <td><span class="badge <?= CePlusReadiness::badgeClass($proj) ?>"><?= CePlusReadiness::label($proj) ?></span></td>
            <?php endif; ?>
            <td class="col-num mono"><?= (int)$h['eol_count'] ?: '—' ?></td>
            <td class="col-num mono"<?= $noDate > 0 ? ' title="Includes ' . $noDate . ' with no patch or published date to count from - treated as failing"' : '' ?>><?= ((int)$h['overdue_count'] + $noDate) ?: '—' ?><?= $noDate > 0 ? '*' : '' ?></td>
            <td class="col-num mono"><?= $noFix ?: '—' ?></td>
            <td class="col-num mono"><?= (int)$h['in_window_count'] ?: '—' ?></td>
            <td class="mono"><?php if ($h['next'] !== null): ?><span title="Patch due <?= Helpers::e($h['next']['due']->format('Y-m-d')) ?>"><?= Helpers::e(CePlusDeadline::shortLabel($h['next'])) ?></span><?php else: ?>—<?php endif; ?></td>
            <td class="mono last-scan-cell">
                <?php if ($h['stale'] === null): ?>
                <?= Helpers::e(Helpers::displayQualysDateTime($h['last_scan_date'], 'Y-m-d H:i')) ?>
                <?php else: ?>
                <span class="badge sev-medium badge-stale" title="<?= Helpers::e(StaleAgent::label($h['stale'])) ?> - status uses the last data received"><?= Helpers::e(StaleAgent::shortLabel($h['stale'])) ?></span>
                <?php endif; ?>
            </td>
        </tr>
        <?php endforeach; endif; ?>
    </tbody>
</table>
</div>

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

<h2 class="section-heading">Next deadlines <span class="section-heading-sub">CE+ findings still inside the window, soonest first</span></h2>
<div class="chart-panel">
    <?php if (empty($deadlines)): ?>
    <p class="chart-empty">No CE+ findings inside the <?= CePlusDeadline::PATCH_WINDOW_DAYS ?>-day window<?= $viewTagId !== null ? ' for this tag' : '' ?>.</p>
    <?php else: ?>
    <div class="table-wrap">
    <table class="vuln-table">
        <thead>
            <tr>
                <th>Due</th>
                <th>Asset</th>
                <th>QID</th>
                <th>Title</th>
                <th class="col-num">CVSS</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($deadlines as $row):
                $dl = CePlusDeadline::forRow($row);
            ?>
            <tr>
                <td class="mono"><?php if ($dl !== null): ?><span title="Patch due <?= Helpers::e($dl['due']->format('Y-m-d')) ?>"><?= Helpers::e(CePlusDeadline::shortLabel($dl)) ?></span><?php else: ?>—<?php endif; ?></td>
                <td><?= Helpers::e($row['hostname'] ?: $row['ip_address'] ?: 'Unknown host') ?></td>
                <td class="mono"><?= (int)$row['qid'] ?></td>
                <td>
                    <a href="/vulnerability_detail?id=<?= (int)$row['id'] ?>"><?= Helpers::e($row['title']) ?></a>
                    <?php if (!empty($row['is_kev'])): ?>
                    <span class="badge badge-kev" title="On the CISA Known Exploited Vulnerabilities catalogue">KEV</span>
                    <?php endif; ?>
                    <?php if (!empty($row['hidden_state'])): ?>
                    <span class="badge badge-hidden" title="Hidden from your default view, but still counted here">Hidden</span>
                    <?php endif; ?>
                </td>
                <td class="mono col-num"><?= $row['effective_cvss_score'] !== null ? number_format((float)$row['effective_cvss_score'], 1) : 'n/a' ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    </div>
    <?php endif; ?>
</div>

<?php endif; ?>

<?php require __DIR__ . '/../src/views/footer.php'; ?>
