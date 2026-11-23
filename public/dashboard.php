<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Auth;
use VulnDash\Lib\CePlusDeadline;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\StaleAgent;
use VulnDash\Lib\SyncStatusRepository;
use VulnDash\Lib\UserRepository;
use VulnDash\Lib\VulnerabilityRepository;

Auth::check();

$tagIds  = Auth::tagIds();
$isAdmin = Auth::isAdmin();
$userId  = Auth::userId();

// Tags this account is allowed to filter by - every tag for an admin, only
// their own assigned tags for a client account.
//
// Every asset is agent-scoped now (scripts/lib/QualysApiClient.php's agent
// scope filter), so this is just one flat tag list - no more Agent
// Tags/Scans split (mirrors assets.php / vulnerabilities.php).
$availableTags   = $isAdmin ? UserRepository::listTags() : UserRepository::getTagsByIds($tagIds);
$availableTagIds = array_map('intval', array_column($availableTags, 'id'));

// Persisted across pages (dashboard <-> assets <-> vulnerabilities) via the
// session - see Helpers::resolveViewTag() for exactly how.
$viewTagId = Helpers::resolveViewTag($availableTagIds);

// Hidden-findings reveal toggle. Every account (client or admin) manages its
// own hides now - see src/Lib/HiddenIssueRepository.php - so this is no
// longer admin-gated; it's still named $canManageHidden for minimal churn
// against the rest of this file. The reveal is a per-session view preference
// (like the tag filter) toggled by the "N hidden" chip below - it changes
// what THIS account sees on the dashboard and the vulnerability list, never
// anyone else's. ?show_hidden=1/0 on the current request updates and
// persists the preference; absent, the stored value stands. See
// VulnerabilityRepository::countHidden() / hiddenExclusionSql().
$canManageHidden = true;
if (isset($_GET['show_hidden'])) {
    $_SESSION['show_hidden'] = $_GET['show_hidden'] === '1';
}
$showHidden = $canManageHidden && !empty($_SESSION['show_hidden']);

$severityCounts   = VulnerabilityRepository::getSeverityCounts($tagIds, $isAdmin, $viewTagId, $showHidden, $userId);
$assetCount       = VulnerabilityRepository::getAssetCount($tagIds, $isAdmin, $viewTagId);
$cePlusFailCount  = VulnerabilityRepository::getCePlusFailCount($tagIds, $isAdmin, $viewTagId, $showHidden, $userId);
// CE+ failures past the 14-day patch window (see CePlusDeadline) - the
// "CE+ overdue" card, equal by construction to the ?ce_overdue=1 list it
// links to.
$cePlusOverdueCount = VulnerabilityRepository::getCePlusOverdueCount($tagIds, $isAdmin, $viewTagId, $showHidden, $userId);
// Assets whose agent hasn't reported within StaleAgent's threshold - their
// findings may be out of date. Equal by construction to /assets?stale=1.
$staleAssetCount  = VulnerabilityRepository::getStaleAssetCount($tagIds, $isAdmin, $viewTagId);
$kevCount         = VulnerabilityRepository::getKevCount($tagIds, $isAdmin, $viewTagId, $showHidden, $userId);
$totalOpenVulns   = array_sum($severityCounts);

// Headline risk score for the current scope - drives the analog gauge at the
// top of the page (src/views/risk_gauge.php). Same scope and hidden-state as
// the severity cards, so the gauge and the numbers beneath it always agree.
$riskScore        = VulnerabilityRepository::getRiskScore($tagIds, $isAdmin, $viewTagId, $showHidden, $userId);

// How many findings this account has hidden in this scope - the chip's
// number. Independent of the reveal toggle (it counts the hide rules, not
// the display state).
$hiddenCount    = $canManageHidden ? VulnerabilityRepository::countHidden($tagIds, $isAdmin, $viewTagId, $userId) : 0;

$categoryCounts = VulnerabilityRepository::getCategoryCounts($tagIds, $isAdmin, $viewTagId, $showHidden, $userId);
$osCounts       = VulnerabilityRepository::getOsCounts($tagIds, $isAdmin, $viewTagId, $showHidden, $userId);
$vulnHistory    = VulnerabilityRepository::getVulnHistory($tagIds, $isAdmin, $viewTagId, 30);

// Same tag scope as every chart above, so this table re-scopes in lockstep
// with the Tags dropdown - see VulnerabilityRepository::getTopVulnerabilities().
$topVulns       = VulnerabilityRepository::getTopVulnerabilities($tagIds, $isAdmin, $viewTagId, 10, $showHidden, $userId);

// Whatever's currently selected in the Tags dropdown needs to carry
// forward onto every chart's click-through link below, so clicking a
// severity bar or a donut segment lands on vulnerabilities.php still
// scoped to the same tag rather than silently widening back out to
// everything.
$tagQuery = [];
if (isset($_GET['view_tag']) && $_GET['view_tag'] !== '') {
    $tagQuery['view_tag'] = $_GET['view_tag'];
}

// ------------------------------------------------------------------
// Findings by severity - bar chart geometry
// ------------------------------------------------------------------
$severityBarDefs = [
    5 => ['label' => 'Critical', 'class' => 'sev-critical'],
    4 => ['label' => 'High',     'class' => 'sev-high'],
    3 => ['label' => 'Medium',   'class' => 'sev-medium'],
    2 => ['label' => 'Low',      'class' => 'sev-low'],
];
$severityChartMax = Helpers::niceCeil(max($severityCounts));

$severityChartW = 700;
$severityChartH = 220;
// Top of the plot area. Deliberately not 0/near-0: the value label for each
// bar is drawn 6px above the bar top, so the *tallest* bar (which reaches
// exactly $severityPlotTop) needs enough clear space above it for that label
// to render inside the viewBox. At 10 the "4" over the highest bar was drawn
// at y=4 and clipped off the top edge by the scroll wrapper; 28 reserves room
// for a 12px label plus its gap regardless of the data.
$severityPlotTop = 28;
$severityPlotBottom = 180;
$severityPlotLeft = 50;
$severityPlotRight = 680;
$severitySlotW = ($severityPlotRight - $severityPlotLeft) / 4;
$severityBarW = $severitySlotW * 0.5;

$severityBars = [];
$i = 0;
foreach ($severityBarDefs as $level => $def) {
    $count = $severityCounts[$level];
    $slotCenter = $severityPlotLeft + $severitySlotW * $i + $severitySlotW / 2;
    $barHeight = $severityChartMax > 0 ? ($count / $severityChartMax) * ($severityPlotBottom - $severityPlotTop) : 0;
    $severityBars[] = [
        'level'  => $level,
        'label'  => $def['label'],
        'class'  => $def['class'],
        'count'  => $count,
        'x'      => $slotCenter - $severityBarW / 2,
        'y'      => $severityPlotBottom - $barHeight,
        'width'  => $severityBarW,
        'height' => $barHeight,
        'labelX' => $slotCenter,
        'href'   => '/vulnerabilities?' . http_build_query($tagQuery + ['severity' => $level]),
    ];
    $i++;
}

// ------------------------------------------------------------------
// Findings by category / operating system - donut chart geometry
// ------------------------------------------------------------------
$donutPalette = ['#3FC6B8', '#6C8DE0', '#C77DD2', '#E0A93F', '#5FAE5F', '#D97A9E', '#B0855A', '#7C93A6', '#4FA8D8', '#D8735B'];

/**
 * Builds the stroke-dasharray/dashoffset for each slice of a donut chart
 * (the "several overlapping circles, each showing only an arc of its
 * stroke" technique - much simpler to hand-compute than real arc <path>
 * geometry, and just as accurate for a full ring).
 *
 * @param array<int, array<string, mixed>> $rows
 * @return array{slices: array<int, array<string, mixed>>, total: int}
 */
$buildDonut = static function (array $rows, string $labelKey, string $filterParam, array $tagQuery) use ($donutPalette): array {
    $total = array_sum(array_column($rows, 'total'));
    $radius = 70;
    $circumference = 2 * M_PI * $radius;
    $cumulative = 0;
    $slices = [];
    foreach ($rows as $idx => $row) {
        $count = (int)$row['total'];
        $fraction = $total > 0 ? $count / $total : 0;
        $length = $fraction * $circumference;
        $slices[] = [
            'label'       => $row[$labelKey],
            'count'       => $count,
            'pct'         => $total > 0 ? round($fraction * 100) : 0,
            'color'       => $donutPalette[$idx % count($donutPalette)],
            'dasharray'   => sprintf('%.3f %.3f', $length, $circumference),
            'dashoffset'  => sprintf('%.3f', -$cumulative),
            'href'        => '/vulnerabilities?' . http_build_query($tagQuery + [$filterParam => $row[$labelKey]]),
        ];
        $cumulative += $length;
    }
    return ['slices' => $slices, 'total' => $total];
};

$categoryDonut = $buildDonut($categoryCounts, 'category', 'category', $tagQuery);
$osDonut = $buildDonut($osCounts, 'os', 'os', $tagQuery);

// ------------------------------------------------------------------
// Vulnerability posture - line chart geometry
// ------------------------------------------------------------------
$historyValues = array_filter($vulnHistory, static fn($v) => $v !== null);
$historyMax = Helpers::niceCeil(!empty($historyValues) ? max($historyValues) : 0);

$lineChartW = 900;
$linePlotTop = 10;
$linePlotBottom = 190;
$linePlotLeft = 45;
$linePlotRight = 880;
$dayCount = count($vulnHistory);
$dayIndexes = array_keys($vulnHistory);

$linePoints = [];
$idx = 0;
foreach ($vulnHistory as $date => $value) {
    if ($value !== null) {
        $x = $linePlotLeft + ($dayCount > 1 ? ($idx / ($dayCount - 1)) * ($linePlotRight - $linePlotLeft) : 0);
        $y = $historyMax > 0 ? $linePlotBottom - ($value / $historyMax) * ($linePlotBottom - $linePlotTop) : $linePlotBottom;
        $linePoints[] = [
            'x'     => round($x, 2),
            'y'     => round($y, 2),
            'date'  => $date,
            'label' => (new DateTimeImmutable($date))->format('j M'),
            'value' => $value,
        ];
    }
    $idx++;
}

$lineLinePath = '';
$lineAreaPath = '';
if (!empty($linePoints)) {
    $coords = array_map(static fn($p) => "{$p['x']},{$p['y']}", $linePoints);
    $lineLinePath = 'M ' . implode(' L ', $coords);
    $first = $linePoints[0];
    $last = $linePoints[count($linePoints) - 1];
    $lineAreaPath = 'M ' . $first['x'] . ',' . $linePlotBottom
        . ' L ' . implode(' L ', $coords)
        . ' L ' . $last['x'] . ',' . $linePlotBottom
        . ' Z';
}

// x-axis date labels: showing all 30 would overlap, so space them out to
// roughly 6-7 labels across the width regardless of how many real (non-gap)
// points there are.
$lineLabelStep = max(1, (int)ceil($dayCount / 6));
$lineAxisLabels = [];
foreach (array_values($vulnHistory) as $i => $value) {
    if ($i % $lineLabelStep === 0 || $i === $dayCount - 1) {
        $date = $dayIndexes[$i];
        $x = $linePlotLeft + ($dayCount > 1 ? ($i / ($dayCount - 1)) * ($linePlotRight - $linePlotLeft) : 0);
        $lineAxisLabels[] = ['x' => round($x, 2), 'label' => (new DateTimeImmutable($date))->format('j M')];
    }
}

// ------------------------------------------------------------------
// Chart panel controls (full-screen expand / close)
// ------------------------------------------------------------------
// Emits the pair of buttons that sit at the right-hand end of a chart
// panel's header, immediately after its hint text ("Click a bar to
// filter" etc): the "expand to full screen" control, and the matching
// "close" that takes its place while that panel is expanded. Both are
// rendered here and only toggled at runtime by the full-screen script in
// src/views/footer.php - that script is also what un-hides the expand
// button on load, so a browser with JavaScript disabled never renders a
// control that can't do anything rather than showing a dead button.
//
// A closure rather than four near-identical copies of this markup: the
// icons and structure are the same for every chart and only the chart's
// name differs - and that name has to differ, because four identically
// labelled icon buttons on one page are indistinguishable to a screen
// reader, which is the entire accessible name these buttons have.
$chartPanelControls = static function (string $chartName): void {
    ?>
    <button type="button" class="chart-expand" data-chart-expand
            title="Full screen"
            aria-label="<?= Helpers::e('Show ' . $chartName . ' full screen') ?>" hidden>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <polyline points="15 3 21 3 21 9"></polyline>
            <polyline points="9 21 3 21 3 15"></polyline>
            <line x1="21" y1="3" x2="14" y2="10"></line>
            <line x1="3" y1="21" x2="10" y2="14"></line>
        </svg>
    </button>
    <button type="button" class="chart-close" data-chart-close
            title="Close full screen"
            aria-label="<?= Helpers::e('Close the full screen view of ' . $chartName) ?>" hidden>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <line x1="18" y1="6" x2="6" y2="18"></line>
            <line x1="6" y1="6" x2="18" y2="18"></line>
        </svg>
    </button>
    <?php
};

// Operational, not tenant data - admin only, same as Manage Users.
$syncStatuses = $isAdmin ? SyncStatusRepository::getSyncStatuses() : [];

$pageTitle = 'Dashboard';
require __DIR__ . '/../src/views/header.php';
?>

<div class="dashboard-hero">
    <!-- Plainsight Security logo. The asset is a dark-on-white JPEG, so it
         sits on its own white "plate" (see .dashboard-logo-plate) to look
         intentional against the dark theme rather than as a bare white
         rectangle; the plate reads fine on the light theme too. width/height
         are the image's real pixels (aspect ratio) so the browser reserves
         space before it loads - CSS caps the displayed height. -->
    <div class="dashboard-logo-plate">
        <img class="dashboard-logo" src="/assets/img/logo-full.jpg" alt="Plainsight Security" width="980" height="588">
    </div>
    <div class="page-heading dashboard-hero-heading">
        <h1>Dashboard</h1>
        <p class="page-subtitle">
            Current open exposure<?= !$isAdmin ? ' for your assigned assets' : ' across all assets' ?><?= $viewTagId !== null ? ', filtered to one tag' : '' ?>.
        </p>
    </div>
</div>

<?php
// Plain-English posture summary. Purely presentational: every figure here is
// the same scoped value the stat grid and charts below already use
// ($severityCounts, $assetCount, $cePlusFailCount, $totalOpenVulns), just
// restated as one sentence so the headline reads in words. Numbers are ints
// echoed directly (no escaping needed); the CE+ clause is dropped when nothing
// fails, and the whole thing collapses to a clean "no findings" line at zero.
$postureTagSuffix = $viewTagId !== null ? ' in this tag' : '';
?>
<p class="dashboard-posture">
    <?php if ($totalOpenVulns === 0): ?>
    No open findings across <strong><?= number_format($assetCount) ?></strong> asset<?= $assetCount === 1 ? '' : 's' ?><?= $postureTagSuffix ?>.
    <?php else: ?>
    <strong><?= number_format($totalOpenVulns) ?></strong> open finding<?= $totalOpenVulns === 1 ? '' : 's' ?> across <strong><?= number_format($assetCount) ?></strong> asset<?= $assetCount === 1 ? '' : 's' ?><?= $postureTagSuffix ?> — <strong><?= number_format($severityCounts[5]) ?></strong> critical, <strong><?= number_format($severityCounts[4]) ?></strong> high<?php if ($cePlusFailCount > 0): ?>, <strong><?= number_format($cePlusFailCount) ?></strong> failing Cyber Essentials Plus<?php endif; ?>.
    <?php endif; ?>
</p>

<?php if (!empty($syncStatuses)): ?>
<div class="sync-status-grid">
    <?php foreach ($syncStatuses as $sync): ?>
    <div class="sync-status-card sync-status-<?= Helpers::e($sync['state']) ?>">
        <div class="sync-status-header">
            <span class="sync-status-dot"></span>
            <span class="sync-status-label"><?= Helpers::e($sync['label']) ?></span>
        </div>
        <div class="sync-status-detail">
            <?php if ($sync['state'] === 'never_run'): ?>
                Never run yet.
            <?php elseif ($sync['state'] === 'failed'): ?>
                <?php
                // A failed KB sync can still have written thousands of records
                // before stopping at the API budget (see the 2026-11 notes in
                // scripts/sync_knowledge_base.php), so say so - "failed" alone
                // reads as "nothing happened". Runs from before that change
                // recorded 0, so they show exactly as before.
                ?>
                Last attempt failed <?= Helpers::e(Helpers::relativeTime($sync['last_started_at'])) ?><?php if ((int)($sync['records_processed'] ?? 0) > 0): ?>, after writing <?= number_format((int)$sync['records_processed']) ?> record<?= (int)$sync['records_processed'] === 1 ? '' : 's' ?><?php endif; ?>: <?= Helpers::e($sync['last_error_message'] ?: 'no error message recorded') ?>
            <?php elseif ($sync['state'] === 'stuck'): ?>
                Still marked "running" since <?= Helpers::e(Helpers::relativeTime($sync['last_started_at'])) ?> - longer than a normal run should take. Either the process is still alive but stuck (check with ps; it will be holding the sync's lock, so later runs skip), or it died without closing its sync_log row (the lock file itself is harmless - the lock is released when the process exits).
            <?php elseif ($sync['state'] === 'running'): ?>
                Currently running (started <?= Helpers::e(Helpers::relativeTime($sync['last_started_at'])) ?>).
            <?php elseif ($sync['state'] === 'overdue'): ?>
                Overdue - last success was <?= Helpers::e(Helpers::relativeTime($sync['last_success_at'])) ?>.
            <?php else: ?>
                Last success <?= Helpers::e(Helpers::relativeTime($sync['last_success_at'])) ?><?php if ($sync['records_processed'] !== null): ?> (<?= (int)$sync['records_processed'] ?> processed)<?php endif; ?>
            <?php endif; ?>
        </div>
        <?php if (!empty($sync['missing_kb_qids'])): ?>
        <?php
        // QIDs reported on agents but missing from the local KB, so those
        // findings aren't shown - see MissingKbQidRepository. A short wait
        // for the next KB sync is normal; past the threshold the card turns
        // amber ('warning') and the fix command is the useful part.
        $missingQids = $sync['missing_kb_qids'];
        $oldestMissing = $missingQids[0];
        $missingIdList = implode(',', array_slice(array_column($missingQids, 'qid'), 0, 50));
        ?>
        <div class="sync-status-note">
            <?= count($missingQids) ?> QID<?= count($missingQids) === 1 ? '' : 's' ?> reported by agents <?= count($missingQids) === 1 ? 'is' : 'are' ?> not in the local KnowledgeBase, so <?= count($missingQids) === 1 ? 'its findings are' : 'their findings are' ?> not shown
            (<?= Helpers::e(implode(', ', array_map(static fn(array $m): string => (string)$m['qid'], array_slice($missingQids, 0, 5)))) ?><?= count($missingQids) > 5 ? ', …' : '' ?>; oldest first seen <?= Helpers::e(Helpers::relativeTime($oldestMissing['first_seen'])) ?>).
            <?php
            $refused = array_values(array_filter($missingQids, static fn(array $m): bool => $m['fetch_attempts'] > 0));
            ?>
            <?php if ($refused !== []): ?>
            Qualys didn't return <?= count($refused) === count($missingQids) ? (count($refused) === 1 ? 'it' : 'them') : count($refused) . ' of them' ?>
            when the daily fetch asked (<?= Helpers::e(implode(', ', array_map(static fn(array $m): string => (string)$m['qid'], array_slice($refused, 0, 5)))) ?><?= count($refused) > 5 ? ', …' : '' ?>;
            last tried <?= Helpers::e(Helpers::relativeTime(max(array_column($refused, 'last_fetch_at')))) ?>) - likely not visible to this subscription, or retired. Check with
            <code class="mono">php scripts/diagnose_kb.php --qid=<?= Helpers::e(implode(',', array_slice(array_column($refused, 'qid'), 0, 50))) ?></code>
            <?php elseif ($sync['state'] === 'warning'): ?>
            Waiting over <?= (int)$sync['kb_missing_warn_hours'] ?> hours, so the daily <code class="mono">fetch_missing_kb_qids.php</code> job doesn't seem to be running. Fetch now with
            <code class="mono">php scripts/diagnose_kb.php --qid=<?= Helpers::e($missingIdList) ?> --fix</code>
            <?php else: ?>
            Fetched automatically by the daily KB gap job - nothing to do.
            <?php endif; ?>
        </div>
        <?php endif; ?>
        <?php if ($sync['last_success_at']): ?>
        <div class="sync-status-timestamp mono"><?= Helpers::e(Helpers::displayDateTime($sync['last_success_at'])) ?></div>
        <?php endif; ?>
    </div>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<?php if (!empty($availableTags)): ?>
<form method="get" class="filter-bar">
    <label class="field field-inline">
        <span>Tags</span>
        <select name="view_tag" onchange="this.form.submit();">
            <option value="">All<?= $isAdmin ? ' tags' : ' your tags' ?></option>
            <?php foreach ($availableTags as $tag): ?>
            <option value="<?= (int)$tag['id'] ?>" <?= $viewTagId === (int)$tag['id'] ? 'selected' : '' ?>><?= Helpers::e($tag['name']) ?></option>
            <?php endforeach; ?>
        </select>
    </label>
    <noscript><button type="submit" class="btn btn-secondary">Apply</button></noscript>
</form>
<?php endif; ?>

<?php
// "N hidden" chip. Shown whenever something is hidden in this scope for
// this account, or whenever the reveal is currently on (so it can always be
// switched back off). Clicking toggles the reveal: off -> counts/list
// include hidden findings and mark them; on -> back to the cleaned view.
// Carries the current tag so toggling doesn't widen the scope.
if ($canManageHidden && ($hiddenCount > 0 || $showHidden)):
    $hiddenChipHref = '/dashboard?' . http_build_query($tagQuery + ['show_hidden' => $showHidden ? '0' : '1']);
?>
<div class="hidden-toggle-row">
    <a class="hidden-chip <?= $showHidden ? 'hidden-chip-active' : '' ?>" href="<?= Helpers::e($hiddenChipHref) ?>"
       title="<?= $showHidden ? 'Hidden findings are included below - click to hide them again' : 'Hidden findings are excluded - click to reveal and include them' ?>">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" class="hidden-chip-icon">
            <?php if ($showHidden): ?>
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>
            <?php else: ?>
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>
            <?php endif; ?>
        </svg>
        <span>
            <?php if ($showHidden): ?>
            Showing <strong><?= number_format($hiddenCount) ?></strong> hidden — click to hide
            <?php else: ?>
            <strong><?= number_format($hiddenCount) ?></strong> hidden
            <?php endif; ?>
        </span>
    </a>
</div>
<?php endif; ?>

<?php
// Headline risk gauge - the first thing on the page. $riskScore is in scope
// (computed above), same tag scope / hidden-state as everything below it.
$risk = $riskScore;
require __DIR__ . '/../src/views/risk_gauge.php';
?>

<div class="stat-grid">
    <a class="stat-card stat-card-primary" href="/assets">
        <span class="stat-number"><?= number_format($assetCount) ?></span>
        <span class="stat-label">Assets</span>
    </a>
    <a class="stat-card sev-critical" href="/vulnerabilities?<?= Helpers::e(http_build_query($tagQuery + ['severity' => 5])) ?>">
        <span class="stat-number"><?= number_format($severityCounts[5]) ?></span>
        <span class="stat-label">Critical</span>
    </a>
    <a class="stat-card sev-high" href="/vulnerabilities?<?= Helpers::e(http_build_query($tagQuery + ['severity' => 4])) ?>">
        <span class="stat-number"><?= number_format($severityCounts[4]) ?></span>
        <span class="stat-label">High</span>
    </a>
    <a class="stat-card sev-medium" href="/vulnerabilities?<?= Helpers::e(http_build_query($tagQuery + ['severity' => 3])) ?>">
        <span class="stat-number"><?= number_format($severityCounts[3]) ?></span>
        <span class="stat-label">Medium</span>
    </a>
    <a class="stat-card sev-low" href="/vulnerabilities?<?= Helpers::e(http_build_query($tagQuery + ['severity' => 2])) ?>">
        <span class="stat-number"><?= number_format($severityCounts[2]) ?></span>
        <span class="stat-label">Low</span>
    </a>
    <a class="stat-card stat-card-kev" href="/vulnerabilities?<?= Helpers::e(http_build_query($tagQuery + ['kev' => 1])) ?>" title="Open findings on the CISA Known Exploited Vulnerabilities catalogue">
        <span class="stat-number"><?= number_format($kevCount) ?></span>
        <span class="stat-label">Known exploited</span>
    </a>
    <?php // Reuses the critical stripe rather than a new style: an overdue CE+ failure is a certain assessment failure, the most urgent thing on the page. ?>
    <a class="stat-card sev-critical" href="/vulnerabilities?<?= Helpers::e(http_build_query($tagQuery + ['ce_overdue' => 1])) ?>" title="CE+ failures not patched within <?= CePlusDeadline::PATCH_WINDOW_DAYS ?> days of the vendor releasing the fix">
        <span class="stat-number"><?= number_format($cePlusOverdueCount) ?></span>
        <span class="stat-label">CE+ overdue</span>
    </a>
    <?php // Amber stripe, matching the "Not reporting" badge it leads to. ?>
    <a class="stat-card sev-medium" href="/assets?<?= Helpers::e(http_build_query($tagQuery + ['stale' => 1])) ?>" title="Assets whose agent hasn't reported in over <?= StaleAgent::staleAfterDays() ?> days - their findings may be out of date">
        <span class="stat-number"><?= number_format($staleAssetCount) ?></span>
        <span class="stat-label">Not reporting</span>
    </a>
</div>

<div class="chart-panel">
    <div class="chart-panel-header">
        <h2>Findings by severity</h2>
        <div class="chart-panel-tools">
            <span class="chart-panel-hint">Click a bar to filter</span>
            <?php if ($totalOpenVulns > 0) { $chartPanelControls('the findings by severity chart'); } ?>
        </div>
    </div>
    <?php if ($totalOpenVulns === 0): ?>
    <p class="chart-empty">No open findings<?= $viewTagId !== null ? ' for this tag' : '' ?>.</p>
    <?php else: ?>
    <div class="chart-scroll-x">
    <svg class="bar-chart" viewBox="0 0 <?= $severityChartW ?> <?= $severityChartH ?>" role="img" aria-label="Findings by severity">
        <?php for ($g = 0; $g <= 4; $g++):
            $gy = $severityPlotBottom - ($g / 4) * ($severityPlotBottom - $severityPlotTop);
            $gv = (int)round($severityChartMax * $g / 4);
        ?>
        <line class="chart-gridline" x1="<?= $severityPlotLeft ?>" y1="<?= $gy ?>" x2="<?= $severityPlotRight ?>" y2="<?= $gy ?>"></line>
        <text class="chart-axis-label" x="<?= $severityPlotLeft - 10 ?>" y="<?= $gy + 4 ?>" text-anchor="end"><?= $gv ?></text>
        <?php endfor; ?>

        <?php foreach ($severityBars as $bar): ?>
        <a href="<?= Helpers::e($bar['href']) ?>">
            <rect class="bar-rect <?= Helpers::e($bar['class']) ?>" x="<?= $bar['x'] ?>" y="<?= $bar['y'] ?>" width="<?= $bar['width'] ?>" height="<?= max(0, $bar['height']) ?>" rx="3"></rect>
            <text class="chart-category-label" x="<?= $bar['labelX'] ?>" y="<?= $severityPlotBottom + 20 ?>" text-anchor="middle"><?= Helpers::e($bar['label']) ?></text>
            <?php if ($bar['count'] > 0): ?>
            <text class="bar-value-label" x="<?= $bar['labelX'] ?>" y="<?= $bar['y'] - 6 ?>" text-anchor="middle"><?= $bar['count'] ?></text>
            <?php endif; ?>
        </a>
        <?php endforeach; ?>
    </svg>
    </div>
    <?php endif; ?>
</div>

<div class="chart-panel">
    <div class="chart-panel-header">
        <h2>Vulnerability posture — last 30 days</h2>
        <div class="chart-panel-tools">
            <span class="chart-panel-hint">Total open vulnerabilities per day</span>
            <?php if (!empty($linePoints)) { $chartPanelControls('the vulnerability posture chart'); } ?>
        </div>
    </div>
    <?php if (empty($linePoints)): ?>
    <p class="chart-empty">No history yet - this chart fills in day by day from today onward.</p>
    <?php else: ?>
    <!-- The scroll wrapper is now an INNER element, not the tooltip's parent.
         Previously .line-chart-wrap carried chart-scroll-x itself, which made
         it an overflow:auto box AND the positioning context for the absolutely
         positioned tooltip - so the rightmost day's tooltip spilling past the
         edge produced a stray scrollbar, and the tallest points' tooltips were
         clipped off the top. Keeping the wrap overflow-visible (tooltip anchor)
         and scrolling only the SVG inside it fixes both. -->
    <div class="line-chart-wrap">
      <div class="line-chart-scroll chart-scroll-x">
        <svg class="line-chart" viewBox="0 0 <?= $lineChartW ?> 220" role="img" aria-label="Vulnerability posture over the last 30 days" data-points="<?= Helpers::e(json_encode($linePoints)) ?>">
            <defs>
                <linearGradient id="lineFillGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="var(--signal)" stop-opacity="0.28"></stop>
                    <stop offset="100%" stop-color="var(--signal)" stop-opacity="0"></stop>
                </linearGradient>
            </defs>
            <?php for ($g = 0; $g <= 4; $g++):
                $gy = $linePlotBottom - ($g / 4) * ($linePlotBottom - $linePlotTop);
                $gv = (int)round($historyMax * $g / 4);
            ?>
            <line class="chart-gridline" x1="<?= $linePlotLeft ?>" y1="<?= $gy ?>" x2="<?= $linePlotRight ?>" y2="<?= $gy ?>"></line>
            <text class="chart-axis-label" x="<?= $linePlotLeft - 10 ?>" y="<?= $gy + 4 ?>" text-anchor="end"><?= $gv ?></text>
            <?php endfor; ?>

            <?php foreach ($lineAxisLabels as $label): ?>
            <text class="chart-axis-label" x="<?= $label['x'] ?>" y="<?= $linePlotBottom + 20 ?>" text-anchor="middle"><?= Helpers::e($label['label']) ?></text>
            <?php endforeach; ?>

            <path class="line-area" d="<?= Helpers::e($lineAreaPath) ?>" fill="url(#lineFillGradient)"></path>
            <path class="line-stroke" d="<?= Helpers::e($lineLinePath) ?>" fill="none"></path>

            <circle class="line-hover-dot" r="4" cx="0" cy="0" hidden></circle>
        </svg>
      </div>
        <div class="line-chart-tooltip" hidden></div>
    </div>
    <?php endif; ?>
</div>

<div class="chart-row">
    <div class="chart-panel">
        <div class="chart-panel-header">
            <h2>Findings by category</h2>
            <div class="chart-panel-tools">
                <span class="chart-panel-hint">Click a section to filter</span>
                <?php if ($categoryDonut['total'] > 0) { $chartPanelControls('the findings by category chart'); } ?>
            </div>
        </div>
        <?php if ($categoryDonut['total'] === 0): ?>
        <p class="chart-empty">No open findings<?= $viewTagId !== null ? ' for this tag' : '' ?>.</p>
        <?php else: ?>
        <div class="donut-wrap">
            <svg class="donut-chart" viewBox="0 0 200 200" role="img" aria-label="Findings by category">
                <g transform="rotate(-90 100 100)">
                    <?php foreach ($categoryDonut['slices'] as $slice): ?>
                    <a href="<?= Helpers::e($slice['href']) ?>">
                        <circle class="donut-slice" cx="100" cy="100" r="70" stroke="<?= Helpers::e($slice['color']) ?>"
                            stroke-dasharray="<?= $slice['dasharray'] ?>" stroke-dashoffset="<?= $slice['dashoffset'] ?>"></circle>
                    </a>
                    <?php endforeach; ?>
                </g>
            </svg>
            <ul class="donut-legend">
                <?php foreach ($categoryDonut['slices'] as $slice): ?>
                <li><a href="<?= Helpers::e($slice['href']) ?>"><span class="legend-dot" style="background: <?= Helpers::e($slice['color']) ?>"></span><?= Helpers::e($slice['label']) ?> (<?= $slice['count'] ?>)</a></li>
                <?php endforeach; ?>
            </ul>
        </div>
        <?php endif; ?>
    </div>

    <div class="chart-panel">
        <div class="chart-panel-header">
            <h2>Findings by operating system</h2>
            <div class="chart-panel-tools">
                <span class="chart-panel-hint">Click a section to filter</span>
                <?php if ($osDonut['total'] > 0) { $chartPanelControls('the findings by operating system chart'); } ?>
            </div>
        </div>
        <?php if ($osDonut['total'] === 0): ?>
        <p class="chart-empty">No open findings<?= $viewTagId !== null ? ' for this tag' : '' ?>.</p>
        <?php else: ?>
        <div class="donut-wrap">
            <svg class="donut-chart" viewBox="0 0 200 200" role="img" aria-label="Findings by operating system">
                <g transform="rotate(-90 100 100)">
                    <?php foreach ($osDonut['slices'] as $slice): ?>
                    <a href="<?= Helpers::e($slice['href']) ?>">
                        <circle class="donut-slice" cx="100" cy="100" r="70" stroke="<?= Helpers::e($slice['color']) ?>"
                            stroke-dasharray="<?= $slice['dasharray'] ?>" stroke-dashoffset="<?= $slice['dashoffset'] ?>"></circle>
                    </a>
                    <?php endforeach; ?>
                </g>
            </svg>
            <ul class="donut-legend">
                <?php foreach ($osDonut['slices'] as $slice): ?>
                <li><a href="<?= Helpers::e($slice['href']) ?>"><span class="legend-dot" style="background: <?= Helpers::e($slice['color']) ?>"></span><?= Helpers::e($slice['label']) ?> (<?= $slice['count'] ?>)</a></li>
                <?php endforeach; ?>
            </ul>
        </div>
        <?php endif; ?>
    </div>
</div>

<div class="chart-panel">
    <div class="chart-panel-header">
        <h2>Top 10 most detected vulnerabilities</h2>
        <span class="chart-panel-hint">Click a row to filter</span>
    </div>
    <?php if (empty($topVulns)): ?>
    <p class="chart-empty">No open findings<?= $viewTagId !== null ? ' for this tag' : '' ?>.</p>
    <?php else: ?>
    <div class="table-wrap">
    <table class="vuln-table top-vulns-table">
        <thead>
            <tr>
                <th>QID</th>
                <th>Title</th>
                <th>Severity</th>
                <th class="col-num">Score</th>
                <th class="col-num">Assets</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($topVulns as $vuln):
                $sevLevel = (int)$vuln['severity_level'];
                // Carries whatever tag is currently selected onto the
                // click-through, same as the severity bars and donut
                // segments above - clicking a QID lands on the vulnerability
                // list scoped to that exact QID AND still to this tag,
                // rather than silently widening back out to everything.
                $vulnHref = '/vulnerabilities?' . http_build_query($tagQuery + ['qid' => (int)$vuln['qid']]);
            ?>
            <tr data-href="<?= Helpers::e($vulnHref) ?>">
                <td class="mono"><a href="<?= Helpers::e($vulnHref) ?>"><?= (int)$vuln['qid'] ?></a></td>
                <td>
                    <a href="<?= Helpers::e($vulnHref) ?>"><?= Helpers::e($vuln['title'] !== '' ? $vuln['title'] : ('QID ' . (int)$vuln['qid'])) ?></a>
                    <?php if (!empty($vuln['is_kev'])): ?>
                    <span class="badge badge-kev" title="On the CISA Known Exploited Vulnerabilities catalogue">KEV</span>
                    <?php endif; ?>
                    <?php if (!empty($vuln['is_ce_plus_fail'])): ?>
                    <span class="badge badge-accent" title="Fails Cyber Essentials Plus (effective CVSS 7.0 or above, with a fix available - zero-days are excluded)">CE+</span>
                    <?php endif; ?>
                </td>
                <td><span class="badge <?= Helpers::severityCssClass($sevLevel) ?>"><?= Helpers::severityLabel($sevLevel) ?></span></td>
                <td class="mono col-num"><?= $vuln['max_cvss_score'] !== null ? number_format((float)$vuln['max_cvss_score'], 1) : 'n/a' ?></td>
                <td class="mono col-num"><?= number_format((int)$vuln['asset_count']) ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    </div>
    <?php endif; ?>
</div>

<div class="ce-banner <?= $cePlusFailCount > 0 ? 'ce-banner-fail' : 'ce-banner-pass' ?>">
    <div class="ce-banner-text">
        <strong><?= number_format($cePlusFailCount) ?></strong>
        open finding<?= $cePlusFailCount === 1 ? '' : 's' ?>
        currently fail<?= $cePlusFailCount === 1 ? 's' : '' ?> Cyber Essentials Plus criteria
        <span class="ce-banner-sub">(effective CVSS score of 7.0 or above, excluding zero-days with no fix yet)</span>
    </div>
    <a class="btn btn-danger" href="/vulnerabilities?ce_plus_only=1">View CE+ failures</a>
</div>

<p class="dashboard-all-link"><a class="btn btn-secondary" href="/vulnerabilities">View all <?= number_format($totalOpenVulns) ?> open vulnerabilities →</a></p>

<?php require __DIR__ . '/../src/views/footer.php'; ?>
