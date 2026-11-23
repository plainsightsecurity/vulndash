<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Auth;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\UserRepository;
use VulnDash\Lib\VulnerabilityRepository;

// "Top fixes": which vulnerabilities, patched everywhere they appear, would
// take the most off the risk score. Open findings grouped by QID and ranked
// by the same risk points as the dashboard gauge (CVSS band x KEV/EPSS
// multiplier - see VulnerabilityRepository::riskPointsSql()), so "share of
// risk" here is directly the share of the gauge's points.
Auth::check();

$tagIds  = Auth::tagIds();
$isAdmin = Auth::isAdmin();
$userId  = Auth::userId();

// Same tag-scope pattern and session-persisted `view_tag` as the dashboard.
$availableTags   = $isAdmin ? UserRepository::listTags() : UserRepository::getTagsByIds($tagIds);
$availableTagIds = array_map('intval', array_column($availableTags, 'id'));
$viewTagId       = Helpers::resolveViewTag($availableTagIds);

// Follows the dashboard's per-session "show hidden" toggle, so the score and
// points here are the same ones the gauge is showing right now.
$showHidden = !empty($_SESSION['show_hidden']);

$limitOptions = [25, 50, 100];
$limit = isset($_GET['limit']) && in_array((int)$_GET['limit'], $limitOptions, true) ? (int)$_GET['limit'] : 25;

$risk  = VulnerabilityRepository::getRiskScore($tagIds, $isAdmin, $viewTagId, $showHidden, $userId);
$fixes = VulnerabilityRepository::getTopFixes($tagIds, $isAdmin, $viewTagId, $userId, $limit, $showHidden);

$totalPoints = (float)$risk['risk_points'];

// Headline: what the gauge would read if the top N were fixed everywhere.
// riskScoreFor() is the gauge's own curve, and the asset count stays the
// same (fixing a vulnerability doesn't remove the host).
$headlineN = min(10, count($fixes));
$headlinePoints = array_sum(array_column(array_slice($fixes, 0, $headlineN), 'risk_points'));
$headlinePct = $totalPoints > 0 ? 100 * $headlinePoints / $totalPoints : 0.0;
$scoreAfter = VulnerabilityRepository::riskScoreFor(max(0.0, $totalPoints - $headlinePoints), (int)$risk['assets']);

$tagQuery = $viewTagId !== null ? ['view_tag' => $viewTagId] : [];

$pct = static fn (float $v): string => $v >= 10 ? number_format($v, 0) . '%' : number_format($v, 1) . '%';

$pageTitle = 'Top fixes';
require __DIR__ . '/../src/views/header.php';
?>

<div class="page-heading">
    <h1>Top fixes</h1>
    <p class="page-subtitle">The vulnerabilities that would take the most off your risk score if patched everywhere they appear, ranked by severity, exploitation (CISA KEV and EPSS) and how many assets carry them.</p>
</div>

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
        <span>Show</span>
        <select name="limit" onchange="this.form.submit();">
            <?php foreach ($limitOptions as $opt): ?>
            <option value="<?= $opt ?>" <?= $limit === $opt ? 'selected' : '' ?>>Top <?= $opt ?></option>
            <?php endforeach; ?>
        </select>
    </label>
    <noscript><button type="submit" class="btn btn-secondary">Apply</button></noscript>
</form>

<?php if ($fixes === []): ?>
<div class="panel">
    <p class="chart-empty">No open findings<?= $viewTagId !== null ? ' for this tag' : '' ?> - nothing to fix.</p>
</div>
<?php else: ?>

<div class="report-summary-panel top-fixes-summary">
    <p class="report-summary-line report-summary-count">
        Fixing the top <?= $headlineN ?> would remove <?= $pct($headlinePct) ?> of the risk behind your score,
        taking it from <strong><?= (int)$risk['score'] ?></strong> to about <strong><?= $scoreAfter ?></strong> out of 100.
    </p>
    <p class="report-summary-line">
        Risk points: <?= number_format($totalPoints) ?> across <?= number_format((int)$risk['findings']) ?> open finding<?= (int)$risk['findings'] === 1 ? '' : 's' ?>
        on <?= number_format((int)$risk['assets']) ?> asset<?= (int)$risk['assets'] === 1 ? '' : 's' ?>.
        <?php if ($showHidden): ?>Includes findings you've hidden (the dashboard's "show hidden" is on).<?php endif; ?>
    </p>
</div>

<div class="table-wrap">
<table class="vuln-table top-fixes-table">
    <thead>
        <tr>
            <th class="col-num">#</th>
            <th>QID</th>
            <th>Title</th>
            <th>Severity</th>
            <th class="col-num">CVSS</th>
            <th class="col-num">EPSS</th>
            <th class="col-num">Assets</th>
            <th class="col-share">Share of risk</th>
            <th class="col-num" title="Running total: fixing this row and every row above it">Cumulative</th>
        </tr>
    </thead>
    <tbody>
        <?php
        $cumulative = 0.0;
        foreach ($fixes as $i => $fix):
            $share = $totalPoints > 0 ? 100 * $fix['risk_points'] / $totalPoints : 0.0;
            $cumulative += $share;
            $sevLevel = $fix['severity_level'];
            $href = '/vulnerabilities?' . http_build_query($tagQuery + ['qid' => $fix['qid']]);
        ?>
        <tr data-href="<?= Helpers::e($href) ?>">
            <td class="mono col-num"><?= $i + 1 ?></td>
            <td class="mono"><a href="<?= Helpers::e($href) ?>"><?= $fix['qid'] ?></a></td>
            <td>
                <a href="<?= Helpers::e($href) ?>"><?= Helpers::e($fix['title'] !== '' ? $fix['title'] : 'QID ' . $fix['qid']) ?></a>
                <?php if ($fix['is_kev']): ?>
                <span class="badge badge-kev" title="On the CISA Known Exploited Vulnerabilities catalogue - confirmed exploited in the wild<?= $fix['kev_ransomware'] ? '; linked to known ransomware campaigns' : '' ?>">KEV</span>
                <?php endif; ?>
                <?php if ($fix['is_ce_plus_fail']): ?>
                <span class="badge badge-accent" title="Fails Cyber Essentials Plus (effective CVSS 7.0 or above, with a fix available - zero-days are excluded)">CE+</span>
                <?php endif; ?>
                <?php if ($fix['patchable'] === 0): ?>
                <span class="badge badge-neutral" title="Qualys lists no vendor patch for this one - it may need a configuration change, mitigation or upgrade instead">No patch</span>
                <?php endif; ?>
            </td>
            <td><span class="badge <?= Helpers::severityCssClass($sevLevel) ?>"><?= Helpers::severityLabel($sevLevel) ?></span></td>
            <td class="mono col-num"><?= $fix['max_cvss'] !== null ? number_format($fix['max_cvss'], 1) : 'n/a' ?></td>
            <td class="mono col-num"><?= $fix['max_epss'] !== null ? Helpers::e(Helpers::epssPercent((float)$fix['max_epss'])) : '&mdash;' ?></td>
            <td class="mono col-num" title="<?= number_format($fix['findings']) ?> finding<?= $fix['findings'] === 1 ? '' : 's' ?>"><?= number_format($fix['assets']) ?></td>
            <td class="col-share">
                <span class="share-bar" aria-hidden="true"><span class="share-bar-fill" style="width: <?= number_format(min(100, $share), 1, '.', '') ?>%"></span></span>
                <span class="mono share-value"><?= $pct($share) ?></span>
            </td>
            <td class="mono col-num"><?= $pct(min(100, $cumulative)) ?></td>
        </tr>
        <?php endforeach; ?>
    </tbody>
</table>
</div>

<p class="report-note">Ranked with the same points as the dashboard's risk score: each open finding scores by its CVSS band, multiplied when it's being exploited (on the CISA KEV list, or a high EPSS score). A vulnerability's share is the total across every asset it's open on, so one fix that clears many hosts can outrank a single worse finding. Click a row to see the affected assets.</p>
<?php endif; ?>

<?php require __DIR__ . '/../src/views/footer.php'; ?>
