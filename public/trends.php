<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Auth;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\UserRepository;
use VulnDash\Lib\VulnerabilityRepository;

Auth::check();

$tagIds  = Auth::tagIds();
$isAdmin = Auth::isAdmin();

// Same tag-scope pattern as dashboard.php/assets.php/vulnerabilities.php - the
// "Tags" dropdown shares the session-persisted view_tag preference (see
// Helpers::resolveViewTag()), so a tag picked here carries over to the other
// pages and vice versa.
$availableTags   = $isAdmin ? UserRepository::listTags() : UserRepository::getTagsByIds($tagIds);
$availableTagIds = array_map('intval', array_column($availableTags, 'id'));
$viewTagId       = Helpers::resolveViewTag($availableTagIds);

// Movement window: a small fixed whitelist, defaulting to 30 days. Validated
// against the whitelist rather than trusted, since it reaches SQL as a day
// count (see getMovementCounts()).
$windowOptions = [7 => 'Last 7 days', 30 => 'Last 30 days', 90 => 'Last 90 days'];
$window = isset($_GET['window']) ? (int)$_GET['window'] : 30;
if (!isset($windowOptions[$window])) {
    $window = 30;
}

$movement = VulnerabilityRepository::getMovementCounts($tagIds, $isAdmin, $viewTagId, $window);
$aging    = VulnerabilityRepository::getAgingBuckets($tagIds, $isAdmin, $viewTagId);
$resolved = VulnerabilityRepository::getRecentlyResolved($tagIds, $isAdmin, $viewTagId, $window, 15);

// Whatever tag is selected must ride along on every click-through so a drill
// into the vulnerability list stays scoped to the same tag rather than
// silently widening back to everything - same rule as the dashboard charts.
$tagQuery = [];
if (isset($_GET['view_tag']) && $_GET['view_tag'] !== '') {
    $tagQuery['view_tag'] = $_GET['view_tag'];
}

/**
 * Age-bucket metadata: the column label plus the exact min/max_age_days
 * filter pair that reproduces this bucket on the vulnerability list. These
 * pairs mirror VulnerabilityRepository::ageBucketCase()'s day boundaries, so
 * a cell's count equals the list it opens (proven by the buildFilterWhere()
 * comment's calendar-day reasoning).
 */
$bucketMeta = [
    0 => ['label' => '0–7 days',   'filters' => ['max_age_days' => 7]],
    1 => ['label' => '8–30 days',  'filters' => ['min_age_days' => 8,  'max_age_days' => 30]],
    2 => ['label' => '31–90 days', 'filters' => ['min_age_days' => 31, 'max_age_days' => 90]],
    3 => ['label' => 'Over 90 days','filters' => ['min_age_days' => 91]],
];

// A cell/row link into the vulnerability list, carrying the current tag plus
// whatever severity/age filters describe that cell.
$vulnLink = static function (array $extra) use ($tagQuery): string {
    return '/vulnerabilities?' . http_build_query($tagQuery + $extra);
};

// "CE+ failures open longer than 30 days" = the 31–90 and over-90 buckets of
// the CE+ overlay. A factual age statement, deliberately NOT phrased as an
// SLA/deadline breach - what counts as "too long" for CE+ is your policy call,
// not something this page should assert.
$cePlusAged = $aging['ce_plus'][2] + $aging['ce_plus'][3];

$hasAnyData = $aging['grand_total'] > 0
    || $movement['new'] > 0 || $movement['resolved'] > 0 || $movement['reopened'] > 0;

$pageTitle = 'Trends';
require __DIR__ . '/../src/views/header.php';
?>

<div class="page-heading">
    <h1>Trends</h1>
    <p class="page-subtitle">What's changed recently, and how long open findings have been outstanding. Open findings only (fixed items are excluded, except where explicitly shown as resolved).</p>
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
    <?php render_view_tag_access_until($availableTags, $viewTagId); ?>
    <?php endif; ?>

    <label class="field field-inline">
        <span>Window</span>
        <select name="window" onchange="this.form.submit();">
            <?php foreach ($windowOptions as $days => $label): ?>
            <option value="<?= (int)$days ?>" <?= $window === $days ? 'selected' : '' ?>><?= Helpers::e($label) ?></option>
            <?php endforeach; ?>
        </select>
    </label>

    <noscript><button type="submit" class="btn btn-secondary">Apply</button></noscript>
</form>

<h2 class="section-heading">Movement <span class="section-heading-sub"><?= Helpers::e($windowOptions[$window]) ?></span></h2>
<div class="stat-grid movement-grid">
    <?php // "New" is the one card that maps cleanly onto the vulnerability
          // list (new_within_days uses the same rolling window as this count),
          // so it's a link; Resolved/Reopened are shown as figures, with the
          // resolved detail available in the "Recently resolved" table below. ?>
    <a class="stat-card movement-card movement-new" href="<?= Helpers::e($vulnLink(['new_within_days' => $window])) ?>">
        <span class="stat-number"><?= number_format($movement['new']) ?></span>
        <span class="stat-label">New findings</span>
        <span class="movement-card-hint">First seen in this window →</span>
    </a>
    <div class="stat-card movement-card movement-resolved">
        <span class="stat-number"><?= number_format($movement['resolved']) ?></span>
        <span class="stat-label">Resolved</span>
        <span class="movement-card-hint">Fixed in this window</span>
    </div>
    <div class="stat-card movement-card movement-reopened">
        <span class="stat-number"><?= number_format($movement['reopened']) ?></span>
        <span class="stat-label">Re-opened</span>
        <span class="movement-card-hint">Returned after a fix</span>
    </div>
</div>

<h2 class="section-heading">Remediation aging <span class="section-heading-sub">open findings by age</span></h2>
<div class="chart-panel">
    <div class="chart-panel-header">
        <h2>Open findings by severity and age</h2>
        <span class="chart-panel-hint">Click a cell to see those findings</span>
    </div>
    <?php if ($aging['grand_total'] === 0): ?>
    <p class="chart-empty">No open findings<?= $viewTagId !== null ? ' for this tag' : '' ?>.</p>
    <?php else: ?>
    <div class="table-wrap">
    <table class="vuln-table aging-matrix">
        <thead>
            <tr>
                <th>Severity</th>
                <?php foreach ($bucketMeta as $b => $meta): ?>
                <th class="col-num"><?= Helpers::e($meta['label']) ?></th>
                <?php endforeach; ?>
                <th class="col-num">Total</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($aging['severities'] as $sev):
                $sevClass = Helpers::severityCssClass($sev);
            ?>
            <tr class="<?= $sevClass ?>-row">
                <td><span class="badge <?= $sevClass ?>"><?= Helpers::severityLabel($sev) ?></span></td>
                <?php foreach ($bucketMeta as $b => $meta):
                    $count = $aging['matrix'][$sev][$b];
                    // Older buckets carry visual weight when non-empty - a
                    // 90-day-old critical should read louder than a 3-day-old
                    // one at a glance. Empty cells stay muted.
                    $cellClass = 'aging-cell';
                    if ($count === 0) {
                        $cellClass .= ' aging-cell-zero';
                    } elseif ($b >= 2) {
                        $cellClass .= ' aging-cell-aged';
                    }
                    $cellHref = $vulnLink(['severity' => $sev] + $meta['filters']);
                ?>
                <td class="col-num <?= $cellClass ?>">
                    <?php if ($count > 0): ?>
                    <a href="<?= Helpers::e($cellHref) ?>"><?= number_format($count) ?></a>
                    <?php else: ?>
                    <span class="mono">0</span>
                    <?php endif; ?>
                </td>
                <?php endforeach; ?>
                <td class="col-num mono aging-total">
                    <?php if ($aging['severity_totals'][$sev] > 0): ?>
                    <a href="<?= Helpers::e($vulnLink(['severity' => $sev])) ?>"><?= number_format($aging['severity_totals'][$sev]) ?></a>
                    <?php else: ?>
                    0
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
        <tfoot>
            <tr class="aging-foot-total">
                <td>All severities</td>
                <?php foreach ($bucketMeta as $b => $meta):
                    $total = $aging['bucket_totals'][$b];
                ?>
                <td class="col-num mono">
                    <?php if ($total > 0): ?>
                    <a href="<?= Helpers::e($vulnLink($meta['filters'])) ?>"><?= number_format($total) ?></a>
                    <?php else: ?>0<?php endif; ?>
                </td>
                <?php endforeach; ?>
                <td class="col-num mono"><?= number_format($aging['grand_total']) ?></td>
            </tr>
            <tr class="aging-foot-ceplus">
                <td>of which CE+ failures</td>
                <?php foreach ($aging['buckets'] as $b): ?>
                <td class="col-num mono"><?= number_format($aging['ce_plus'][$b]) ?></td>
                <?php endforeach; ?>
                <td class="col-num mono"><?= number_format($aging['ce_plus_total']) ?></td>
            </tr>
        </tfoot>
    </table>
    </div>

    <?php if ($cePlusAged > 0): ?>
    <p class="aging-ceplus-note">
        <span class="badge badge-accent" title="Fails Cyber Essentials Plus (effective CVSS 7.0 or above, with a fix available - zero-days are excluded)">CE+</span>
        <strong><?= number_format($cePlusAged) ?></strong>
        CE+ failure<?= $cePlusAged === 1 ? ' has' : 's have' ?> been open longer than 30 days.
        <a href="<?= Helpers::e($vulnLink(['ce_plus_only' => 1, 'min_age_days' => 31])) ?>">Review them →</a>
    </p>
    <?php endif; ?>
    <?php endif; ?>
</div>

<h2 class="section-heading">Recently resolved <span class="section-heading-sub"><?= Helpers::e($windowOptions[$window]) ?></span></h2>
<div class="chart-panel">
    <?php if (empty($resolved)): ?>
    <p class="chart-empty">Nothing resolved in this window<?= $viewTagId !== null ? ' for this tag' : '' ?>.</p>
    <?php else: ?>
    <div class="table-wrap">
    <table class="vuln-table">
        <thead>
            <tr>
                <th>Asset</th>
                <th>QID</th>
                <th>Title</th>
                <th>Severity</th>
                <th class="col-num">CVSS</th>
                <th>Resolved</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($resolved as $row):
                $sevLevel = (int)$row['severity_level'];
            ?>
            <tr>
                <td><?= Helpers::e($row['hostname'] ?: $row['ip_address'] ?: 'Unknown host') ?></td>
                <td class="mono"><?= (int)$row['qid'] ?></td>
                <?php // No detail link here: a resolved finding's detection row has
                      // been deleted (remediation = deletion on this platform), so
                      // there's no live /vulnerability_detail page to point at. ?>
                <td><?= Helpers::e($row['title']) ?></td>
                <td><span class="badge <?= Helpers::severityCssClass($sevLevel) ?>"><?= Helpers::severityLabel($sevLevel) ?></span></td>
                <td class="mono col-num"><?= $row['effective_cvss_score'] !== null ? number_format((float)$row['effective_cvss_score'], 1) : 'n/a' ?></td>
                <td class="mono"><?= Helpers::e(Helpers::displayDateTime($row['resolved_at'])) ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    </div>
    <?php endif; ?>
</div>

<?php if (!$hasAnyData): ?>
<p class="chart-empty">No movement or open findings yet<?= $viewTagId !== null ? ' for this tag' : '' ?> - this page fills in as detections sync and as findings are opened and fixed over time.</p>
<?php endif; ?>

<?php require __DIR__ . '/../src/views/footer.php'; ?>
