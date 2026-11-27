<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Auth;
use VulnDash\Lib\CePlusDeadline;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\UserRepository;
use VulnDash\Lib\VulnerabilityRepository;

Auth::check();

$tagIds  = Auth::tagIds();
$isAdmin = Auth::isAdmin();
$userId  = Auth::userId();

// Every asset is agent-scoped now (scripts/lib/QualysApiClient.php's agent
// scope filter), so this is just one flat tag list - no more Agent
// Tags/Scans split.
$availableTags   = $isAdmin ? UserRepository::listTags() : UserRepository::getTagsByIds($tagIds);
$availableTagIds = array_map('intval', array_column($availableTags, 'id'));

// Persisted across pages (dashboard <-> assets <-> vulnerabilities) via the
// session - see Helpers::resolveViewTag() for exactly how.
$viewTagId = Helpers::resolveViewTag($availableTagIds);

// Hidden-findings reveal - a per-session, per-account toggle the dashboard's
// "N hidden" chip drives too (see public/dashboard.php). Persisted in
// session, so revealing on the dashboard carries straight through to this
// list. Every account (client or admin) manages its own hides now - see
// src/Lib/HiddenIssueRepository.php - so this is no longer admin-gated; it's
// still named $canManageHidden for minimal churn against the rest of this
// file. When on, hidden findings appear here with a "HIDDEN" chip and can be
// opened and unhidden from their detail page.
$canManageHidden = true;
if (isset($_GET['show_hidden'])) {
    $_SESSION['show_hidden'] = $_GET['show_hidden'] === '1';
}
$showHidden = $canManageHidden && !empty($_SESSION['show_hidden']);

// Drilling into a single asset (from /assets, or a detection's asset
// link) pins the whole page to that one asset. getAssetDetail() checks the
// asset against the caller's tag scope independently of $viewTagId, which
// is only ever a list-page display filter - so once we know which asset
// this is, that check has already happened, and re-applying $viewTagId on
// top would be redundant at best and, if the asset doesn't happen to carry
// whichever tag is currently selected, would produce a confusing "no
// results" for an asset the account is otherwise fully allowed to see.
$assetId = isset($_GET['asset_id']) && $_GET['asset_id'] !== '' ? (int)$_GET['asset_id'] : null;
$assetDetail = $assetId !== null ? VulnerabilityRepository::getAssetDetail($assetId, $tagIds, $isAdmin) : null;
$effectiveViewTagId = $assetDetail !== null ? null : $viewTagId;

if ($assetId !== null && $assetDetail === null) {
    $pageTitle = 'Not found';
    require __DIR__ . '/../src/views/header.php';
    ?>
    <div class="page-heading">
        <h1>Not found</h1>
        <p class="page-subtitle">That asset doesn't exist, or isn't visible to your account.</p>
    </div>
    <p><a class="btn btn-secondary" href="/assets">&larr; Back to assets</a></p>
    <?php
    require __DIR__ . '/../src/views/footer.php';
    exit;
}

$severity   = isset($_GET['severity']) && $_GET['severity'] !== '' ? (int)$_GET['severity'] : null;
// CE+ (Cyber Essentials Plus) only cares about findings with a CVSS >= 7.0,
// i.e. severity 4 (High) or 5 (Critical) - a Medium or Low severity filter
// can never contain a CE+ failure. The checkbox is hidden for those
// severities below, and forced off here too so a stale/hand-built query
// string (e.g. ce_plus_only=1&severity=3) can't sneak the filter back in.
$cePlusAllowedForSeverity = $severity === null || $severity === 5 || $severity === 4;
$cePlusOnly = $cePlusAllowedForSeverity && !empty($_GET['ce_plus_only']);
// CE+ failures past the 14-day patch window (see CePlusDeadline) - the
// target of the dashboard's "CE+ overdue" card. A subset of CE+ failures, so
// the same Medium/Low severity rule applies.
$ceOverdueOnly = $cePlusAllowedForSeverity && !empty($_GET['ce_overdue']);
// Overdue is a subset of CE+ failures, so it implies the CE+ box - set here
// rather than only in the checkbox's onchange, so the dashboard card's plain
// ?ce_overdue=1 link (and a no-JS submit) also lands with both ticked. It
// doesn't change the results: the overdue filter already requires
// is_ce_plus_fail = 1.
$cePlusOnly = $cePlusOnly || $ceOverdueOnly;
// Exploitability filters (see qid_exploit / VulnerabilityRepository). kev=1 is
// also the target of the dashboard's "Known exploited" stat card. min_epss is a
// 0..1 probability floor, offered as a few sensible presets in the UI but
// accepted as any value here and clamped into range.
$kevOnly    = !empty($_GET['kev']);
$minEpss    = isset($_GET['min_epss']) && $_GET['min_epss'] !== '' ? max(0.0, min(1.0, (float)$_GET['min_epss'])) : null;
$page       = max(1, (int)($_GET['page'] ?? 1));
$perPage    = 50;

$search   = isset($_GET['q']) && trim((string)$_GET['q']) !== '' ? trim((string)$_GET['q']) : null;
$sort     = isset($_GET['sort']) && $_GET['sort'] !== '' ? (string)$_GET['sort'] : null;
$dir      = isset($_GET['dir']) && strtolower((string)$_GET['dir']) === 'desc' ? 'desc' : 'asc';
$category = isset($_GET['category']) && $_GET['category'] !== '' ? (string)$_GET['category'] : null;
$os       = isset($_GET['os']) && $_GET['os'] !== '' ? (string)$_GET['os'] : null;
// Exact-QID drill-in from the dashboard's "Top 10 most detected
// vulnerabilities" table (see VulnerabilityRepository::buildFilterWhere()).
$qid      = isset($_GET['qid']) && $_GET['qid'] !== '' ? (int)$_GET['qid'] : null;
// CVE drill-in from the search page's "view in list" link (public/search.php):
// every QID Qualys maps to that CVE. Only a well-formed CVE ID is accepted, so
// anything else is ignored rather than becoming a filter that matches nothing.
$cve      = isset($_GET['cve']) && preg_match('/^CVE-\d{4}-\d{4,7}$/i', (string)$_GET['cve']) === 1 ? strtoupper((string)$_GET['cve']) : null;

// Age-of-finding drill-ins from the Trends page (see the aging matrix and
// "New findings" card in public/trends.php). new_within_days is the rolling
// "appeared in the last N days" window; min_age_days/max_age_days are the
// calendar-day age bounds behind a matrix cell. All are validated to a
// non-negative int here and interpreted in VulnerabilityRepository::
// buildFilterWhere(), which is the single place their day semantics live.
$newWithinDays = isset($_GET['new_within_days']) && $_GET['new_within_days'] !== '' ? max(0, (int)$_GET['new_within_days']) : null;
$minAgeDays    = isset($_GET['min_age_days']) && $_GET['min_age_days'] !== '' ? max(0, (int)$_GET['min_age_days']) : null;
$maxAgeDays    = isset($_GET['max_age_days']) && $_GET['max_age_days'] !== '' ? max(0, (int)$_GET['max_age_days']) : null;

$filters = ['severity' => $severity, 'ce_plus_only' => $cePlusOnly, 'ce_overdue_only' => $ceOverdueOnly, 'kev_only' => $kevOnly, 'min_epss' => $minEpss, 'asset_id' => $assetId, 'search' => $search, 'category' => $category, 'os' => $os, 'qid' => $qid, 'cve' => $cve, 'new_within_days' => $newWithinDays, 'min_age_days' => $minAgeDays, 'max_age_days' => $maxAgeDays];

$detections  = VulnerabilityRepository::getDetections($tagIds, $isAdmin, $filters, $page, $perPage, $effectiveViewTagId, $sort, $dir, $showHidden, $userId);
$totalCount  = VulnerabilityRepository::getDetectionsCount($tagIds, $isAdmin, $filters, $effectiveViewTagId, $showHidden, $userId);

// Chip number for this scope (this account's own hides only). Uses the same
// tag scope as the list (the effective one, which pins to a single asset
// when drilled in).
$hiddenCount = $canManageHidden ? VulnerabilityRepository::countHidden($tagIds, $isAdmin, $effectiveViewTagId, $userId) : 0;

// Toggle link that preserves the current query (filters, sort, page, tag) and
// just flips show_hidden - so revealing/hiding doesn't drop the user's filters.
$hiddenChipQuery = $_GET;
unset($hiddenChipQuery['show_hidden']);
$hiddenChipQuery['show_hidden'] = $showHidden ? '0' : '1';
$hiddenChipHref = '?' . http_build_query($hiddenChipQuery);
$totalPages  = $totalCount > 0 ? (int)ceil($totalCount / $perPage) : 1;

$pageTitle = $assetDetail ? ($assetDetail['hostname'] ?: $assetDetail['ip_address']) : 'Vulnerabilities';
require __DIR__ . '/../src/views/header.php';
?>

<?php if ($assetDetail): ?>
<div class="page-heading detail-heading-row">
    <div>
        <h1><?= Helpers::e($assetDetail['hostname'] ?: $assetDetail['ip_address'] ?: 'Unknown host') ?></h1>
        <p class="page-subtitle">
            <?= Helpers::e($assetDetail['ip_address'] ?: '—') ?><?php if (!empty($assetDetail['os'])): ?> · <?= Helpers::e($assetDetail['os']) ?><?php endif; ?> · showing open findings only (fixed items are excluded)
        </p>
    </div>
    <a class="btn btn-secondary" href="/assets">&larr; Back to assets</a>
</div>
<?php else: ?>
<div class="page-heading">
    <h1>Vulnerabilities</h1>
    <p class="page-subtitle">Showing open findings only (fixed items are excluded).</p>
</div>
<?php endif; ?>

<form method="get" class="filter-bar">
    <?php if ($assetId !== null): ?>
    <input type="hidden" name="asset_id" value="<?= (int)$assetId ?>">
    <?php endif; ?>

    <?php if (!$assetDetail && !empty($availableTags)): ?>
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
        <span>Severity</span>
        <select name="severity" onchange="this.form.submit()">
            <option value="">All</option>
            <option value="5" <?= $severity === 5 ? 'selected' : '' ?>>Critical</option>
            <option value="4" <?= $severity === 4 ? 'selected' : '' ?>>High</option>
            <option value="3" <?= $severity === 3 ? 'selected' : '' ?>>Medium</option>
            <option value="2" <?= $severity === 2 ? 'selected' : '' ?>>Low</option>
        </select>
    </label>

    <?php // CE+ only ever concerns Critical/High findings (CVSS >= 7.0) - hidden
          // for a Medium/Low severity filter, where it could never match anything. ?>
    <?php if ($cePlusAllowedForSeverity): ?>
    <?php // The two boxes are linked: unticking CE+ also clears overdue (which
          // can't apply without it - otherwise the server would re-tick CE+
          // and it would look stuck), and ticking overdue ticks CE+. ?>
    <label class="checkbox-field">
        <input type="checkbox" name="ce_plus_only" value="1" <?= $cePlusOnly ? 'checked' : '' ?> onchange="if (!this.checked) { this.form.elements['ce_overdue'].checked = false; } this.form.submit()">
        <span>CE+ failures only <span class="checkbox-hint">(CVSS &ge; 7.0, excl. zero-days)</span></span>
    </label>

    <label class="checkbox-field">
        <input type="checkbox" name="ce_overdue" value="1" <?= $ceOverdueOnly ? 'checked' : '' ?> onchange="if (this.checked) { this.form.elements['ce_plus_only'].checked = true; } this.form.submit()">
        <span>CE+ overdue only <span class="checkbox-hint">(&gt; <?= CePlusDeadline::PATCH_WINDOW_DAYS ?> days since patch released)</span></span>
    </label>
    <?php endif; ?>

    <label class="checkbox-field">
        <input type="checkbox" name="kev" value="1" <?= $kevOnly ? 'checked' : '' ?> onchange="this.form.submit()">
        <span>Known exploited only <span class="checkbox-hint">(CISA KEV)</span></span>
    </label>

    <label class="field field-inline">
        <span>EPSS</span>
        <select name="min_epss" onchange="this.form.submit()">
            <option value="">Any</option>
            <?php foreach (['0.5' => '&ge; 50%', '0.1' => '&ge; 10%', '0.01' => '&ge; 1%'] as $val => $lbl): ?>
            <option value="<?= $val ?>" <?= ($minEpss !== null && abs($minEpss - (float)$val) < 0.0000001) ? 'selected' : '' ?>><?= $lbl ?></option>
            <?php endforeach; ?>
        </select>
    </label>

    <label class="field field-inline">
        <span>Search</span>
        <span class="search-input-wrap">
            <input type="text" name="q" class="search-debounce-input" value="<?= Helpers::e($search ?? '') ?>" placeholder="Title, hostname, QID…" autocomplete="off">
            <button type="button" class="search-clear" aria-label="Clear search" title="Clear search" <?= ($search === null || $search === '') ? 'hidden' : '' ?>>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
            </button>
        </span>
    </label>

    <noscript><button type="submit" class="btn btn-secondary">Apply</button></noscript>
</form>

<div class="result-count-row">
    <p class="result-count"><?= number_format($totalCount) ?> result<?= $totalCount === 1 ? '' : 's' ?></p>
    <?php
    // Same reveal chip as the dashboard, mirrored here so it's clear why hidden
    // rows appear (or that some are being suppressed) and can be toggled without
    // going back to the dashboard. Preserves the current filters.
    if ($canManageHidden && ($hiddenCount > 0 || $showHidden)):
    ?>
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
    <?php endif; ?>
</div>

<?php
// A human-readable label for whichever age drill-in (if any) is active, shown
// as a single chip rather than one per bound - the two bounds describe one
// age band and read better together. Mirrors the Trends aging-matrix columns.
$ageChipLabel = null;
if ($newWithinDays !== null) {
    $ageChipLabel = 'First seen: last ' . $newWithinDays . ' day' . ($newWithinDays === 1 ? '' : 's');
} elseif ($minAgeDays !== null && $maxAgeDays !== null) {
    $ageChipLabel = 'Age: ' . $minAgeDays . '–' . $maxAgeDays . ' days';
} elseif ($maxAgeDays !== null) {
    $ageChipLabel = 'Age: ' . $maxAgeDays . ' days or less';
} elseif ($minAgeDays !== null) {
    // min_age_days = N means "at least N days old", i.e. older than N-1 days -
    // phrase it that way so "91" reads as the "over 90 days" bucket it came from.
    $ageChipLabel = 'Age: over ' . max(0, $minAgeDays - 1) . ' days';
}
?>
<?php if ($category !== null || $os !== null || $qid !== null || $cve !== null || $ageChipLabel !== null || $kevOnly || $minEpss !== null): ?>
<p class="active-filter-chips">
    <?php if ($qid !== null):
        $clearQidQuery = $_GET;
        unset($clearQidQuery['qid'], $clearQidQuery['page']);
    ?>
    <span class="filter-chip">QID: <?= (int)$qid ?> <a href="?<?= Helpers::e(http_build_query($clearQidQuery)) ?>" aria-label="Clear QID filter" title="Clear QID filter">&times;</a></span>
    <?php endif; ?>
    <?php if ($cve !== null):
        $clearCveQuery = $_GET;
        unset($clearCveQuery['cve'], $clearCveQuery['page']);
    ?>
    <span class="filter-chip">CVE: <?= Helpers::e($cve) ?> <a href="?<?= Helpers::e(http_build_query($clearCveQuery)) ?>" aria-label="Clear CVE filter" title="Clear CVE filter">&times;</a></span>
    <?php endif; ?>
    <?php if ($kevOnly):
        $clearKevQuery = $_GET;
        unset($clearKevQuery['kev'], $clearKevQuery['page']);
    ?>
    <span class="filter-chip">Known exploited (KEV) <a href="?<?= Helpers::e(http_build_query($clearKevQuery)) ?>" aria-label="Clear KEV filter" title="Clear KEV filter">&times;</a></span>
    <?php endif; ?>
    <?php if ($minEpss !== null):
        $clearEpssQuery = $_GET;
        unset($clearEpssQuery['min_epss'], $clearEpssQuery['page']);
    ?>
    <span class="filter-chip">EPSS &ge; <?= rtrim(rtrim(number_format($minEpss * 100, 1), '0'), '.') ?>% <a href="?<?= Helpers::e(http_build_query($clearEpssQuery)) ?>" aria-label="Clear EPSS filter" title="Clear EPSS filter">&times;</a></span>
    <?php endif; ?>
    <?php if ($ageChipLabel !== null):
        // One clear link drops all three age params (only one family is ever
        // set at a time) plus page, exactly like the other chips.
        $clearAgeQuery = $_GET;
        unset($clearAgeQuery['new_within_days'], $clearAgeQuery['min_age_days'], $clearAgeQuery['max_age_days'], $clearAgeQuery['page']);
    ?>
    <span class="filter-chip"><?= Helpers::e($ageChipLabel) ?> <a href="?<?= Helpers::e(http_build_query($clearAgeQuery)) ?>" aria-label="Clear age filter" title="Clear age filter">&times;</a></span>
    <?php endif; ?>
    <?php if ($category !== null):
        $clearCategoryQuery = $_GET;
        unset($clearCategoryQuery['category'], $clearCategoryQuery['page']);
    ?>
    <span class="filter-chip">Category: <?= Helpers::e($category) ?> <a href="?<?= Helpers::e(http_build_query($clearCategoryQuery)) ?>" aria-label="Clear category filter" title="Clear category filter">&times;</a></span>
    <?php endif; ?>
    <?php if ($os !== null):
        $clearOsQuery = $_GET;
        unset($clearOsQuery['os'], $clearOsQuery['page']);
    ?>
    <span class="filter-chip">OS: <?= Helpers::e($os) ?> <a href="?<?= Helpers::e(http_build_query($clearOsQuery)) ?>" aria-label="Clear OS filter" title="Clear OS filter">&times;</a></span>
    <?php endif; ?>
</p>
<?php endif; ?>

<div class="table-wrap">
<table class="vuln-table">
    <thead>
        <tr>
            <?php if (!$assetDetail): ?><th><?= Helpers::sortLink('Asset', 'asset', $sort, $dir) ?></th><?php endif; ?>
            <th><?= Helpers::sortLink('QID', 'qid', $sort, $dir) ?></th>
            <th><?= Helpers::sortLink('Title', 'title', $sort, $dir) ?></th>
            <th><?= Helpers::sortLink('Severity', 'severity', $sort, $dir) ?></th>
            <th><?= Helpers::sortLink('CVSS', 'cvss', $sort, $dir) ?></th>
            <th><?= Helpers::sortLink('EPSS', 'epss', $sort, $dir) ?></th>
            <th title="CE+ 14-day patch deadline, counted from when the vendor released the patch"><?= Helpers::sortLink('CE+ due', 'ce_due', $sort, $dir) ?></th>
            <th><?= Helpers::sortLink('Status', 'status', $sort, $dir) ?></th>
            <th><?= Helpers::sortLink('Port', 'port', $sort, $dir) ?></th>
            <th><?= Helpers::sortLink('Last found', 'last_found', $sort, $dir) ?></th>
        </tr>
    </thead>
    <tbody>
        <?php if (empty($detections)): ?>
        <tr class="empty-row"><td colspan="<?= $assetDetail ? 9 : 10 ?>">No vulnerabilities match the current filters.</td></tr>
        <?php else: foreach ($detections as $row):
            $ceDeadline = CePlusDeadline::forRow($row);
        ?>
        <tr class="<?= Helpers::severityCssClass((int)$row['severity_level']) ?>-row">
            <?php if (!$assetDetail): ?><td><?= Helpers::e($row['hostname'] ?: $row['ip_address']) ?></td><?php endif; ?>
            <td class="mono"><?= (int)$row['qid'] ?></td>
            <td>
                <a href="/vulnerability_detail?id=<?= (int)$row['id'] ?>"><?= Helpers::e($row['title']) ?></a>
                <?php if (!empty($row['is_kev'])): ?>
                <span class="badge badge-kev" title="On the CISA Known Exploited Vulnerabilities catalogue — confirmed exploited in the wild<?= !empty($row['kev_ransomware']) ? '; linked to known ransomware campaigns' : '' ?>">KEV</span>
                <?php endif; ?>
                <?php if (($row['detection_type'] ?? null) === 'Potential'): ?>
                <span class="badge badge-potential" title="Qualys flagged this as a potential finding it could not fully confirm">Potential</span>
                <?php endif; ?>
                <?php // hidden_state is only ever set on a returned row when hidden findings are being revealed (see hiddenStateSelect()). ?>
                <?php if (!empty($row['hidden_state'])): ?>
                <span class="badge badge-hidden" title="This finding is hidden from your default view - open it to unhide">
                    Hidden · <?= (int)$row['hidden_state'] === 2 ? 'Mine' : 'This asset' ?>
                </span>
                <?php endif; ?>
            </td>
            <td><span class="badge <?= Helpers::severityCssClass((int)$row['severity_level']) ?>"><?= Helpers::severityLabel((int)$row['severity_level']) ?></span></td>
            <td class="mono"><?= $row['effective_cvss_score'] !== null ? number_format((float)$row['effective_cvss_score'], 1) : 'n/a' ?></td>
            <td class="mono" title="<?= isset($row['max_epss']) && $row['max_epss'] !== null ? Helpers::e(Helpers::epssTooltip((float)$row['max_epss'])) : 'No EPSS score' ?>"><?= isset($row['max_epss']) && $row['max_epss'] !== null ? Helpers::e(Helpers::epssPercent((float)$row['max_epss'])) : '—' ?></td>
            <?php // Only CE+ failures carry a deadline; '—' for everything else, and for a CE+ failure with no clock (no vendor patch yet, or no date). ?>
            <td class="mono"><?php if ($ceDeadline === null): ?>—<?php elseif ($ceDeadline['overdue']): ?><span class="badge badge-ce-fail" title="Patch was due <?= Helpers::e($ceDeadline['due']->format('Y-m-d')) ?>"><?= Helpers::e(CePlusDeadline::shortLabel($ceDeadline)) ?></span><?php else: ?><span title="Patch due <?= Helpers::e($ceDeadline['due']->format('Y-m-d')) ?>"><?= Helpers::e(CePlusDeadline::shortLabel($ceDeadline)) ?></span><?php endif; ?></td>
            <td><?= Helpers::e($row['status']) ?></td>
            <td class="mono"><?= $row['port'] !== null ? (int)$row['port'] : '—' ?></td>
            <td class="mono"><?= Helpers::e(Helpers::displayQualysDateTime($row['last_found'])) ?></td>
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

<?php require __DIR__ . '/../src/views/footer.php'; ?>
