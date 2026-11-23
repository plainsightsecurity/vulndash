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
$userId  = Auth::userId();

// Same tag-scope pattern as dashboard.php/assets.php/vulnerabilities.php -
// the "Tags" dropdown below shares the same session-persisted `view_tag`
// preference as those pages (see Helpers::resolveViewTag()), so picking a
// tag here also carries over if you then click through to Vulnerabilities.
$availableTags   = $isAdmin ? UserRepository::listTags() : UserRepository::getTagsByIds($tagIds);
$availableTagIds = array_map('intval', array_column($availableTags, 'id'));
$viewTagId       = Helpers::resolveViewTag($availableTagIds);

$severity   = isset($_GET['severity']) && $_GET['severity'] !== '' ? (int)$_GET['severity'] : null;
// CE+ (Cyber Essentials Plus) only cares about findings with a CVSS >= 7.0,
// i.e. severity 4 (High) or 5 (Critical) - a Medium or Low severity filter
// can never contain a CE+ failure. The checkbox is hidden for those
// severities below, and forced off here too so a stale/hand-built query
// string (e.g. ce_plus_only=1&severity=3) can't sneak the filter back in -
// same rule as public/vulnerabilities.php.
$cePlusAllowedForSeverity = $severity === null || $severity === 5 || $severity === 4;
$cePlusOnly = $cePlusAllowedForSeverity && !empty($_GET['ce_plus_only']);

// Exploitability filters - same parameters (kev=1, min_epss as a 0..1
// fraction) and parsing as public/vulnerabilities.php and both export
// scripts, which already honoured them; this page just had no controls for
// them, so a KEV/EPSS-filtered report could only be had from a hand-built URL.
$kevOnly = !empty($_GET['kev']);
$minEpss = isset($_GET['min_epss']) && $_GET['min_epss'] !== '' ? max(0.0, min(1.0, (float)$_GET['min_epss'])) : null;

$filters = ['severity' => $severity, 'ce_plus_only' => $cePlusOnly, 'kev_only' => $kevOnly, 'min_epss' => $minEpss];

// Two different counts, deliberately: $severityCounts is the tag scope's
// severity breakdown (ignores the severity dropdown - it's there to show
// what's in scope, not what's about to be exported) but DOES respect the
// CE+ toggle when it's on, since CE+ isn't just "another filter" the same
// way severity/tag are - it's a subset that can only ever contain
// Critical/High findings, so leaving it out here previously meant the
// Medium/Low cards kept showing their full unfiltered counts even with
// "CE+ failures only" checked, which read as the checkbox not working.
// $matchingCount is scope + severity + CE+ combined - exactly what a click
// on "Download PDF"/"Download CSV" would produce, since both exports use
// this same $filters array.
//
// getSeverityCounts() only knows the CE+ filter, so with KEV or EPSS on the
// cards are counted per band through getDetectionsCount() instead - exactly
// as public/report_pdf.php does for its cover cards, so the preview and the
// PDF cover agree. With neither on, the original single query is kept.
if ($kevOnly || $minEpss !== null) {
    $severityCounts = [];
    foreach ([5, 4, 3, 2] as $level) {
        $severityCounts[$level] = VulnerabilityRepository::getDetectionsCount($tagIds, $isAdmin, ['severity' => $level] + $filters, $viewTagId, false, $userId);
    }
} else {
    $severityCounts = VulnerabilityRepository::getSeverityCounts($tagIds, $isAdmin, $viewTagId, false, $userId, $cePlusOnly);
}
$matchingCount  = VulnerabilityRepository::getDetectionsCount($tagIds, $isAdmin, $filters, $viewTagId, false, $userId);

$scopeLabel     = Helpers::scopeLabel($availableTags, $viewTagId, $isAdmin);
// Same wording as the PDF cover's "Filters applied" line (report_pdf.php).
$filtersApplied = implode(', ', array_filter([
    Helpers::describeReportFilters($severity, $cePlusOnly),
    $kevOnly ? 'Known exploited (CISA KEV) only' : '',
    $minEpss !== null ? 'EPSS >= ' . rtrim(rtrim(number_format($minEpss * 100, 1), '0'), '.') . '%' : '',
], static fn (string $part): bool => $part !== ''));

$pageTitle = 'Reports';
require __DIR__ . '/../src/views/header.php';
?>

<div class="page-heading">
    <h1>Reports</h1>
    <p class="page-subtitle">Export the current vulnerability scope as a PDF or CSV report. Showing open findings only (fixed items are excluded).</p>
</div>

<form method="get" class="filter-bar" id="reportFilterForm">
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
    <label class="checkbox-field">
        <input type="checkbox" name="ce_plus_only" value="1" <?= $cePlusOnly ? 'checked' : '' ?> onchange="this.form.submit()">
        <span>CE+ failures only <span class="checkbox-hint">(CVSS &ge; 7.0, excl. zero-days)</span></span>
    </label>
    <?php endif; ?>

    <label class="checkbox-field">
        <input type="checkbox" name="kev" value="1" <?= $kevOnly ? 'checked' : '' ?> onchange="this.form.submit()">
        <span>Known exploited only <span class="checkbox-hint">(CISA KEV)</span></span>
    </label>

    <?php // Same presets as the Vulnerabilities page. A non-preset value from a
          // hand-built/linked URL is kept as an extra option rather than being
          // silently shown as "Any" while still filtering the export. ?>
    <?php
        $epssPresets = ['0.5' => '&ge; 50%', '0.1' => '&ge; 10%', '0.01' => '&ge; 1%'];
        $epssMatched = false;
    ?>
    <label class="field field-inline">
        <span>EPSS</span>
        <select name="min_epss" onchange="this.form.submit()">
            <option value="">Any</option>
            <?php foreach ($epssPresets as $val => $lbl):
                $sel = $minEpss !== null && abs($minEpss - (float)$val) < 0.0000001;
                $epssMatched = $epssMatched || $sel; ?>
            <option value="<?= $val ?>" <?= $sel ? 'selected' : '' ?>><?= $lbl ?></option>
            <?php endforeach; ?>
            <?php if ($minEpss !== null && !$epssMatched): ?>
            <option value="<?= Helpers::e((string)$minEpss) ?>" selected>&ge; <?= rtrim(rtrim(number_format($minEpss * 100, 1), '0'), '.') ?>%</option>
            <?php endif; ?>
        </select>
    </label>

    <noscript><button type="submit" class="btn btn-secondary">Apply</button></noscript>

    <div class="stat-grid report-stat-grid">
        <div class="stat-card sev-critical">
            <span class="stat-number"><?= number_format($severityCounts[5]) ?></span>
            <span class="stat-label">Critical</span>
        </div>
        <div class="stat-card sev-high">
            <span class="stat-number"><?= number_format($severityCounts[4]) ?></span>
            <span class="stat-label">High</span>
        </div>
        <div class="stat-card sev-medium">
            <span class="stat-number"><?= number_format($severityCounts[3]) ?></span>
            <span class="stat-label">Medium</span>
        </div>
        <div class="stat-card sev-low">
            <span class="stat-number"><?= number_format($severityCounts[2]) ?></span>
            <span class="stat-label">Low</span>
        </div>
    </div>

    <div class="report-summary-panel">
        <p class="report-summary-line"><strong>Scope:</strong> <?= Helpers::e($scopeLabel) ?></p>
        <p class="report-summary-line"><strong>Filters applied:</strong> <?= $filtersApplied !== '' ? Helpers::e($filtersApplied) : 'None' ?></p>
        <p class="report-summary-line report-summary-count"><?= number_format($matchingCount) ?> finding<?= $matchingCount === 1 ? '' : 's' ?> will be included in the export.</p>
    </div>

    <div class="report-actions">
        <button type="submit" formaction="/report_pdf" class="btn btn-primary">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
            Download PDF
        </button>
        <button type="submit" formaction="/report_csv" class="btn btn-secondary">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
            Download CSV
        </button>
    </div>
</form>

<p class="report-note">The PDF report includes a summary and a findings table (capped at the 2,000 most severe matching findings, ordered by severity). The CSV export has no cap and includes every matching finding, one per row.</p>

<?php require __DIR__ . '/../src/views/footer.php'; ?>
