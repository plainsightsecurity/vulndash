<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\AuditLog;
use VulnDash\Lib\Auth;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\PdfReport;
use VulnDash\Lib\UserRepository;
use VulnDash\Lib\VulnerabilityRepository;

// Same auth/scope/filter resolution as public/reports.php and
// public/report_csv.php - see report_csv.php's docblock for why all three
// deliberately read the same GET parameters.
Auth::check();

$tagIds  = Auth::tagIds();
$isAdmin = Auth::isAdmin();
$userId  = Auth::userId();

$availableTags   = $isAdmin ? UserRepository::listTags() : UserRepository::getTagsByIds($tagIds);
$availableTagIds = array_map('intval', array_column($availableTags, 'id'));
$viewTagId       = Helpers::resolveViewTag($availableTagIds);

$severity   = isset($_GET['severity']) && $_GET['severity'] !== '' ? (int)$_GET['severity'] : null;
// Same CE+/severity interaction as public/reports.php: CE+ can only ever
// match a Critical/High finding, so a Medium/Low severity request forces it
// off rather than silently building a report whose cover cards contradict
// its own "Filters applied" line.
$cePlusAllowedForSeverity = $severity === null || $severity === 5 || $severity === 4;
$cePlusOnly = $cePlusAllowedForSeverity && !empty($_GET['ce_plus_only']);
// Exploitability filters, parsed exactly as report_csv.php does. Until
// 2026-11-04 this export ignored them while the CSV honoured them, so the
// same filtered link produced a CSV and a PDF with different rows.
$kevOnly    = !empty($_GET['kev']);
$minEpss    = isset($_GET['min_epss']) && $_GET['min_epss'] !== '' ? max(0.0, min(1.0, (float)$_GET['min_epss'])) : null;
$filters    = ['severity' => $severity, 'ce_plus_only' => $cePlusOnly, 'kev_only' => $kevOnly, 'min_epss' => $minEpss];

// A hard row cap for the PDF specifically (see PdfReport::renderDetailTable()
// and getDetectionsForExport()'s docblock) - a laid-out, paginated table
// has real per-row rendering cost, unlike the CSV export's plain fputcsv()
// stream, so an unfiltered admin report across a very large estate is
// capped to something that stays a genuinely readable document rather than
// a multi-thousand-page PDF. The CSV export next to it always has the
// complete list regardless of this cap.
const REPORT_PDF_MAX_ROWS = 2000;

$totalCount = VulnerabilityRepository::getDetectionsCount($tagIds, $isAdmin, $filters, $viewTagId, false, $userId);
// The cover's Critical/High/Medium/Low cards: every filter EXCEPT severity
// (they show the breakdown of what's in scope, not just the chosen band -
// same reasoning as reports.php's comment on its own cards). Counted per
// band through getDetectionsCount() rather than getSeverityCounts(), because
// that method only knows the CE+ filter: with KEV or EPSS applied its cards
// would have described a different set of findings from the table below.
// With neither applied the numbers are identical to before.
$severityCounts = [];
foreach ([5, 4, 3, 2] as $level) {
    $severityCounts[$level] = VulnerabilityRepository::getDetectionsCount($tagIds, $isAdmin, ['severity' => $level] + $filters, $viewTagId, false, $userId);
}
// The cover's "CE+ overdue" card: the overdue subset of exactly what this
// report contains (same scope and filters as $totalCount), so it can never
// exceed the findings listed - and counted before the row cap, like
// $totalCount, so it stays the true figure even for a truncated report.
$cePlusOverdueCount = VulnerabilityRepository::getDetectionsCount($tagIds, $isAdmin, $filters + ['ce_overdue_only' => true], $viewTagId, false, $userId);
// In-scope assets whose agent isn't reporting (see StaleAgent) - a cover note
// so the reader knows some findings may be out of date. Scope only: whether
// a host has gone quiet doesn't depend on which findings were filtered.
$staleAssetCount = VulnerabilityRepository::getStaleAssetCount($tagIds, $isAdmin, $viewTagId);
$detections = VulnerabilityRepository::getDetectionsForExport($tagIds, $isAdmin, $filters, $viewTagId, REPORT_PDF_MAX_ROWS, $userId);
$truncated = $totalCount > REPORT_PDF_MAX_ROWS;

// Helpers::describeReportFilters() only knows severity and CE+; the KEV/EPSS
// parts are appended here in the same style, so the cover's "Filters
// applied" line still states everything the report was filtered by.
$filterParts = array_filter([
    Helpers::describeReportFilters($severity, $cePlusOnly),
    $kevOnly ? 'Known exploited (CISA KEV) only' : '',
    $minEpss !== null ? 'EPSS >= ' . rtrim(rtrim(number_format($minEpss * 100, 1), '0'), '.') . '%' : '',
], static fn (string $part): bool => $part !== '');

$meta = [
    'scope'        => Helpers::scopeLabel($availableTags, $viewTagId, $isAdmin),
    'filters'      => implode(', ', $filterParts),
    'generatedAt'  => (new DateTimeImmutable('now', new DateTimeZone('Europe/London')))->format('Y-m-d H:i T'),
    'generatedBy'  => Auth::username(),
];

AuditLog::record('report.exported', [
    'target_type'  => 'report',
    'target_label' => 'PDF - ' . $meta['scope'],
    'details'      => ['format' => 'pdf', 'rows' => count($detections), 'filters' => $meta['filters'] !== '' ? $meta['filters'] : 'none'],
]);

$pdf = new PdfReport();
$pdf->buildReport($meta, $severityCounts, $totalCount, $detections, $truncated, REPORT_PDF_MAX_ROWS, $cePlusOverdueCount, $staleAssetCount);
$pdf->Output('D', 'vulndash-report-' . date('Y-m-d-His') . '.pdf');
