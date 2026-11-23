<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\AuditLog;
use VulnDash\Lib\Auth;
use VulnDash\Lib\CePlusDeadline;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\UserRepository;
use VulnDash\Lib\VulnerabilityRepository;

// Same auth/scope/filter resolution as public/reports.php and
// public/report_pdf.php - all three deliberately read the same GET
// parameters (view_tag, severity, ce_plus_only) so the row count shown in
// the Reports preview always matches what actually comes out of whichever
// export button was clicked.
Auth::check();

$tagIds  = Auth::tagIds();
$isAdmin = Auth::isAdmin();
$userId  = Auth::userId();

$availableTags   = $isAdmin ? UserRepository::listTags() : UserRepository::getTagsByIds($tagIds);
$availableTagIds = array_map('intval', array_column($availableTags, 'id'));
$viewTagId       = Helpers::resolveViewTag($availableTagIds);

$severity   = isset($_GET['severity']) && $_GET['severity'] !== '' ? (int)$_GET['severity'] : null;
$cePlusOnly = !empty($_GET['ce_plus_only']);
// Honour the same exploitability filters the vulnerability list offers, so an
// export linked/filtered by KEV or EPSS comes out matching what's on screen.
$kevOnly    = !empty($_GET['kev']);
$minEpss    = isset($_GET['min_epss']) && $_GET['min_epss'] !== '' ? max(0.0, min(1.0, (float)$_GET['min_epss'])) : null;
$filters    = ['severity' => $severity, 'ce_plus_only' => $cePlusOnly, 'kev_only' => $kevOnly, 'min_epss' => $minEpss];

// No $limit here (unlike report_pdf.php) - the CSV export is deliberately
// the "complete list, however large" option; streaming rows straight to
// output via fputcsv() is cheap enough that there's no real reason to cap
// it the way the PDF's laid-out table has to be.
$rows = VulnerabilityRepository::getDetectionsForExport($tagIds, $isAdmin, $filters, $viewTagId, null, $userId);

AuditLog::record('report.exported', [
    'target_type'  => 'report',
    'target_label' => 'CSV - ' . Helpers::scopeLabel($availableTags, $viewTagId, $isAdmin),
    'details'      => ['format' => 'csv', 'rows' => count($rows), 'filters' => implode(', ', array_filter([
        Helpers::describeReportFilters($severity, $cePlusOnly),
        $kevOnly ? 'Known exploited (CISA KEV) only' : '',
        $minEpss !== null ? 'EPSS >= ' . rtrim(rtrim(number_format($minEpss * 100, 1), '0'), '.') . '%' : '',
    ])) ?: 'none'],
]);

// Excel's hard limit is 32,767 characters per cell; a longer value doesn't
// fail cleanly, it spills the remainder into the following rows and wrecks
// the sheet's alignment. Evidence is the only column that can get near it,
// so it's capped a little under with an explicit marker rather than left to
// corrupt the file. The full text stays on the finding's page in the dashboard.
const CSV_EVIDENCE_MAX_CHARS = 32000;
const CSV_EVIDENCE_TRUNCATED_MARKER = "\n[truncated - full evidence on the finding's page in the dashboard]";

$filename = 'vulndash-report-' . date('Y-m-d-His') . '.csv';

header('Content-Type: text/csv; charset=UTF-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Cache-Control: private, max-age=0, must-revalidate');
header('Pragma: public');

$out = fopen('php://output', 'w');

// A UTF-8 BOM ahead of the header row so Excel (which otherwise assumes
// the system codepage rather than UTF-8 for a plain .csv) renders any
// non-ASCII characters in a finding's title correctly, rather than
// mangling them - other CSV readers (LibreOffice, Google Sheets, PHP's own
// fgetcsv()) all cope fine with a leading BOM.
fwrite($out, "\xEF\xBB\xBF");

// New columns are added after Last Found, so the original sixteen keep their
// positions for anything already reading these exports by column. Evidence
// stays last: it's the long, multi-line one, easiest to read at the end.
fputcsv($out, [
    'Hostname', 'IP Address', 'QID', 'Title', 'Severity', 'CVSS Score',
    'CVSS Source', 'On CISA KEV', 'KEV Due Date', 'EPSS %', 'EPSS Percentile',
    'Status', 'Port', 'Protocol', 'First Found', 'Last Found',
    'CE+ Fail', 'CE+ Patch Due', 'CE+ Days Overdue', 'Evidence',
]);

foreach ($rows as $row) {
    // Qualys entity-encodes evidence before wrapping it in CDATA, so the
    // stored text still carries &lt; / &quot; etc - decoded once here to the
    // plain text a spreadsheet should show. Same decode, and same reasoning,
    // as $evidenceText in public/vulnerability_detail.php. Line breaks are
    // kept: fputcsv() quotes the cell, so they stay inside it.
    $evidence = html_entity_decode((string)($row['results'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    if (mb_strlen($evidence, 'UTF-8') > CSV_EVIDENCE_MAX_CHARS) {
        $evidence = mb_substr($evidence, 0, CSV_EVIDENCE_MAX_CHARS - mb_strlen(CSV_EVIDENCE_TRUNCATED_MARKER, 'UTF-8'), 'UTF-8')
            . CSV_EVIDENCE_TRUNCATED_MARKER;
    }

    // CE+ 14-day patch clock (see CePlusDeadline). Patch Due is blank for
    // anything that isn't a CE+ failure, or is one with no clock (no vendor
    // patch yet, or no date at all); Days Overdue is a plain number of calendar days past the due date
    // (so it sorts/filters in a spreadsheet), 0 if it fell due earlier today,
    // and blank unless actually overdue. All three are
    // DB-derived (a flag, a date, an int), so no csvSafe() needed.
    $isCePlusFail = !empty($row['is_ce_plus_fail']);
    $ceDeadline = CePlusDeadline::forRow($row);

    // Every free-text column is passed through Helpers::csvSafe() to
    // neutralise spreadsheet formula/CSV injection: values sourced from
    // Qualys (the finding title, CVSS source, scan evidence) or from asset
    // inventory (hostname, protocol) that begin with =, +, -, @ or a leading
    // tab/CR would otherwise be executed as a formula when the export is
    // opened in Excel/LibreOffice/Sheets. Purely numeric columns (QID,
    // score, port) are cast to int/float and can't carry this, so they're
    // left as-is. See Helpers::csvSafe() and OWASP "CSV Injection".
    fputcsv($out, [
        Helpers::csvSafe($row['hostname']),
        Helpers::csvSafe($row['ip_address']),
        (int)$row['qid'],
        Helpers::csvSafe($row['title']),
        Helpers::severityLabel((int)$row['severity_level']),
        $row['effective_cvss_score'] !== null ? number_format((float)$row['effective_cvss_score'], 1) : '',
        Helpers::csvSafe($row['effective_cvss_source']),
        // Exploitability columns from the qid_exploit rollup. All are DB-owned
        // (a flag, a DATE, decimals) so they can't carry a CSV-injection
        // payload the way the free-text columns can - no csvSafe() needed.
        !empty($row['is_kev']) ? 'Yes' : 'No',
        $row['kev_due_date'] ?? '',
        isset($row['max_epss']) && $row['max_epss'] !== null ? number_format((float)$row['max_epss'] * 100, 2) : '',
        isset($row['max_epss_percentile']) && $row['max_epss_percentile'] !== null ? number_format((float)$row['max_epss_percentile'] * 100, 2) : '',
        Helpers::csvSafe($row['status']),
        $row['port'] !== null ? (int)$row['port'] : '',
        Helpers::csvSafe($row['protocol']),
        // Plain 'Y-m-d H:i:s' rather than Helpers::displayQualysDateTime()'s
        // usual '...T' (BST/GMT-labelled) format - a spreadsheet column of
        // timestamps is more useful sortable/parseable than annotated, and
        // this is still the correct Europe/London wall-clock value either
        // way (see that method's docblock for why these two particular
        // columns need the UTC -> Europe/London conversion at all).
        Helpers::displayQualysDateTime($row['first_found'], 'Y-m-d H:i:s'),
        Helpers::displayQualysDateTime($row['last_found'], 'Y-m-d H:i:s'),
        $isCePlusFail ? 'Yes' : 'No',
        $ceDeadline !== null ? $ceDeadline['due']->format('Y-m-d') : '',
        $ceDeadline !== null && $ceDeadline['overdue'] ? $ceDeadline['days'] : '',
        Helpers::csvSafe($evidence),
    ]);
}

fclose($out);
