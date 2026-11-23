<?php
declare(strict_types=1);

namespace VulnDash\Lib;

// FPDF is a small, dependency-free PDF-generation library (single file, no
// Composer/vendor tree needed) - vendored here the same way
// public/assets/js/qrcode.js is vendored for MFA QR codes, since this app
// deliberately has zero external PHP dependencies (see bootstrap.php). It
// defines the global \FPDF class this file extends below.
//
// Source: https://github.com/Setasign/FPDF (community mirror of the
// original fpdf.org project by Olivier Plathey). FPDF's licence is
// deliberately permissive - free for any use including commercial, with no
// requirement beyond keeping the author credit in the source file itself
// (already present at the top of Vendor/FPDF/fpdf.php) - so no separate
// licence file is needed for this to be redistributed as part of VulnDash.
require_once __DIR__ . '/Vendor/FPDF/fpdf.php';

/**
 * Builds the vulnerability report PDF handed out by public/report_pdf.php -
 * a cover section (logo, report scope/filters, generated-by/at, and a
 * severity summary strip) followed by a paginated findings table.
 *
 * FPDF's core fonts (Helvetica/Arial etc.) only support Latin-1
 * (ISO-8859-1), not full Unicode - this app's data is all plain English
 * ASCII in practice (Qualys titles, hostnames), but as a defensive measure
 * every piece of text that could conceivably contain something outside
 * Latin-1 goes through latin1() below, which transliterates to the closest
 * ASCII/Latin-1 equivalent rather than corrupting the PDF output. Embedding
 * a full Unicode TTF font would remove this limitation entirely, at the
 * cost of a much heavier vendored dependency - not worth it unless titles
 * containing non-Latin1 characters actually turn up in practice.
 *
 * Table rows use variable height (the Title column wraps, up to 3 lines)
 * with the row's own severity colour as a left-edge stripe, echoing the
 * coloured-stripe convention already used for table rows on the web
 * dashboard (see style.css). Automatic page breaking is deliberately
 * turned off while the table is being drawn - see renderDetailTable()'s
 * docblock for why - and each row is checked against the page's own break
 * trigger by hand instead, so a wrapped row is never split awkwardly
 * across two pages.
 *
 * A finding with scan evidence gets it as a sub-row directly beneath its
 * main row, in Courier, clamped to EVIDENCE_MAX_LINES - see
 * evidenceLines() for why it's clamped rather than shown in full.
 */
class PdfReport extends \FPDF
{
    private const LOGO_PATH = __DIR__ . '/../assets/logo-full.png';
    // Real aspect ratio of logo-full.png (980x588) - used so the logo is
    // never stretched, whatever width it's placed at.
    private const LOGO_ASPECT = 588 / 980;

    private const STRIPE_W = 2.5;
    private const BOTTOM_MARGIN = 16.0;
    private const ROW_LINE_HEIGHT = 4.0;
    private const MAX_TITLE_LINES = 3;

    private const EVIDENCE_FONT_SIZE = 6.5;
    private const EVIDENCE_LINE_HEIGHT = 3.0;
    private const EVIDENCE_MAX_LINES = 6;
    // Breathing room below the evidence text, so it doesn't sit on the row's
    // separator line.
    private const EVIDENCE_PAD_BOTTOM = 1.2;
    // The evidence sub-row's label sits under the Severity/CVSS/EPSS/KEV/QID columns
    // and the text itself under Title onwards, so it reads as belonging to
    // the row above rather than as a new row.
    private const EVIDENCE_TEXT_FROM_COLUMN = 'title';

    /** @var array<int, array{key: string, label: string, width: float, align: string}> */
    private array $columns = [
        ['key' => 'severity',   'label' => 'Severity',   'width' => 20.0, 'align' => 'L'],
        ['key' => 'cvss',       'label' => 'CVSS',       'width' => 13.0, 'align' => 'R'],
        // Exploitability, beside CVSS so severity-then-likelihood reads left
        // to right. The 23mm they need came out of Title (wraps anyway) plus
        // the 14.5mm the table previously left unused at the right margin.
        ['key' => 'epss',       'label' => 'EPSS',       'width' => 13.0, 'align' => 'R'],
        ['key' => 'kev',        'label' => 'KEV',        'width' => 10.0, 'align' => 'C'],
        ['key' => 'qid',        'label' => 'QID',        'width' => 15.0, 'align' => 'L'],
        ['key' => 'title',      'label' => 'Title',      'width' => 103.0, 'align' => 'L'],
        ['key' => 'asset',      'label' => 'Asset',      'width' => 50.0, 'align' => 'L'],
        ['key' => 'status',     'label' => 'Status',     'width' => 18.0, 'align' => 'L'],
        ['key' => 'last_found', 'label' => 'Last found', 'width' => 24.0, 'align' => 'L'],
    ];

    private string $generatedAtFooter = '';

    public function __construct()
    {
        parent::__construct('L', 'mm', 'A4');
        $this->SetTitle('VulnDash Vulnerability Report');
        $this->SetAuthor('Plainsight Security');
        $this->SetCreator('VulnDash');
        $this->SetMargins(14, 12, 14);
        $this->SetAutoPageBreak(true, self::BOTTOM_MARGIN);
        $this->AliasNbPages();
        $this->generatedAtFooter = (new \DateTimeImmutable('now', new \DateTimeZone('Europe/London')))
            ->format('Y-m-d H:i T');
    }

    /**
     * Renders the whole report - cover/summary section then the findings
     * table - and leaves the document ready for Output(). Call this once
     * per instance; nothing before it needs a page to exist yet.
     *
     * @param array{scope: string, filters: string, generatedAt: string, generatedBy: string} $meta
     * @param array<int, int> $severityCounts level (2-5) => count, same shape as VulnerabilityRepository::getSeverityCounts()
     * @param array<int, array<string, mixed>> $detections rows from VulnerabilityRepository::getDetectionsForExport()
     * @param int|null $cePlusOverdueCount CE+ failures past the patch window
     *        within the same filters - adds a "CE+ overdue" cover card when
     *        given; null leaves the cover exactly as before.
     * @param int|null $staleAssetCount in-scope assets whose agent isn't
     *        reporting (see StaleAgent) - when above 0, the cover says so,
     *        since their findings may be out of date.
     */
    public function buildReport(array $meta, array $severityCounts, int $totalCount, array $detections, bool $truncated, int $maxRows, ?int $cePlusOverdueCount = null, ?int $staleAssetCount = null): void
    {
        $this->AddPage();
        $this->renderCoverSummary($meta, $severityCounts, $totalCount, $cePlusOverdueCount, $staleAssetCount);
        $this->renderDetailTable($detections);

        if ($truncated) {
            $this->Ln(3);
            $this->SetFont('Helvetica', 'I', 8);
            $this->SetTextColor(150, 60, 60);
            $this->MultiCell(0, 4.5, $this->latin1(sprintf(
                'Showing the first %s of %s matching findings, ordered by severity (most severe first). '
                    . 'Use the CSV export for the complete list.',
                number_format($maxRows),
                number_format($totalCount)
            )));
        }
    }

    /**
     * Page header, called automatically by FPDF on every AddPage() - the
     * full logo + title on the cover page, a slim repeating strip with a
     * small logo on every page after that (so a printed/scrolled-through
     * report is still identifiable page-by-page without repeating the
     * whole cover treatment).
     */
    public function Header(): void
    {
        if ($this->PageNo() === 1) {
            $logoW = 52.0;
            $logoH = $logoW * self::LOGO_ASPECT;
            if (is_file(self::LOGO_PATH)) {
                $this->Image(self::LOGO_PATH, $this->lMargin, 12, $logoW);
            }

            $this->SetXY($this->lMargin + $logoW + 8, 14);
            $this->SetFont('Helvetica', 'B', 20);
            $this->SetTextColor(20, 20, 20);
            $this->Cell(0, 10, 'Vulnerability Report', 0, 2);

            $this->SetX($this->lMargin + $logoW + 8);
            $this->SetFont('Helvetica', '', 10);
            $this->SetTextColor(110, 114, 122);
            $this->Cell(0, 6, 'Plainsight Security - Vulnerability Management Dashboard', 0, 1);

            $ruleY = 12 + max($logoH, 26) + 4;
            $this->SetDrawColor(210, 212, 216);
            $this->SetLineWidth(0.3);
            $this->Line($this->lMargin, $ruleY, $this->w - $this->rMargin, $ruleY);
            $this->SetY($ruleY + 6);
        } else {
            $logoW = 20.0;
            if (is_file(self::LOGO_PATH)) {
                $this->Image(self::LOGO_PATH, $this->lMargin, 7, $logoW);
            }

            $this->SetFont('Helvetica', 'B', 10);
            $this->SetTextColor(60, 64, 72);
            $this->SetXY($this->w - $this->rMargin - 90, 9);
            $this->Cell(90, 6, 'Vulnerability Report', 0, 0, 'R');

            $this->SetDrawColor(210, 212, 216);
            $this->SetLineWidth(0.3);
            $this->Line($this->lMargin, 20, $this->w - $this->rMargin, 20);
            $this->SetY(24);
        }
    }

    /** Page footer, called automatically by FPDF on every AddPage()/Close(). */
    public function Footer(): void
    {
        $this->SetY(-14);
        $this->SetFont('Helvetica', 'I', 8);
        $this->SetTextColor(130, 134, 142);
        $this->Cell(0, 5, 'Generated ' . $this->generatedAtFooter . ' - Plainsight Security - CONFIDENTIAL', 0, 0, 'L');
        $this->Cell(0, 5, 'Page ' . $this->PageNo() . ' / {nb}', 0, 0, 'R');
    }

    /**
     * The cover section immediately below Header(): scope/filter/generated
     * metadata as a simple key-value list, then a summary strip of
     * Critical/High/Medium/Low/Total counts styled after the dashboard's
     * own stat cards (see style.css .stat-card) so the printed report
     * still reads as "the same app", not a generic export.
     *
     * @param array{scope: string, filters: string, generatedAt: string, generatedBy: string} $meta
     * @param array<int, int> $severityCounts
     */
    private function renderCoverSummary(array $meta, array $severityCounts, int $totalCount, ?int $cePlusOverdueCount = null, ?int $staleAssetCount = null): void
    {
        $lines = [
            ['Scope', $meta['scope']],
            ['Filters applied', $meta['filters'] !== '' ? $meta['filters'] : 'None'],
            ['Generated', $meta['generatedAt']],
            ['Generated by', $meta['generatedBy']],
        ];
        // Only when it applies: a report reader can't otherwise tell that some
        // of the findings below come from hosts that have gone quiet.
        if ($staleAssetCount !== null && $staleAssetCount > 0) {
            $lines[] = ['Not reporting', sprintf(
                '%s asset%s with no agent report in over %d days - %s findings may be out of date',
                number_format($staleAssetCount),
                $staleAssetCount === 1 ? '' : 's',
                StaleAgent::staleAfterDays(),
                $staleAssetCount === 1 ? 'its' : 'their'
            )];
        }

        foreach ($lines as [$label, $value]) {
            $this->SetFont('Helvetica', 'B', 9.5);
            $this->SetTextColor(60, 64, 72);
            $this->Cell(34, 6, $label . ':', 0, 0);
            $this->SetFont('Helvetica', '', 9.5);
            $this->SetTextColor(20, 20, 20);
            $this->Cell(0, 6, $this->latin1((string)$value), 0, 1);
        }

        $this->Ln(4);

        $cards = [
            ['label' => 'Critical', 'count' => $severityCounts[5] ?? 0, 'color' => [178, 58, 58]],
            ['label' => 'High',     'count' => $severityCounts[4] ?? 0, 'color' => [193, 101, 46]],
            ['label' => 'Medium',   'count' => $severityCounts[3] ?? 0, 'color' => [201, 154, 58]],
            ['label' => 'Low',      'count' => $severityCounts[2] ?? 0, 'color' => [76, 139, 114]],
            ['label' => 'Total open', 'count' => $totalCount, 'color' => [63, 198, 184]],
        ];
        // Card widths are derived from the count below, so a sixth card just
        // narrows the strip evenly.
        if ($cePlusOverdueCount !== null) {
            $cards[] = ['label' => 'CE+ overdue', 'count' => $cePlusOverdueCount, 'color' => [178, 58, 58]];
        }

        $usableWidth = $this->w - $this->lMargin - $this->rMargin;
        $gutter = 3.0;
        $cardW = ($usableWidth - $gutter * (count($cards) - 1)) / count($cards);
        $cardH = 20.0;
        $x0 = $this->lMargin;
        $y0 = $this->GetY();

        foreach ($cards as $i => $card) {
            $x = $x0 + $i * ($cardW + $gutter);
            [$r, $g, $b] = $card['color'];

            $this->SetDrawColor($r, $g, $b);
            $this->SetLineWidth(0.6);
            $this->Rect($x, $y0, $cardW, $cardH, 'D');

            $this->SetXY($x, $y0 + 3);
            $this->SetFont('Helvetica', 'B', 15);
            $this->SetTextColor($r, $g, $b);
            $this->Cell($cardW, 8, number_format((int)$card['count']), 0, 2, 'C');

            $this->SetX($x);
            $this->SetFont('Helvetica', '', 8);
            $this->SetTextColor(90, 94, 102);
            $this->Cell($cardW, 5, $card['label'], 0, 0, 'C');
        }

        $this->SetLineWidth(0.2);
        $this->SetXY($x0, $y0 + $cardH + 8);
    }

    /**
     * The paginated findings table. Automatic page breaking is switched
     * off for the duration of this method: FPDF's own Cell()/MultiCell()
     * trigger a page break mid-call whenever content would cross
     * PageBreakTrigger, which - for a row built out of several MultiCell()
     * calls, one per column - could break a single row's columns across
     * two different pages if one column happens to wrap more than the
     * others. Checking (and breaking) by hand before each whole row starts
     * instead means a row is always drawn complete on one page. Auto page
     * break is restored at the end for whatever content follows (the
     * "truncated" notice in buildReport()).
     *
     * The fit check covers the row AND its evidence sub-row together, so a
     * finding's evidence is never stranded at the top of the next page
     * away from the finding it belongs to.
     *
     * @param array<int, array<string, mixed>> $rows
     */
    private function renderDetailTable(array $rows): void
    {
        $this->SetFont('Helvetica', 'B', 11);
        $this->SetTextColor(20, 20, 20);
        $this->Cell(0, 8, 'Findings', 0, 1);
        $this->Ln(1);

        if (empty($rows)) {
            $this->SetFont('Helvetica', '', 9.5);
            $this->SetTextColor(110, 114, 122);
            $this->Cell(0, 6, 'No findings match the current filters.', 0, 1);
            return;
        }

        $this->drawTableHeader();
        $this->SetAutoPageBreak(false, self::BOTTOM_MARGIN);

        $zebra = false;
        $titleWidth = $this->colWidth('title');

        foreach ($rows as $row) {
            $severityLevel = (int)$row['severity_level'];
            $titleText = $this->clampToLines($this->latin1((string)$row['title']), $titleWidth, self::MAX_TITLE_LINES);
            $assetRaw = ($row['hostname'] ?? '') !== '' ? $row['hostname'] : ($row['ip_address'] ?? '');
            $assetText = $this->truncateToWidth($this->latin1((string)$assetRaw), $this->colWidth('asset'));
            $cvssText = $row['effective_cvss_score'] !== null ? number_format((float)$row['effective_cvss_score'], 1) : 'n/a';

            $cellText = [
                'severity'   => Helpers::severityLabel($severityLevel),
                'cvss'       => $cvssText,
                'epss'       => $this->formatEpss($row['max_epss'] ?? null),
                // Blank rather than "No" so the handful of KEV rows stand out
                // in a long table instead of being lost in a column of Nos.
                'kev'        => !empty($row['is_kev']) ? 'KEV' : '',
                'qid'        => (string)(int)$row['qid'],
                'title'      => $titleText,
                'asset'      => $assetText,
                'status'     => $this->latin1((string)$row['status']),
                'last_found' => $this->formatReportDate($row['last_found']),
            ];

            $nbLines = max(1, $this->NbLines($titleWidth, $cellText['title']));
            // A CE+ failure with a patch clock gets its "Overdue 12d" / "5d
            // left" as a second line under Status, so the row needs at least
            // two lines even when the title fits on one.
            $ceDeadline = CePlusDeadline::forRow($row);
            $rowHeight = max($nbLines, $ceDeadline !== null ? 2 : 1) * self::ROW_LINE_HEIGHT;

            // After NbLines() above, not before: evidenceLines() measures in
            // Courier, and NbLines() measures in whatever font is current.
            $evidence = $this->evidenceLines((string)($row['results'] ?? ''));
            $evidenceHeight = $evidence !== []
                ? count($evidence) * self::EVIDENCE_LINE_HEIGHT + self::EVIDENCE_PAD_BOTTOM
                : 0.0;

            if ($this->GetY() + $rowHeight + $evidenceHeight > $this->PageBreakTrigger) {
                $this->AddPage($this->CurOrientation);
                $this->drawTableHeader();
            }

            $this->drawTableRow($cellText, $severityLevel, $rowHeight, $zebra, $evidence, $evidenceHeight, $ceDeadline);
            $zebra = !$zebra;
        }

        $this->SetAutoPageBreak(true, self::BOTTOM_MARGIN);
    }

    /**
     * @param array<string, string> $cellText keyed the same as $this->columns
     * @param string[] $evidence display lines from evidenceLines(); [] for none
     * @param array{due: \DateTimeImmutable, overdue: bool, days: int}|null $ceDeadline from CePlusDeadline::status()
     */
    private function drawTableRow(array $cellText, int $severityLevel, float $rowHeight, bool $zebra, array $evidence = [], float $evidenceHeight = 0.0, ?array $ceDeadline = null): void
    {
        $x = $this->lMargin;
        $y = $this->GetY();
        $totalWidth = self::STRIPE_W + array_sum(array_column($this->columns, 'width'));
        $totalHeight = $rowHeight + $evidenceHeight;
        [$r, $g, $b] = $this->severityColor($severityLevel);

        // Zebra fill and severity stripe span the evidence sub-row too, so
        // the two read as one finding.
        if ($zebra) {
            $this->SetFillColor(245, 246, 248);
            $this->Rect($x, $y, $totalWidth, $totalHeight, 'F');
        }

        $this->SetFillColor($r, $g, $b);
        $this->Rect($x, $y, self::STRIPE_W, $totalHeight, 'F');

        $curX = $x + self::STRIPE_W;
        foreach ($this->columns as $col) {
            $this->SetXY($curX, $y);
            if ($col['key'] === 'severity') {
                $this->SetFont('Helvetica', 'B', 8);
                $this->SetTextColor($r, $g, $b);
            } elseif ($col['key'] === 'kev') {
                // Same red as the web badge's intent: confirmed exploited in
                // the wild, regardless of the row's own severity colour.
                $this->SetFont('Helvetica', 'B', 8);
                $this->SetTextColor(178, 58, 58);
            } else {
                $this->SetFont('Helvetica', '', 8);
                $this->SetTextColor(30, 30, 30);
            }
            $this->MultiCell($col['width'], self::ROW_LINE_HEIGHT, $cellText[$col['key']], 0, $col['align'], false);

            if ($col['key'] === 'status' && $ceDeadline !== null) {
                // Second line under the status. Drawn separately rather than
                // as "Active\nOverdue 12d" so it can take its own colour:
                // red when overdue, muted while still inside the window.
                $this->SetXY($curX, $y + self::ROW_LINE_HEIGHT);
                $this->SetFont('Helvetica', $ceDeadline['overdue'] ? 'B' : '', 7);
                if ($ceDeadline['overdue']) {
                    $this->SetTextColor(178, 58, 58);
                } else {
                    $this->SetTextColor(110, 114, 122);
                }
                $this->Cell($col['width'], self::ROW_LINE_HEIGHT, CePlusDeadline::shortLabel($ceDeadline), 0, 0, 'L');
            }

            $curX += $col['width'];
        }

        if ($evidence !== []) {
            $ey = $y + $rowHeight;
            $textX = $x + self::STRIPE_W + $this->evidenceLabelWidth();

            $this->SetXY($x + self::STRIPE_W, $ey);
            $this->SetFont('Helvetica', 'I', 7);
            $this->SetTextColor(110, 114, 122);
            $this->Cell($this->evidenceLabelWidth(), self::EVIDENCE_LINE_HEIGHT, 'Evidence', 0, 0, 'L');

            $this->SetXY($textX, $ey);
            $this->SetFont('Courier', '', self::EVIDENCE_FONT_SIZE);
            $this->SetTextColor(70, 74, 82);
            // Each line was pre-wrapped to fit by evidenceLines(), so
            // MultiCell() only ever breaks on the \n separators.
            $this->MultiCell($this->evidenceTextWidth(), self::EVIDENCE_LINE_HEIGHT, implode("\n", $evidence), 0, 'L', false);

            // The next row's NbLines() measures in the current font, which
            // every row before this addition left as Helvetica 8.
            $this->SetFont('Helvetica', '', 8);
        }

        $this->SetDrawColor(224, 226, 230);
        $this->SetLineWidth(0.15);
        $this->Line($x, $y + $totalHeight, $x + $totalWidth, $y + $totalHeight);
        $this->SetXY($x, $y + $totalHeight);
    }

    private function drawTableHeader(): void
    {
        $x = $this->lMargin;
        $y = $this->GetY();
        $h = 7.0;

        $this->SetFillColor(230, 232, 236);
        $this->Rect($x, $y, self::STRIPE_W + array_sum(array_column($this->columns, 'width')), $h, 'F');

        $this->SetFont('Helvetica', 'B', 8);
        $this->SetTextColor(40, 44, 52);
        $this->SetXY($x + self::STRIPE_W, $y);
        foreach ($this->columns as $col) {
            $this->Cell($col['width'], $h, $col['label'], 0, 0, $col['align']);
        }
        $this->Ln($h);
    }

    /**
     * EPSS probability (0..1) as a percentage for the table. Non-zero
     * scores that would round to 0.0% show as "<0.1%", so "scored, but
     * very unlikely" isn't confused with "not scored" ("n/a", e.g. a QID
     * with no CVE or one FIRST hasn't scored yet).
     */
    private function formatEpss(mixed $epss): string
    {
        if ($epss === null || $epss === '') {
            return 'n/a';
        }
        $pct = (float)$epss * 100;
        if ($pct > 0 && $pct < 0.05) {
            return '<0.1%';
        }
        return number_format($pct, 1) . '%';
    }

    private function colWidth(string $key): float
    {
        foreach ($this->columns as $col) {
            if ($col['key'] === $key) {
                return $col['width'];
            }
        }
        return 0.0;
    }

    /** Combined width of the columns before EVIDENCE_TEXT_FROM_COLUMN, where the "Evidence" label sits. */
    private function evidenceLabelWidth(): float
    {
        $w = 0.0;
        foreach ($this->columns as $col) {
            if ($col['key'] === self::EVIDENCE_TEXT_FROM_COLUMN) {
                break;
            }
            $w += $col['width'];
        }
        return $w;
    }

    /** Combined width from EVIDENCE_TEXT_FROM_COLUMN to the table's right edge. */
    private function evidenceTextWidth(): float
    {
        return array_sum(array_column($this->columns, 'width')) - $this->evidenceLabelWidth();
    }

    /**
     * Turns a detection's stored evidence into the display lines for its
     * PDF sub-row: decoded, tidied, hard-wrapped to the text width, and
     * clamped to EVIDENCE_MAX_LINES. Returns [] when there's nothing to show.
     *
     * Decoded once from Qualys's entity encoding, exactly as on the web
     * detail page - see $evidenceText in public/vulnerability_detail.php.
     *
     * Clamped, not shown in full, because the PDF lays out up to
     * REPORT_PDF_MAX_ROWS findings and some evidence runs to hundreds of
     * lines (package lists, file listings): unclamped, one finding could
     * fill several pages and the report would stop being readable. The last
     * line says where the rest is. The CSV export carries evidence in full.
     *
     * Blank lines are dropped - with only a few lines available, spending
     * them on whitespace would hide real content. Lines are hard-wrapped at
     * a fixed character count rather than at spaces: Courier is monospaced
     * so that's exact, and evidence is often unbroken paths and version
     * strings where word-wrapping has nothing to break on anyway.
     *
     * Leaves the current font as Courier; drawTableRow() restores Helvetica.
     *
     * @return string[]
     */
    private function evidenceLines(string $raw): array
    {
        $text = html_entity_decode($raw, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $text = str_replace(["\r\n", "\r", "\t"], ["\n", "\n", '    '], $text);
        // Other control characters have no glyph in the core fonts.
        $text = (string)preg_replace('/[\x00-\x09\x0B-\x1F\x7F]/', '', $text);
        $text = $this->latin1(trim($text));
        if ($text === '') {
            return [];
        }

        $this->SetFont('Courier', '', self::EVIDENCE_FONT_SIZE);
        // One character short of the exact fit, so float rounding can never
        // make MultiCell() decide a full line needs wrapping again.
        $perLine = max(20, (int)floor(($this->evidenceTextWidth() - 2 * $this->cMargin) / $this->GetStringWidth('M')) - 1);

        $lines = [];
        $truncated = false;
        foreach (explode("\n", $text) as $source) {
            $source = rtrim($source);
            if ($source === '') {
                continue;
            }
            // latin1() output is single-byte, so str_split() never cuts a character.
            foreach (str_split($source, $perLine) as $chunk) {
                if (count($lines) === self::EVIDENCE_MAX_LINES) {
                    $truncated = true;
                    break 2;
                }
                $lines[] = $chunk;
            }
        }

        if ($truncated) {
            $lines[self::EVIDENCE_MAX_LINES - 1] = substr(
                '[... truncated - full evidence in the dashboard and the CSV export]',
                0,
                $perLine
            );
        }

        return $lines;
    }

    /**
     * Maps a 1-5 severity level to the same RGB values as this app's own
     * --sev-* CSS custom properties (see public/assets/css/style.css) -
     * kept as plain literals here rather than re-derived from anywhere,
     * since a PDF has no CSS to read from. Level 1 (Informational) is kept
     * as a fallback only - VulnerabilityRepository::getDetectionsForExport()
     * never actually returns it, same as everywhere else in this app.
     *
     * @return array{0: int, 1: int, 2: int}
     */
    private function severityColor(int $level): array
    {
        return match ($level) {
            5 => [178, 58, 58],   // --sev-critical #B23A3A
            4 => [193, 101, 46],  // --sev-high     #C1652E
            3 => [201, 154, 58],  // --sev-medium   #C99A3A
            2 => [76, 139, 114],  // --sev-low      #4C8B72
            default => [91, 107, 124], // --sev-info #5B6B7C
        };
    }

    /**
     * Same UTC -> Europe/London conversion as Helpers::displayQualysDateTime()
     * (last_found is one of the six Qualys-sourced columns still stored in
     * UTC - see that method's docblock for the full list and why), but a
     * compact date-only format since the PDF column is much narrower than
     * anywhere this value is shown on the web dashboard.
     */
    private function formatReportDate(?string $utcDatetime): string
    {
        if ($utcDatetime === null || $utcDatetime === '') {
            return '-';
        }
        try {
            $dt = new \DateTimeImmutable($utcDatetime, new \DateTimeZone('UTC'));
        } catch (\Exception $e) {
            return $utcDatetime;
        }
        return $dt->setTimezone(new \DateTimeZone('Europe/London'))->format('d M Y');
    }

    /**
     * Transliterates UTF-8 text down to Latin-1 for FPDF's core fonts -
     * see this class's own docblock for why. Falls back to the original
     * string if iconv itself fails outright (should not happen for
     * well-formed input) rather than emitting an empty cell.
     */
    private function latin1(string $utf8): string
    {
        $converted = @iconv('UTF-8', 'ISO-8859-1//TRANSLIT//IGNORE', $utf8);
        return $converted !== false ? $converted : $utf8;
    }

    /**
     * Counts how many lines MultiCell() would wrap $txt into inside a cell
     * of width $w at the current font - adapted from MultiCell()'s own
     * line-break arithmetic just above in this same vendored file, with
     * the actual cell-drawing calls stripped out and a line counter kept
     * in their place instead. Needed because a table built from several
     * MultiCell() columns per row (see drawTableRow()) has to know each
     * row's total height *before* drawing anything for that row, to place
     * the zebra-stripe background and severity stripe at the right size
     * and to decide whether the row still fits on the current page.
     */
    private function NbLines(float $w, string $txt): int
    {
        $cw = $this->CurrentFont['cw'];
        if ($w <= 0) {
            $w = $this->w - $this->rMargin - $this->x;
        }
        $wmax = ($w - 2 * $this->cMargin) * 1000 / $this->FontSize;
        $s = str_replace("\r", '', $txt);
        $nb = strlen($s);
        if ($nb > 0 && $s[$nb - 1] === "\n") {
            $nb--;
        }
        $sep = -1;
        $i = 0;
        $j = 0;
        $l = 0;
        $nl = 1;
        while ($i < $nb) {
            $c = $s[$i];
            if ($c === "\n") {
                $i++;
                $sep = -1;
                $j = $i;
                $l = 0;
                $nl++;
                continue;
            }
            if ($c === ' ') {
                $sep = $i;
            }
            $l += $cw[$c] ?? 0;
            if ($l > $wmax) {
                if ($sep === -1) {
                    if ($i === $j) {
                        $i++;
                    }
                } else {
                    $i = $sep + 1;
                }
                $sep = -1;
                $j = $i;
                $l = 0;
                $nl++;
            } else {
                $i++;
            }
        }
        return $nl;
    }

    /**
     * Shortens $text (appending "...") until MultiCell() would wrap it
     * into no more than $maxLines lines at width $w - trims whole words
     * first, falling back to a hard character cut only for a single
     * unbroken "word" longer than the whole cell (shouldn't happen for
     * anything this app actually stores, but bounds the loop either way).
     */
    private function clampToLines(string $text, float $w, int $maxLines): string
    {
        if ($this->NbLines($w, $text) <= $maxLines) {
            return $text;
        }

        $words = explode(' ', $text);
        while (count($words) > 1) {
            array_pop($words);
            $candidate = implode(' ', $words) . '...';
            if ($this->NbLines($w, $candidate) <= $maxLines) {
                return $candidate;
            }
        }

        return mb_substr($text, 0, 200) . '...';
    }

    /**
     * Shortens $text (appending "...") until it fits on a single line
     * within width $w - used for the Asset column, which (unlike Title) is
     * never allowed to wrap, since hostname/IP are expected to be short
     * and a wrapped Asset column would make the row-height math in
     * renderDetailTable() (which only measures the Title column) wrong.
     */
    private function truncateToWidth(string $text, float $w): string
    {
        $wmax = $w - 2 * $this->cMargin;
        if ($this->GetStringWidth($text) <= $wmax) {
            return $text;
        }

        while ($text !== '' && $this->GetStringWidth($text . '...') > $wmax) {
            $text = mb_substr($text, 0, -1);
        }
        return $text . '...';
    }
}
