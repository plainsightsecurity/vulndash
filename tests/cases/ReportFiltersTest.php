<?php
declare(strict_types=1);

// KEV / EPSS / CE+ filters shared by the Vulnerabilities page, the Reports
// preview and both exports, plus the PDF's KEV and EPSS columns.

use VulnDash\Lib\PdfReport;
use VulnDash\Lib\VulnerabilityRepository as V;

test('KEV filter keeps only CISA KEV findings', function () {
    seed_estate();
    eq(V::getDetectionsCount([], true, ['kev_only' => true]), 1);
    eq(V::getDetectionsForExport([], true, ['kev_only' => true])[0]['qid'] ?? null, 5001);
});

test('EPSS floor filter', function () {
    seed_estate();
    eq(V::getDetectionsCount([], true, ['min_epss' => 0.1]), 2, '>= 10%');
    eq(V::getDetectionsCount([], true, ['min_epss' => 0.5]), 1, '>= 50%');
    eq(V::getDetectionsCount([], true, ['min_epss' => 0.0001]), 3, 'unscored QIDs never match');
});

test('CE+ filter', function () {
    seed_estate();
    eq(V::getDetectionsCount([], true, ['ce_plus_only' => true]), 2);
});

test('filters combine with tenant scope', function () {
    seed_estate();
    eq(V::getDetectionsCount([2], false, ['ce_plus_only' => true, 'kev_only' => true], null, false, 2), 0);
    eq(V::getDetectionsCount([1], false, ['kev_only' => true, 'min_epss' => 0.5], null, false, 2), 1);
});

test('PDF builds with KEV and EPSS columns', function () {
    seed_estate();
    $rows = V::getDetectionsForExport([], true, [], null, 2000);
    $pdf = new PdfReport();
    $pdf->SetCompression(false);
    $pdf->buildReport(
        ['scope' => 'All tags', 'filters' => '', 'generatedAt' => 'now', 'generatedBy' => 'tests'],
        [5 => 1, 4 => 1, 3 => 1, 2 => 1], 4, $rows, false, 2000, 0, 0
    );
    $out = $pdf->Output('S');
    ok(str_starts_with($out, '%PDF'), 'output is a PDF');
    foreach (['(EPSS)', '(KEV)', '(97.0%)', '(12.0%)', '(<0.1%)', '(n/a)', '(host-untagged)'] as $needle) {
        ok(str_contains($out, $needle), "PDF contains $needle");
    }
});
