<?php
declare(strict_types=1);

// CE+ scoring rules from the project spec: CVSS3 first, then CVSS2, then the
// Qualys severity midpoint (High 7.95, Critical 9.5); fail at >= 7.0; titles
// marked "Zero Day" never fail (no fix exists yet).

use VulnDash\Lib\CvssCalculator as C;

test('CVSS3 base is used when present', function () {
    $r = C::calculate(6.5, 9.0, 5, 'x');
    eq($r['score'], 6.5);
    eq($r['source'], 'CVSS3');
    eq($r['is_ce_plus_fail'], false);
});

test('CVSS2 is used when there is no CVSS3', function () {
    $r = C::calculate(null, 7.2, 3, 'x');
    eq([$r['score'], $r['source'], $r['is_ce_plus_fail']], [7.2, 'CVSS2', true]);
});

test('a zero CVSS3 counts as missing', function () {
    eq(C::calculate(0.0, 7.2, 3, 'x')['source'], 'CVSS2');
});

test('severity midpoints when no CVSS at all', function () {
    eq(C::calculate(null, null, 5, 'x')['score'], 9.5, 'Critical');
    eq(C::calculate(null, null, 4, 'x')['score'], 7.95, 'High');
    eq(C::calculate(null, null, 4, 'x')['is_ce_plus_fail'], true, 'High fails CE+');
    eq(C::calculate(null, null, 3, 'x')['is_ce_plus_fail'], false, 'Medium passes CE+');
    eq(C::calculate(null, null, 4, 'x')['source'], 'QUALYS_SEVERITY_ESTIMATE');
});

test('threshold is inclusive at 7.0', function () {
    eq(C::calculate(7.0, null, 4, 'x')['is_ce_plus_fail'], true, '7.0');
    eq(C::calculate(6.9, null, 4, 'x')['is_ce_plus_fail'], false, '6.9');
});

test('zero-day titles never fail CE+', function () {
    foreach (['Foo RCE (Zero Day)', 'Foo - Zero Day', 'Foo (ZeroDay)', 'foo zero-day bar'] as $title) {
        $r = C::calculate(9.8, null, 5, $title);
        eq([$r['is_ce_plus_fail'], $r['is_zero_day']], [false, true], $title);
    }
    eq(C::calculate(9.8, null, 5, 'Zerodays Corp agent RCE')['is_zero_day'], false, 'needs a word boundary');
});
