<?php
declare(strict_types=1);

// Smoke-tests every page as an admin and as a client against the standard
// seeded estate: each must render without a PHP warning, notice or fatal,
// admin-only pages must refuse a client, and nothing from another tenant
// (host-b) or from untagged assets (host-untagged) may appear in a client's
// pages or exports.

require __DIR__ . '/lib.php';

reset_db();
seed_estate();

const OTHER_TENANTS = ['host-b', 'host-untagged'];

// [role, page, query, expect, mustContain[], mustNotContain[]]
// expect: html (complete page), 403, empty (redirect / no body), pdf, csv
$cases = [
    ['anon',   'login.php',              '',                  'html',  ['password'], []],
    ['anon',   'dashboard.php',          '',                  'empty', [], []],
    ['admin',  'dashboard.php',          '',                  'html',  [], []],
    ['admin',  'assets.php',             '',                  'html',  ['host-a', 'host-b', 'host-untagged'], []],
    ['admin',  'assets.php',             'stale=1',           'html',  [], []],
    ['admin',  'vulnerabilities.php',    '',                  'html',  ['host-b'], []],
    ['admin',  'vulnerabilities.php',    'severity=5&ce_plus_only=1&kev=1&min_epss=0.5', 'html', ['host-a'], ['host-b']],
    ['admin',  'vulnerability_detail.php', 'id=3',            'html',  ['host-b'], []],
    ['admin',  'reports.php',            'kev=1&min_epss=0.1', 'html', ['Known exploited (CISA KEV) only'], []],
    ['admin',  'report_pdf.php',         '',                  'pdf',   [], []],
    ['admin',  'report_csv.php',         '',                  'csv',   ['host-untagged'], []],
    ['admin',  'trends.php',             '',                  'html',  [], []],
    ['admin',  'top_fixes.php',          '',                  'html',  ['Fixing the top 4', 'Critical remote code execution'], []],
    ['admin',  'top_fixes.php',          'view_tag=2&limit=50', 'html', ['High severity flaw'], ['Critical remote code execution']],
    ['admin',  'search.php',             'q=host',            'html',  [], []],
    ['admin',  'ce_readiness.php',       '',                  'html',  [], []],
    ['admin',  'preferences.php',        '',                  'html',  [], []],
    ['admin',  'mfa.php',                '',                  'html',  [], []],
    ['admin',  'password.php',           '',                  'html',  [], []],
    ['admin',  'admin/users.php',        '',                  'html',  ['client'], []],
    ['admin',  'admin/api_usage.php',    '',                  'html',  [], []],
    ['client', 'dashboard.php',          '',                  'html',  [], OTHER_TENANTS],
    ['client', 'assets.php',             '',                  'html',  ['host-a'], OTHER_TENANTS],
    ['client', 'vulnerabilities.php',    '',                  'html',  ['host-a'], OTHER_TENANTS],
    ['client', 'vulnerabilities.php',    'view_tag=2',        'html',  [], OTHER_TENANTS],
    ['client', 'vulnerability_detail.php', 'id=1',            'html',  ['host-a'], []],
    ['client', 'vulnerability_detail.php', 'id=3',            'any',   [], OTHER_TENANTS],
    ['client', 'reports.php',            '',                  'html',  [], OTHER_TENANTS],
    ['client', 'report_csv.php',         '',                  'csv',   ['host-a'], OTHER_TENANTS],
    ['client', 'report_pdf.php',         '',                  'pdf',   [], []],
    ['client', 'trends.php',             '',                  'html',  [], OTHER_TENANTS],
    ['client', 'top_fixes.php',          '',                  'html',  ['Critical remote code execution'], ['High severity flaw', 'Low banner disclosure']],
    ['client', 'top_fixes.php',          'view_tag=2',        'html',  [], ['High severity flaw', 'Low banner disclosure']],
    ['client', 'search.php',             'q=host',            'html',  [], OTHER_TENANTS],
    ['client', 'ce_readiness.php',       '',                  'html',  [], OTHER_TENANTS],
    ['client', 'preferences.php',        '',                  'html',  ['Exploited-vulnerability alerts'], []],
    ['client', 'admin/users.php',        '',                  '403',   [], []],
    ['client', 'admin/api_usage.php',    '',                  '403',   [], []],
];

$pass = 0;
$failed = [];
foreach ($cases as [$role, $page, $query, $expect, $must, $mustNot]) {
    $label = "$role  $page" . ($query !== '' ? "?$query" : '');
    $cmd = [PHP_BINARY, __DIR__ . '/render_page.php', $page, $query, $role];
    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $out = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    proc_close($proc);

    $problems = [];
    if (preg_match_all('/^PHPERR: .*$/m', $out, $m)) {
        $problems = array_merge($problems, array_unique($m[0]));
    }
    if (trim($err) !== '') {
        $problems[] = 'stderr: ' . trim(substr($err, 0, 300));
    }
    switch ($expect) {
        case 'html':
            if (!str_contains($out, '</html>')) $problems[] = 'no complete HTML page';
            if (str_contains($out, '403 Forbidden')) $problems[] = 'got 403';
            break;
        case '403':
            if (!str_contains($out, '403 Forbidden')) $problems[] = 'expected 403 Forbidden';
            break;
        case 'empty':
            if (trim($out) !== '') $problems[] = 'expected no body (redirect)';
            break;
        case 'pdf':
            if (!str_starts_with($out, '%PDF')) $problems[] = 'not a PDF';
            break;
        case 'csv':
            if (!str_starts_with($out, "\xEF\xBB\xBFHostname,")) $problems[] = 'not the CSV export';
            break;
    }
    foreach ($must as $s) {
        if (!str_contains($out, $s)) $problems[] = "missing '$s'";
    }
    foreach ($mustNot as $s) {
        if (str_contains($out, $s)) $problems[] = "LEAK: contains '$s'";
    }

    if ($problems === []) {
        echo "  ok    $label\n";
        $pass++;
    } else {
        echo "  FAIL  $label\n        " . implode("\n        ", $problems) . "\n";
        $failed[] = $label;
    }
}

echo "\n$pass passed, " . count($failed) . " failed\n";
exit($failed === [] ? 0 : 1);
