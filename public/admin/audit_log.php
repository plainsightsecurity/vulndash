<?php
declare(strict_types=1);

require_once __DIR__ . '/../../src/bootstrap.php';

use VulnDash\Lib\AuditLog;
use VulnDash\Lib\Auth;
use VulnDash\Lib\Helpers;

// Admin-only view of the audit log (src/Lib/AuditLog.php): sign-ins, account
// security changes, admin actions, hides, scan/uninstall requests, remediation
// edits and report exports. Read-only - nothing here can change or delete a row.
Auth::requireAdmin();

$areas = [
    'auth'    => 'Sign-ins',
    'account' => 'Account security',
    'admin'   => 'Admin actions',
    'finding' => 'Hidden findings',
    'scan'    => 'Scan requests',
    'agent'   => 'Agent uninstalls',
    'report'  => 'Report exports',
];

$isDate = static fn (string $v): bool => preg_match('/^\d{4}-\d{2}-\d{2}$/', $v) === 1 && strtotime($v) !== false;
$get = static fn (string $k): string => trim((string)($_GET[$k] ?? ''));

$filters = [
    'user'   => $get('user') !== '' ? $get('user') : null,
    'area'   => isset($areas[$get('area')]) ? $get('area') : null,
    'action' => isset(AuditLog::ACTION_LABELS[$get('action')]) ? $get('action') : null,
    'from'   => $isDate($get('from')) ? $get('from') : null,
    'to'     => $isDate($get('to')) ? $get('to') : null,
    'q'      => $get('q') !== '' ? mb_substr($get('q'), 0, 100) : null,
];

/** Details as "key: value" pairs, nested lists flattened - compact enough for a table cell. */
$detailText = static function (array $details): string {
    // MySQL's JSON type stores keys in its own order; put before/after back
    // in reading order.
    $details = array_merge(array_intersect_key(['before' => null, 'after' => null], $details), $details);
    $parts = [];
    foreach ($details as $k => $v) {
        if (is_array($v)) {
            $v = array_is_list($v) ? implode(', ', array_map('strval', $v)) : json_encode($v, JSON_UNESCAPED_SLASHES);
        } elseif (is_bool($v)) {
            $v = $v ? 'yes' : 'no';
        } elseif ($v === null) {
            $v = '-';
        }
        $parts[] = str_replace('_', ' ', (string)$k) . ': ' . ($v === '' ? '(none)' : (string)$v);
    }
    return implode('; ', $parts);
};

// CSV download of everything matching the current filters (no paging).
if (($_GET['format'] ?? '') === 'csv') {
    $rows = AuditLog::search($filters, 100000);
    AuditLog::record('report.exported', [
        'target_type'  => 'report',
        'target_label' => 'Audit log CSV',
        'details'      => ['format' => 'audit-csv', 'rows' => count($rows), 'filters' => array_filter($filters)],
    ]);
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="vulndash-audit-log-' . date('Y-m-d-His') . '.csv"');
    header('Cache-Control: private, max-age=0, must-revalidate');
    $out = fopen('php://output', 'w');
    fwrite($out, "\xEF\xBB\xBF");
    fputcsv($out, ['Time (UK)', 'User', 'Action', 'Action code', 'Target', 'Details', 'IP address']);
    foreach ($rows as $r) {
        fputcsv($out, array_map([Helpers::class, 'csvSafe'], [
            (string)$r['occurred_at'],
            (string)($r['username'] ?? ''),
            AuditLog::label((string)$r['action']),
            (string)$r['action'],
            (string)($r['target_label'] ?? ''),
            $detailText($r['details']),
            (string)($r['ip_address'] ?? ''),
        ]));
    }
    fclose($out);
    exit;
}

$perPage    = 50;
$total      = AuditLog::count($filters);
$totalPages = max(1, (int)ceil($total / $perPage));
$page       = min(max(1, (int)($_GET['page'] ?? 1)), $totalPages);
$rows       = AuditLog::search($filters, $perPage, ($page - 1) * $perPage);
$actors     = AuditLog::actors();

$pageQuery = static function (array $changes): string {
    $q = array_filter(array_merge($_GET, $changes), static fn ($v) => $v !== null && $v !== '');
    return '?' . http_build_query($q);
};

$failureActions = ['auth.login_failed', 'auth.account_locked', 'auth.mfa_failed'];

$pageTitle = 'Audit Log';
require __DIR__ . '/../../src/views/header.php';
?>

<div class="page-heading">
    <h1>Audit Log</h1>
    <p class="page-subtitle">Who did what: sign-ins, account security changes, admin actions, hidden findings, scan and uninstall requests, remediation edits and report exports. Kept for <?= AuditLog::retentionDays() ?> days. Times are UK time.</p>
</div>

<form method="get" class="filter-bar">
    <label class="field field-inline">
        <span>User</span>
        <select name="user">
            <option value="">Anyone</option>
            <?php foreach ($actors as $a): ?>
            <option value="<?= Helpers::e($a) ?>" <?= $filters['user'] === $a ? 'selected' : '' ?>><?= Helpers::e($a) ?></option>
            <?php endforeach; ?>
        </select>
    </label>

    <label class="field field-inline">
        <span>Activity</span>
        <select name="action">
            <option value="">All activity</option>
            <?php foreach ($areas as $areaKey => $areaLabel): ?>
            <optgroup label="<?= Helpers::e($areaLabel) ?>">
                <?php foreach (AuditLog::ACTION_LABELS as $code => $label):
                    if (!str_starts_with($code, $areaKey . '.')) { continue; } ?>
                <option value="<?= Helpers::e($code) ?>" <?= $filters['action'] === $code ? 'selected' : '' ?>><?= Helpers::e($label) ?></option>
                <?php endforeach; ?>
            </optgroup>
            <?php endforeach; ?>
        </select>
    </label>

    <label class="field field-inline">
        <span>From</span>
        <input type="date" name="from" value="<?= Helpers::e($filters['from'] ?? '') ?>">
    </label>
    <label class="field field-inline">
        <span>To</span>
        <input type="date" name="to" value="<?= Helpers::e($filters['to'] ?? '') ?>">
    </label>
    <label class="field field-inline">
        <span>Search</span>
        <input type="search" name="q" value="<?= Helpers::e($filters['q'] ?? '') ?>" placeholder="Account, host, QID, IP...">
    </label>

    <?php if ($filters['area'] !== null && $filters['action'] === null): ?>
    <input type="hidden" name="area" value="<?= Helpers::e($filters['area']) ?>">
    <?php endif; ?>
    <button type="submit" class="btn btn-primary">Filter</button>
    <?php if (array_filter($filters)): ?>
    <a class="btn btn-secondary" href="/admin/audit_log">Clear</a>
    <?php endif; ?>
</form>

<div class="audit-toolbar">
    <span class="audit-count"><?= number_format($total) ?> event<?= $total === 1 ? '' : 's' ?><?= $filters['area'] !== null && $filters['action'] === null ? ' &middot; ' . Helpers::e($areas[$filters['area']]) : '' ?></span>
    <span class="audit-quick">
        <a href="<?= Helpers::e($pageQuery(['area' => null, 'action' => 'auth.login_failed', 'page' => null])) ?>">Failed sign-ins</a>
        &middot;
        <a href="<?= Helpers::e($pageQuery(['action' => null, 'area' => 'admin', 'page' => null])) ?>">Admin actions</a>
        &middot;
        <a href="<?= Helpers::e($pageQuery(['action' => null, 'area' => 'report', 'page' => null])) ?>">Exports</a>
    </span>
    <?php if ($total > 0): ?>
    <a class="btn btn-secondary" href="<?= Helpers::e($pageQuery(['format' => 'csv', 'page' => null])) ?>">Download CSV</a>
    <?php endif; ?>
</div>

<?php if ($rows === []): ?>
<div class="panel"><p class="chart-empty">No events match these filters.</p></div>
<?php else: ?>
<div class="table-wrap">
<table class="vuln-table audit-table">
    <thead>
        <tr>
            <th>When</th>
            <th>User</th>
            <th>Action</th>
            <th>Target</th>
            <th>Details</th>
            <th>IP address</th>
        </tr>
    </thead>
    <tbody>
        <?php foreach ($rows as $r):
            $action = (string)$r['action'];
            $isFailure = in_array($action, $failureActions, true);
        ?>
        <tr class="<?= $isFailure ? 'audit-failure' : '' ?>">
            <td class="mono nowrap" title="<?= Helpers::e(Helpers::relativeTime((string)$r['occurred_at'])) ?>"><?= Helpers::e(date('j M Y H:i:s', strtotime((string)$r['occurred_at']))) ?></td>
            <td>
                <?php if ($r['username'] !== null): ?>
                <a href="<?= Helpers::e($pageQuery(['user' => $r['username'], 'page' => null])) ?>"><?= Helpers::e((string)$r['username']) ?></a>
                <?php else: ?>
                <span class="muted">&mdash;</span>
                <?php endif; ?>
            </td>
            <td>
                <?= Helpers::e(AuditLog::label($action)) ?>
                <span class="audit-code mono"><?= Helpers::e($action) ?></span>
            </td>
            <td><?= Helpers::e((string)($r['target_label'] ?? '')) ?></td>
            <td class="audit-details"><?= Helpers::e($detailText($r['details'])) ?></td>
            <td class="mono"><?php if ($r['ip_address'] !== null): ?><a href="<?= Helpers::e($pageQuery(['q' => $r['ip_address'], 'page' => null])) ?>"><?= Helpers::e((string)$r['ip_address']) ?></a><?php endif; ?></td>
        </tr>
        <?php endforeach; ?>
    </tbody>
</table>
</div>

<?php if ($totalPages > 1): ?>
<nav class="pagination" aria-label="Pagination">
    <?php if ($page > 1): ?><a href="<?= Helpers::e($pageQuery(['page' => $page - 1])) ?>">&larr; Newer</a><?php endif; ?>
    <span class="pagination-status">Page <?= $page ?> of <?= number_format($totalPages) ?></span>
    <?php if ($page < $totalPages): ?><a href="<?= Helpers::e($pageQuery(['page' => $page + 1])) ?>">Older &rarr;</a><?php endif; ?>
</nav>
<?php endif; ?>
<?php endif; ?>

<?php require __DIR__ . '/../../src/views/footer.php'; ?>
