<?php
declare(strict_types=1);

require_once __DIR__ . '/../../src/bootstrap.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Auth;
use VulnDash\Lib\Helpers;

Auth::requireAdmin();

/**
 * Short, friendly label for a logged endpoint path - falls back to the
 * raw path itself for anything not explicitly named here, so a future
 * Qualys endpoint this app starts calling still shows up correctly
 * without needing a code change first.
 */
function friendlyEndpointLabel(string $endpoint): string
{
    $known = [
        '/fo/asset/host/vm/detection/' => 'Host Detection',
        '/fo/asset/host/'              => 'Host List',
        '/fo/knowledge_base/vuln/'     => 'KnowledgeBase',
    ];
    return $known[$endpoint] ?? $endpoint;
}

$endpoints = ApiCallLogRepository::getEndpoints();
$dailyTotals = ApiCallLogRepository::getDailyTotals(30);
$hourlyTotals = ApiCallLogRepository::getHourlyTotals(24);

// Per-endpoint-and-version figures replace the old single "N of M remaining"
// line, which only ever described whichever endpoint and version the last
// call happened to use - Qualys counts its limit per endpoint per version
// (25 each per 24h since 2026-10). Caught so the rest of the page still works if the code is
// deployed before database/migrations/2026-10-add-api-version-to-call-log.sql.
$versionSummary = null;
try {
    $versionSummary = ApiCallLogRepository::getVersionSummary(24);
} catch (\PDOException $e) {
    $versionSummary = null;
}

$pageTitle = 'API Usage';
require __DIR__ . '/../../src/views/header.php';
?>

<h1>API Usage</h1>
<p class="page-subtitle">Every call this app has made to Qualys, one row per physical HTTP request - not per sync run, since a single run can make several once pagination kicks in.</p>

<?php if ($versionSummary === null): ?>
<div class="chart-panel">
    <p class="chart-empty">Per-version figures need database/migrations/2026-10-add-api-version-to-call-log.sql applied.</p>
</div>
<?php elseif (!empty($versionSummary)): ?>
<div class="chart-panel">
    <div class="chart-panel-header">
        <h2>By API version and endpoint</h2>
        <span class="chart-panel-hint">Qualys limits each endpoint on each version separately</span>
    </div>
    <div class="table-wrap">
        <table class="vuln-table admin-table">
            <thead>
                <tr>
                    <th>Version</th>
                    <th>Endpoint</th>
                    <th class="col-num">Calls made (last 24h)</th>
                    <th class="col-num">Left (per Qualys)</th>
                    <th>As of</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($versionSummary as $row): ?>
                <tr>
                    <td class="mono"><?= $row['api_version'] === null ? 'Not recorded' : Helpers::e($row['api_version'] === 'QPS' ? 'QPS' : '/api/' . $row['api_version'] . '/') ?></td>
                    <td><?= $row['endpoint'] === null ? 'All endpoints' : Helpers::e(friendlyEndpointLabel($row['endpoint'])) ?></td>
                    <td class="mono col-num"><?= number_format($row['calls']) ?></td>
                    <td class="mono col-num"><?= $row['remaining'] !== null ? '<strong>' . number_format($row['remaining']) . '</strong>' . ($row['limit'] !== null ? ' of ' . number_format($row['limit']) : '') : '—' ?></td>
                    <td><?= $row['reported_at'] !== null ? Helpers::e(Helpers::relativeTime($row['reported_at'])) : '—' ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <p class="checkbox-hint" style="margin: 0.75rem 0 0;">"Left" is Qualys's own authoritative figure from the last call on that endpoint and version; Qualys's window is rolling, so calls free up again 24 hours after they were made. "Not recorded" is calls logged before the version was tracked.</p>
</div>
<?php endif; ?>

<?php if (empty($endpoints)): ?>
<div class="chart-panel">
    <p class="chart-empty">No API calls logged yet. This fills in as the sync scripts run.</p>
</div>
<?php else: ?>

<div class="chart-panel">
    <div class="chart-panel-header">
        <h2>Last 24 hours</h2>
        <span class="chart-panel-hint">Most recent hour first</span>
    </div>
    <div class="table-wrap">
        <table class="vuln-table admin-table">
            <thead>
                <tr>
                    <th>Hour</th>
                    <?php foreach ($endpoints as $endpoint): ?>
                    <th><?= Helpers::e(friendlyEndpointLabel($endpoint)) ?></th>
                    <?php endforeach; ?>
                    <th>Total</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($hourlyTotals as $period => $counts): ?>
                <tr>
                    <td class="mono"><?= Helpers::e($period) ?></td>
                    <?php foreach ($endpoints as $endpoint): ?>
                    <td class="mono"><?= number_format($counts[$endpoint] ?? 0) ?></td>
                    <?php endforeach; ?>
                    <td class="mono"><strong><?= number_format($counts['total']) ?></strong></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<div class="chart-panel">
    <div class="chart-panel-header">
        <h2>Last 30 days</h2>
        <span class="chart-panel-hint">Most recent day first</span>
    </div>
    <div class="table-wrap">
        <table class="vuln-table admin-table">
            <thead>
                <tr>
                    <th>Day</th>
                    <?php foreach ($endpoints as $endpoint): ?>
                    <th><?= Helpers::e(friendlyEndpointLabel($endpoint)) ?></th>
                    <?php endforeach; ?>
                    <th>Total</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($dailyTotals as $period => $counts): ?>
                <tr>
                    <td class="mono"><?= Helpers::e($period) ?></td>
                    <?php foreach ($endpoints as $endpoint): ?>
                    <td class="mono"><?= number_format($counts[$endpoint] ?? 0) ?></td>
                    <?php endforeach; ?>
                    <td class="mono"><strong><?= number_format($counts['total']) ?></strong></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<?php endif; ?>

<?php require __DIR__ . '/../../src/views/footer.php'; ?>
