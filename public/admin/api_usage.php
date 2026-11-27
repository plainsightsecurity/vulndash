<?php
declare(strict_types=1);

require_once __DIR__ . '/../../src/bootstrap.php';

use VulnDash\Lib\ApiBudget;
use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Auth;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\ServerHealth;

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

// Forecast and auto interval - see src/Lib/ApiBudget.php.
$budget = null;
try {
    $budgetIn = ApiBudget::currentInputs();
    $autoState = ApiBudget::autoState();
    $autoOn = ApiBudget::autoEnabled();
    $currentInterval = $autoOn ? (int)($autoState['interval'] ?? ApiBudget::chooseInterval($budgetIn)['interval']) : $budgetIn['cron_minutes'];
    $budget = [
        'in'       => $budgetIn,
        'auto'     => $autoOn,
        'state'    => $autoState,
        'interval' => $currentInterval,
        'forecast' => ApiBudget::forecast($budgetIn, $currentInterval),
        'usable'   => ApiBudget::usable($budgetIn),
        'capacity' => array_combine($budgetIn['intervals'], array_map(fn (int $i) => ApiBudget::assetCapacity($budgetIn, $i), $budgetIn['intervals'])),
    ];
} catch (\Throwable $e) {
    $budget = null;
}

$pageTitle = 'API Usage';
require __DIR__ . '/../../src/views/header.php';
?>

<h1>API Usage</h1>
<p class="page-subtitle">Every call this app has made to Qualys, one row per physical HTTP request - not per sync run, since a single run can make several once pagination kicks in.</p>

<?php if ($budget !== null):
    $in = $budget['in'];
    $fullPages = ApiBudget::fullPages($in['assets'], $in['page_size']);
    $status = static function (float $calls) use ($budget, $in): string {
        if ($calls > $budget['usable']) {
            return '<span class="badge badge-danger">Over</span>';
        }
        return $calls > $budget['usable'] - 4 ? '<span class="badge badge-warn">Tight</span>' : '<span class="badge badge-active">OK</span>';
    };
?>
<div class="chart-panel">
    <div class="chart-panel-header">
        <h2>Forecast</h2>
        <span class="chart-panel-hint">Host Detection and Host List calls per day at the current estate size</span>
    </div>
    <p style="margin: 0 0 0.75rem;">
        Host sync: <strong>every <?= (int)$budget['interval'] ?> minutes</strong>
        <?php if ($budget['auto']): ?>
        <span class="badge badge-accent">auto</span>
        <?php if (isset($budget['state']['decided_at'])): ?><span class="checkbox-hint">decided <?= Helpers::e(Helpers::relativeTime(date('Y-m-d H:i:s', (int)$budget['state']['decided_at']))) ?></span><?php endif; ?>
        <?php else: ?>
        <span class="badge badge-neutral">fixed</span> <span class="checkbox-hint">(sync.host_detection_auto_interval is off)</span>
        <?php endif; ?>
        <br>
        <span class="checkbox-hint">
            <?= number_format($in['assets']) ?> assets at <?= number_format($in['page_size']) ?> per page = <?= $fullPages ?> page<?= $fullPages === 1 ? '' : 's' ?> per full pull;
            incremental pulls average <?= rtrim(rtrim(number_format($in['inc_pages'], 2), '0'), '.') ?> page<?= $in['inc_pages'] == 1 ? '' : 's' ?>.
            Usable per endpoint and version: <?= $budget['usable'] ?> a day (limit <?= $in['limit'] ?> less the <?= $in['reserve'] ?>-call reserve).
        </span>
    </p>
    <div class="table-wrap">
        <table class="vuln-table admin-table">
            <thead>
                <tr>
                    <th>Version</th>
                    <th class="col-num">Host Detection / day</th>
                    <th>&nbsp;</th>
                    <th class="col-num">Host List / day</th>
                    <th>&nbsp;</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($budget['forecast'] as $version => $f): ?>
                <tr>
                    <td class="mono">/api/<?= Helpers::e($version) ?>/</td>
                    <td class="mono col-num"><?= (int)ceil($f['detection']) ?></td>
                    <td><?= $status($f['detection']) ?></td>
                    <td class="mono col-num"><?= (int)ceil($f['host_list']) ?></td>
                    <td><?= $status($f['host_list']) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <p class="checkbox-hint" style="margin: 0.75rem 0 0;">
        Roughly how many assets fit:
        <?php $parts = [];
        foreach ($budget['capacity'] as $interval => $cap) {
            $parts[] = 'every ' . $interval . ' min: ' . ($cap === null ? 'none' : 'up to ~' . number_format($cap));
        }
        echo Helpers::e(implode(' · ', $parts)); ?>.
        <?php if ($budget['auto']): ?>The sync picks the shortest interval that fits and emails admins when it changes or an endpoint runs low.<?php endif; ?>
    </p>
</div>
<?php endif; ?>

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

<?php
// Server: disk space and database size (src/Lib/ServerHealth.php). Alerts at
// alerts.disk_warn_percent come from scripts/send_sync_alerts.php.
$filesystems = ServerHealth::filesystems();
$dbSize = ServerHealth::databaseSize();
$diskWarn = ServerHealth::warnPercent();
?>
<div class="chart-panel" id="server">
    <div class="chart-panel-header">
        <h2>Server</h2>
        <span class="chart-panel-hint">Disk space and database size - admins are emailed when a disk reaches <?= $diskWarn ?>% full</span>
    </div>
    <div class="table-wrap">
        <table class="vuln-table admin-table">
            <thead><tr><th>Disk</th><th>Holds</th><th class="col-num">Used</th><th class="col-num">Free</th><th class="col-num">Size</th></tr></thead>
            <tbody>
                <?php if ($filesystems === []): ?>
                <tr class="empty-row"><td colspan="5">Couldn't read disk space on this server.</td></tr>
                <?php else: foreach ($filesystems as $fs): ?>
                <tr>
                    <td class="mono"><?= Helpers::e($fs['mount']) ?></td>
                    <td><?= Helpers::e(implode(', ', $fs['holds'])) ?></td>
                    <td class="col-num mono"><?= Helpers::e(number_format($fs['used_pct'], 1)) ?>%
                        <?php if ($fs['used_pct'] >= $diskWarn): ?><span class="badge badge-danger">Low on space</span><?php endif; ?></td>
                    <td class="col-num mono"><?= Helpers::e(ServerHealth::bytes($fs['free'])) ?></td>
                    <td class="col-num mono"><?= Helpers::e(ServerHealth::bytes($fs['total'])) ?></td>
                </tr>
                <?php endforeach; endif; ?>
            </tbody>
        </table>
    </div>
    <p style="margin: 1rem 0 0.5rem;">Database: <strong><?= Helpers::e(ServerHealth::bytes($dbSize['total'])) ?></strong> (data and indexes). Largest tables:</p>
    <div class="table-wrap">
        <table class="vuln-table admin-table">
            <thead><tr><th>Table</th><th class="col-num">Size</th><th class="col-num">Rows (approx.)</th></tr></thead>
            <tbody>
                <?php foreach ($dbSize['tables'] as $t): ?>
                <tr>
                    <td class="mono"><?= Helpers::e($t['name']) ?></td>
                    <td class="col-num mono"><?= Helpers::e(ServerHealth::bytes($t['bytes'])) ?></td>
                    <td class="col-num mono"><?= number_format($t['rows']) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<?php require __DIR__ . '/../../src/views/footer.php'; ?>
