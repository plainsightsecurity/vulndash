#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Sends the scan_request_queue to Qualys: every pending "scan this asset now"
 * request from the Assets page goes out in ONE bulk Cloud Agent on-demand
 * scan call (QualysApiClient::launchOnDemandScanByAssetIds()).
 *
 * Call budget: the on-demand scan endpoint allows 25 calls per 24h and
 * exists only under /qps/rest/1.0/ (scripts/check_ods_api_versions.php found
 * 2.0-7.0 all refuse it, 2026-11-10), so there's no other version to rotate
 * across. Every waiting request goes in the same call, however many there
 * are. A send goes as soon as anything is queued, as long as
 * ScanRequestRepository::sendWindow() allows it: fewer than
 * qualys.ods_daily_budget calls (default 22) in the last 24h, and at least
 * qualys.ods_min_interval_minutes (default 10) since the last call, so a
 * burst of requests is batched, and - on busy days - paced so the budget
 * lasts through the day (qualys.ods_burst, default 6; see sendWindow()). Both are counted from qualys_api_call_log,
 * so failed calls and manual probes count, as they do at Qualys. A run with
 * nothing pending, or not yet allowed to send, makes no call. (Until
 * 2026-11-10 this was a fixed 60-minute gap, which made most requests wait
 * up to an hour on days when the budget was nowhere near used.)
 *
 * Targeting is by AssetView id (assets.qualys_asset_id), with the same
 * tagName EQUALS <agent_scope_tag> guard as the uninstall worker. A request
 * still missing that id is resolved with one Host Asset search call (100
 * hosts per call), and the id is stored on the asset so it is only ever
 * looked up once. If that search succeeds but Qualys has no such host, the
 * request fails with ScanRequestRepository::NOTE_NOT_FOUND_IN_QUALYS - the
 * host is gone and there is nothing to scan.
 *
 * Retry: claiming a request bumps its attempts. If the send (or the lookup)
 * fails, requests go back to 'pending' for the next allowed send, until
 * --max-attempts (default 3), after which they're marked 'failed' with the
 * reason, which the Assets page shows.
 *
 * Unlike process_agent_uninstalls.php this runs for real by default: a scan
 * changes nothing on the host except running its normal check early.
 * --dry-run shows what would be sent and changes nothing.
 *
 * Config (src/config/config.php, all optional):
 *   qualys.ods_daily_budget          default 22 (of Qualys's 25 per 24h)
 *   qualys.ods_min_interval_minutes  default 10
 *   qualys.ods_burst                 default 6 (0 = no pacing)
 *   qualys.ods_scan_type             default 'Vulnerability_Scan'
 *   qualys.ods_override_cpu          default false (keep the agents' CPU throttle)
 *
 * Suggested cron entry (every 5 minutes, so a request waits at most ~5
 * minutes once a send is allowed - written as an explicit minute list,
 * since the usual step shorthand would end this docblock early):
 *   2,7,12,17,22,27,32,37,42,47,52,57 * * * * php /var/www/dashboard.plainsightsecurity.co.uk/scripts/process_scan_requests.php >> /var/log/vulndash/scan_requests.log 2>&1
 *
 * Usage:
 *   php scripts/process_scan_requests.php                 # send if due
 *   php scripts/process_scan_requests.php --dry-run       # preview only
 *   php scripts/process_scan_requests.php --max-attempts=5
 *   php scripts/process_scan_requests.php --limit=200
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;
use VulnDash\Lib\ScanRequestRepository;
use VulnDash\Scripts\QualysApiClient;

$dryRun      = in_array('--dry-run', $argv, true);
$maxAttempts = 3;
$limit       = 500;
foreach ($argv as $arg) {
    if (preg_match('/^--max-attempts=(\d+)$/', $arg, $m)) {
        $maxAttempts = max(1, (int)$m[1]);
    }
    if (preg_match('/^--limit=(\d+)$/', $arg, $m)) {
        $limit = max(1, (int)$m[1]);
    }
}

$lockPath = sys_get_temp_dir() . '/vulndash_scan_requests.lock';
$lockHandle = fopen($lockPath, 'c');
if ($lockHandle === false) {
    fwrite(STDERR, "Could not open lock file {$lockPath} - check its ownership/permissions.\n");
    exit(1);
}
@chmod($lockPath, 0666);
if (!flock($lockHandle, LOCK_EX | LOCK_NB)) {
    fwrite(STDOUT, "Another scan request run is already in progress - exiting.\n");
    exit(0);
}

$tagGuard        = Config::get('qualys.agent_scope_tag') !== null ? (string)Config::get('qualys.agent_scope_tag') : null;
$scanType        = (string)(Config::get('qualys.ods_scan_type') ?? 'Vulnerability_Scan');
$overrideCpu     = (bool)(Config::get('qualys.ods_override_cpu') ?? false);

fwrite(STDOUT, '=== scan requests (' . date('Y-m-d H:i:s') . ') ' . ($dryRun ? 'DRY RUN' : '') . "\n");

$client = null;
$pending = ScanRequestRepository::countPending();
if ($pending === 0) {
    fwrite(STDOUT, "Nothing pending.\n");
    finish(0);
}

// The budget applies to dry runs too, so a preview says honestly whether a
// real run would send now.
$window = ScanRequestRepository::sendWindow();
$budgetLine = "{$window['calls_24h']} of {$window['budget']} on-demand call(s) used in the last 24h";
if (time() < $window['next_at']) {
    $why = match ($window['reason']) {
        'budget' => 'the 24h budget is used up until then',
        'pacing' => "pacing: after {$window['burst']} sends close together, the rest of the budget is spread through the day",
        default  => "sends are at least {$window['min_gap_minutes']} minutes apart",
    };
    fwrite(STDOUT, "{$pending} request(s) pending; {$budgetLine}. Next send allowed from "
        . date('H:i', $window['next_at']) . " ({$why}). Not sending yet.\n");
    finish(0);
}
fwrite(STDOUT, "{$pending} request(s) pending; {$budgetLine}.\n");

$client = new QualysApiClient(
    (string)Config::get('qualys.api_base_url'),
    (string)Config::get('qualys.username'),
    (string)Config::get('qualys.password'),
    (string)(Config::get('qualys.api_version') ?? '4.0'),
    $tagGuard,
    is_array(Config::get('qualys.excluded_tags')) ? Config::get('qualys.excluded_tags') : null
);

if ($dryRun) {
    $rows = ScanRequestRepository::listPending($limit);
    fwrite(STDOUT, count($rows) . " pending request(s):\n");
    $ids = [];
    foreach ($rows as $r) {
        fwrite(STDOUT, sprintf("  %-40s host=%-12d assetId=%s\n",
            (string)($r['hostname'] ?: $r['ip_address'] ?: '(unknown)'),
            (int)$r['qualys_host_id'],
            $r['qualys_asset_id'] !== null ? (string)$r['qualys_asset_id'] : '(missing - would be looked up first)'));
        if ($r['qualys_asset_id'] !== null) {
            $ids[] = (int)$r['qualys_asset_id'];
        }
    }
    if ($ids !== []) {
        fwrite(STDOUT, "\nWould POST to " . ScanRequestRepository::ODS_ENDPOINT . "?scan={$scanType}&overrideConfigCpu=" . ($overrideCpu ? 'true' : 'false') . " :\n");
        fwrite(STDOUT, '  ' . $client->buildUninstallRequestXml(array_values(array_unique($ids)), $tagGuard) . "\n");
    }
    fwrite(STDOUT, "\nDRY RUN - nothing sent, nothing changed.\n");
    finish(0);
}

$claimed = ScanRequestRepository::claimPending($limit);
if ($claimed === []) {
    fwrite(STDOUT, "Nothing pending.\n");
    finish(0);
}
fwrite(STDOUT, 'Claimed ' . count($claimed) . " request(s).\n");

$exitCode = 0;
$counts = ['sent' => 0, 'not_found' => 0, 'retry' => 0, 'failed' => 0];

/**
 * Returns rows to pending, or fails those out of attempts - the shared
 * outcome of a failed lookup or a failed send.
 *
 * @param array<int, array<string, mixed>> $rows
 */
$retryOrFail = static function (array $rows, string $reason) use ($maxAttempts, &$counts): void {
    $retry = [];
    $give = [];
    foreach ($rows as $r) {
        if ((int)$r['attempts'] >= $maxAttempts) {
            $give[] = (int)$r['id'];
        } else {
            $retry[] = (int)$r['id'];
        }
    }
    ScanRequestRepository::releaseToPending($retry, 'Last attempt failed, will retry: ' . $reason);
    ScanRequestRepository::markFailed($give, 'Failed after ' . $maxAttempts . ' attempts: ' . $reason);
    $counts['retry'] += count($retry);
    $counts['failed'] += count($give);
};

// --- Resolve missing AssetView ids --------------------------------------
$resolveError = null;
$needResolve = array_values(array_filter($claimed, static fn ($r) => $r['qualys_asset_id'] === null));
if ($needResolve !== []) {
    fwrite(STDOUT, 'Looking up ' . count($needResolve) . " AssetView id(s)...\n");
    try {
        $map = $client->resolveAssetViewIdsByHostIds(array_map(static fn ($r) => (int)$r['qualys_host_id'], $needResolve));
    } catch (\Throwable $e) {
        $map = [];
        $resolveError = $e->getMessage();
        fwrite(STDERR, "  lookup failed: {$resolveError}\n");
    }
    foreach ($claimed as &$r) {
        if ($r['qualys_asset_id'] === null && isset($map[(int)$r['qualys_host_id']])) {
            $r['qualys_asset_id'] = $map[(int)$r['qualys_host_id']];
            ScanRequestRepository::storeAssetViewId((int)$r['id'], $r['asset_id'] !== null ? (int)$r['asset_id'] : null, (int)$r['qualys_asset_id']);
        }
    }
    unset($r);
}

$targetable = array_values(array_filter($claimed, static fn ($r) => $r['qualys_asset_id'] !== null));
$unresolved = array_values(array_filter($claimed, static fn ($r) => $r['qualys_asset_id'] === null));

if ($unresolved !== []) {
    if ($resolveError === null) {
        ScanRequestRepository::markFailed(array_map(static fn ($r) => (int)$r['id'], $unresolved), ScanRequestRepository::NOTE_NOT_FOUND_IN_QUALYS);
        $counts['not_found'] += count($unresolved);
        foreach ($unresolved as $r) {
            fwrite(STDOUT, '  not found in Qualys, no scan possible: ' . (string)($r['hostname'] ?: $r['ip_address'] ?: '(unknown)') . ' (host ' . (int)$r['qualys_host_id'] . ")\n");
        }
    } else {
        $retryOrFail($unresolved, 'AssetView id lookup failed: ' . $resolveError);
        $exitCode = 1;
    }
}

// --- One bulk send -----------------------------------------------------
if ($targetable !== []) {
    $assetViewIds = array_values(array_unique(array_map(static fn ($r) => (int)$r['qualys_asset_id'], $targetable)));
    fwrite(STDOUT, "Requesting {$scanType} on " . count($assetViewIds) . " agent(s) in one call...\n");
    try {
        $client->launchOnDemandScanByAssetIds($assetViewIds, $scanType, $overrideCpu, $tagGuard);
        ScanRequestRepository::markSent(array_map(static fn ($r) => (int)$r['id'], $targetable));
        $counts['sent'] += count($targetable);
    } catch (\Throwable $e) {
        fwrite(STDERR, "  send failed: {$e->getMessage()}\n");
        $retryOrFail($targetable, $e->getMessage());
        $exitCode = 1;
    }
}

fwrite(STDOUT, "  Sent to Qualys       : {$counts['sent']}\n");
fwrite(STDOUT, "  Not found in Qualys  : {$counts['not_found']}\n");
fwrite(STDOUT, "  Back to pending      : {$counts['retry']}\n");
fwrite(STDOUT, "  Failed (max attempts): {$counts['failed']}\n");
finish($exitCode);


/**
 * Single exit path: persists the API call log and releases the lock before
 * exiting, without relying on finally (exit() skips it).
 */
function finish(int $code): void
{
    global $client, $lockHandle;
    if ($client instanceof QualysApiClient) {
        try {
            ApiCallLogRepository::recordCalls($client->getCallLog());
        } catch (\Throwable $e) {
            fwrite(STDERR, "  (warning: could not record API call log: {$e->getMessage()})\n");
        }
    }
    if (is_resource($lockHandle)) {
        flock($lockHandle, LOCK_UN);
        fclose($lockHandle);
    }
    exit($code);
}
