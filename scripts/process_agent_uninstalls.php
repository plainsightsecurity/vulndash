#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Drains the agent_uninstall_queue: sends the queued Cloud Agent uninstalls to
 * Qualys in as few API calls as possible (one bulk call for the whole batch),
 * then mirrors Qualys's own side-effect locally for the hosts it confirmed.
 *
 * THIS IS THE ONE DESTRUCTIVE STEP in the uninstall feature. A confirmed run
 * asks Qualys to purge the hosts' scan data (findings) and remove the agent
 * hosts from the subscription (per Qualys's own docs), and locally deactivates
 * those assets and deletes their detections. It therefore behaves like every
 * other destructive script in this codebase:
 *
 *   - DRY RUN BY DEFAULT. With no --confirm it reads the pending queue, shows
 *     exactly which assets it would uninstall and the exact XML body it would
 *     POST, and changes nothing (no queue mutation, no API call, no cleanup).
 *   - --confirm actually claims the rows, calls Qualys, and applies cleanup
 *     only for the asset ids Qualys reports back as acted-on.
 *
 * Targeting: by AssetView asset id (assets.qualys_asset_id), which is what the
 * uninstall API takes - NOT the qweb host id. Rows still missing that id are
 * resolved on the fly (Host Asset search). A tagName EQUALS <agent_scope_tag>
 * guard is ANDed onto the request (Qualys's recommended blast-radius
 * protection) so the call can only ever touch agent-tagged hosts.
 *
 * Host already gone from Qualys (2026-11): when that lookup call SUCCEEDS but
 * returns no asset for a host, Qualys no longer has the host at all - there is
 * nothing to uninstall, and what the user asked for is already true. Such rows
 * are settled as 'uninstalled' (with AgentUninstallRepository::
 * NOTE_NOT_FOUND_IN_QUALYS in last_error, so the queue says why no call was
 * made) and get the same local cleanup as a confirmed uninstall. They used to
 * be marked 'failed', which ends the dashboard suppression WITHOUT cleanup -
 * so the host reappeared with its old findings ~20 minutes after every
 * request ("bernard", 2026-11-06, three requests in a row). The local row is
 * then deleted by the hourly prune once Qualys's Host List no longer has it.
 * Only a successful lookup counts: if the lookup call itself fails, nothing is
 * known about those hosts, so they go through the same retry-then-fail path as
 * a failed uninstall call, rather than being failed (or settled) on the spot.
 *
 * Retry: claiming a row bumps its attempts counter. A row that Qualys doesn't
 * confirm (or a whole-batch API error) is returned to 'pending' to retry next
 * run, until --max-attempts (default 3) is reached, after which it's marked
 * 'failed' with the reason so it surfaces instead of retrying forever.
 *
 * Usage:
 *   php scripts/process_agent_uninstalls.php                 # dry run
 *   php scripts/process_agent_uninstalls.php --confirm       # actually uninstall
 *   php scripts/process_agent_uninstalls.php --max-attempts=5
 *   php scripts/process_agent_uninstalls.php --limit=200
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\AgentUninstallRepository;
use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;
use VulnDash\Lib\Database;
use VulnDash\Scripts\QualysApiClient;

$confirm     = in_array('--confirm', $argv, true);
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

// Same non-blocking-lock pattern as the sync scripts: never let two runs call
// Qualys's uninstall endpoint concurrently.
$lockPath = sys_get_temp_dir() . '/vulndash_agent_uninstall.lock';
$lockHandle = \VulnDash\Lib\LockFile::open($lockPath);
if ($lockHandle === false) {
    fwrite(STDERR, "Could not open lock file {$lockPath} - check its ownership/permissions.\n");
    exit(1);
}
@chmod($lockPath, 0666);
if (!flock($lockHandle, LOCK_EX | LOCK_NB)) {
    fwrite(STDOUT, "Another uninstall run is already in progress - exiting.\n");
    exit(0);
}

$agentScopeTag = Config::get('qualys.agent_scope_tag') !== null ? (string)Config::get('qualys.agent_scope_tag') : null;
$tagGuard      = $agentScopeTag; // AND tagName EQUALS <scope> as the blast-radius guard

fwrite(STDOUT, "==========================================================\n");
fwrite(STDOUT, "  Process agent uninstall queue\n");
fwrite(STDOUT, "----------------------------------------------------------\n");
fwrite(STDOUT, "  API base    : " . (string)Config::get('qualys.api_base_url') . "\n");
fwrite(STDOUT, "  Tag guard   : " . ($tagGuard ?? '(none)') . "\n");
fwrite(STDOUT, "  Max attempts: {$maxAttempts}\n");
fwrite(STDOUT, "  Mode        : " . ($confirm ? 'CONFIRM (will uninstall + clean up)' : 'DRY RUN (no changes)') . "\n");
fwrite(STDOUT, "==========================================================\n\n");

$exitCode = 0;

if (!$confirm) {
    // ---- DRY RUN: read-only preview ----
    $rows = AgentUninstallRepository::listPending($limit);
    if ($rows === []) {
        fwrite(STDOUT, "Nothing pending.\n");
        finish(0);
    }

    $withId = [];
    $withoutId = [];
    foreach ($rows as $r) {
        if ($r['qualys_asset_id'] !== null) {
            $withId[] = $r;
        } else {
            $withoutId[] = $r;
        }
    }

    fwrite(STDOUT, count($rows) . " pending request(s):\n");
    foreach ($withId as $r) {
        fwrite(STDOUT, sprintf("  %-40s host=%-12d assetId=%d\n",
            (string)($r['hostname'] ?: $r['ip_address'] ?: '(unknown)'),
            (int)$r['qualys_host_id'], (int)$r['qualys_asset_id']));
    }
    foreach ($withoutId as $r) {
        fwrite(STDOUT, sprintf("  %-40s host=%-12d assetId=(missing - would resolve at run time; if Qualys has no such asset, treated as already removed)\n",
            (string)($r['hostname'] ?: $r['ip_address'] ?: '(unknown)'), (int)$r['qualys_host_id']));
    }

    $ids = array_values(array_unique(array_map(static fn ($r) => (int)$r['qualys_asset_id'], $withId)));
    if ($ids !== []) {
        $client = makeClient();
        fwrite(STDOUT, "\nWould POST to /qps/rest/2.0/uninstall/am/asset/ :\n");
        fwrite(STDOUT, "  " . $client->buildUninstallRequestXml($ids, $tagGuard) . "\n");
        fwrite(STDOUT, "\nWould then, for each asset id Qualys confirms: set is_active=0 and delete its detections.\n");
    }
    fwrite(STDOUT, "\nDRY RUN - nothing sent, nothing changed. Re-run with --confirm to process.\n");
    finish(0);
}

// ---- CONFIRM: claim, uninstall, clean up ----
$client = makeClient();
$claimed = AgentUninstallRepository::claimPending($limit);
if ($claimed === []) {
    fwrite(STDOUT, "Nothing pending.\n");
    finish(0);
}
fwrite(STDOUT, "Claimed " . count($claimed) . " request(s) for processing.\n");

// Resolve any rows still missing an AssetView id (self-sufficient even if
// scripts/resolve_asset_ids.php was never run). $resolveError records whether
// the lookup itself failed - see "Host already gone from Qualys" in this
// file's docblock for why that distinction decides what happens next.
$resolveError = null;
$needResolve = array_values(array_filter($claimed, static fn ($r) => $r['qualys_asset_id'] === null));
if ($needResolve !== []) {
    $hostIds = array_map(static fn ($r) => (int)$r['qualys_host_id'], $needResolve);
    fwrite(STDOUT, "Resolving " . count($needResolve) . " missing AssetView id(s)...\n");
    try {
        $map = $client->resolveAssetViewIdsByHostIds($hostIds);
    } catch (\Throwable $e) {
        $map = [];
        $resolveError = $e->getMessage();
        fwrite(STDERR, "  (resolve failed: {$resolveError})\n");
    }
    if ($map !== []) {
        $pdo = Database::getConnection();
        $updA = $pdo->prepare('UPDATE assets SET qualys_asset_id = :aid WHERE id = :id');
        $updQ = $pdo->prepare('UPDATE agent_uninstall_queue SET qualys_asset_id = :aid WHERE id = :qid');
        foreach ($claimed as &$r) {
            if ($r['qualys_asset_id'] === null && isset($map[(int)$r['qualys_host_id']])) {
                $r['qualys_asset_id'] = $map[(int)$r['qualys_host_id']];
                if ($r['asset_id'] !== null) {
                    $updA->execute(['aid' => $r['qualys_asset_id'], 'id' => (int)$r['asset_id']]);
                }
                $updQ->execute(['aid' => $r['qualys_asset_id'], 'qid' => (int)$r['id']]);
            }
        }
        unset($r);
    }
}

// Partition into targetable (have an AssetView id) and unresolved.
$targetable = [];
$unresolved = [];
foreach ($claimed as $r) {
    if ($r['qualys_asset_id'] !== null) {
        $targetable[] = $r;
    } else {
        $unresolved[] = $r;
    }
}

$alreadyGoneRowIds = [];
$lookupRetry = [];
$lookupGive = [];
if ($unresolved !== []) {
    if ($resolveError === null) {
        // The lookup worked and Qualys has no such asset: already removed
        // there. Settle and clean up, so the host stays off the dashboard -
        // see the docblock.
        $alreadyGoneRowIds = array_map(static fn ($r) => (int)$r['id'], $unresolved);
        $alreadyGoneAssetIds = array_values(array_filter(array_map(static fn ($r) => $r['asset_id'] !== null ? (int)$r['asset_id'] : 0, $unresolved)));
        AgentUninstallRepository::markAlreadyGone($alreadyGoneRowIds);
        AgentUninstallRepository::applyLocalCleanup($alreadyGoneAssetIds);
        foreach ($unresolved as $r) {
            fwrite(STDOUT, "  not found in Qualys, already removed there - cleaned up locally: " . (string)($r['hostname'] ?: $r['ip_address'] ?: '(unknown)') . " (host " . (int)$r['qualys_host_id'] . ")\n");
        }
    } else {
        // The lookup itself failed, so nothing is known about these hosts:
        // retry, the same way a failed uninstall call is retried.
        foreach ($unresolved as $r) {
            if ((int)$r['attempts'] >= $maxAttempts) {
                $lookupGive[] = (int)$r['id'];
            } else {
                $lookupRetry[] = (int)$r['id'];
            }
        }
        if ($lookupRetry !== []) {
            AgentUninstallRepository::releaseToPending($lookupRetry);
        }
        if ($lookupGive !== []) {
            AgentUninstallRepository::markFailed($lookupGive, 'AssetView id lookup failed after max attempts: ' . $resolveError);
        }
        fwrite(STDERR, "  AssetView lookup failed for " . count($unresolved) . " request(s): " . count($lookupRetry) . " returned to pending for retry, " . count($lookupGive) . " marked failed (max attempts).\n");
        $exitCode = 1;
    }
}

if ($targetable === []) {
    fwrite(STDOUT, "Nothing targetable this run.\n");
    printSummary(0, 0, 0, count($alreadyGoneRowIds), count($lookupRetry), count($lookupGive));
    finish($exitCode);
}

// One bulk call for the whole batch.
$assetViewIds = array_values(array_unique(array_map(static fn ($r) => (int)$r['qualys_asset_id'], $targetable)));
fwrite(STDOUT, "Uninstalling " . count($assetViewIds) . " agent(s) in one call...\n");

$confirmed = null;
try {
    $confirmed = $client->uninstallAgentsByAssetIds($assetViewIds, $tagGuard);
} catch (\Throwable $e) {
    // The whole call failed - nothing was uninstalled. Return rows to pending
    // to retry next run, unless they've exhausted their attempts. (attempts was
    // already incremented by claimPending.)
    $retry = [];
    $give  = [];
    foreach ($targetable as $r) {
        if ((int)$r['attempts'] >= $maxAttempts) {
            $give[] = (int)$r['id'];
        } else {
            $retry[] = (int)$r['id'];
        }
    }
    if ($retry !== []) {
        AgentUninstallRepository::releaseToPending($retry);
    }
    if ($give !== []) {
        AgentUninstallRepository::markFailed($give, 'Uninstall API call failed after max attempts: ' . $e->getMessage());
    }
    fwrite(STDERR, "Uninstall call failed: {$e->getMessage()}\n");
    fwrite(STDERR, "  " . count($retry) . " returned to pending for retry, " . count($give) . " marked failed (max attempts).\n");
    $exitCode = 1;
    finish($exitCode);
}

// Map Qualys's confirmed asset ids back to queue rows.
$confirmedSet = array_flip($confirmed);
$succeededRowIds = [];
$succeededAssetIds = [];
$notConfirmed = [];
foreach ($targetable as $r) {
    if (isset($confirmedSet[(int)$r['qualys_asset_id']])) {
        $succeededRowIds[] = (int)$r['id'];
        if ($r['asset_id'] !== null) {
            $succeededAssetIds[] = (int)$r['asset_id'];
        }
    } else {
        $notConfirmed[] = $r;
    }
}

if ($succeededRowIds !== []) {
    AgentUninstallRepository::markUninstalled($succeededRowIds);
    // Mirror Qualys's purge locally only for confirmed assets.
    AgentUninstallRepository::applyLocalCleanup($succeededAssetIds);
}

// Anything Qualys didn't confirm: retry next run, or fail if attempts exhausted.
$retry = [];
$give  = [];
foreach ($notConfirmed as $r) {
    if ((int)$r['attempts'] >= $maxAttempts) {
        $give[] = (int)$r['id'];
    } else {
        $retry[] = (int)$r['id'];
    }
}
if ($retry !== []) {
    AgentUninstallRepository::releaseToPending($retry);
}
if ($give !== []) {
    AgentUninstallRepository::markFailed($give, 'Not confirmed by Qualys after max attempts.');
}

printSummary(count($succeededRowIds), count($retry), count($give), count($alreadyGoneRowIds), count($lookupRetry), count($lookupGive));
finish($exitCode);


/**
 * Build the API client from config (same construction as the sync scripts).
 */
function makeClient(): QualysApiClient
{
    return new QualysApiClient(
        (string)Config::get('qualys.api_base_url'),
        (string)Config::get('qualys.username'),
        (string)Config::get('qualys.password'),
        (string)(Config::get('qualys.api_version') ?? '4.0'),
        Config::get('qualys.agent_scope_tag') !== null ? (string)Config::get('qualys.agent_scope_tag') : null,
        is_array(Config::get('qualys.excluded_tags')) ? Config::get('qualys.excluded_tags') : null
    );
}

/** End-of-run counts. The two lookup lines only appear when something hit them. */
function printSummary(int $uninstalled, int $retry, int $failed, int $alreadyGone, int $lookupRetry, int $lookupFailed): void
{
    fwrite(STDOUT, "\n----------------------------------------------------------\n");
    fwrite(STDOUT, "  Uninstalled (confirmed): {$uninstalled}\n");
    fwrite(STDOUT, "  Already gone in Qualys : {$alreadyGone}\n");
    fwrite(STDOUT, "  Not confirmed -> retry : {$retry}\n");
    fwrite(STDOUT, "  Not confirmed -> failed: {$failed}\n");
    if ($lookupRetry > 0 || $lookupFailed > 0) {
        fwrite(STDOUT, "  Lookup failed -> retry : {$lookupRetry}\n");
        fwrite(STDOUT, "  Lookup failed -> failed: {$lookupFailed}\n");
    }
}

/**
 * Single exit path. Persists the API call log and releases the lock explicitly
 * BEFORE exiting - deliberately not relying on a finally block, because exit()
 * skips finally in PHP (a bug this codebase has been bitten by before).
 */
function finish(int $code): void
{
    global $client, $lockHandle;
    if (isset($client) && $client instanceof QualysApiClient) {
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
