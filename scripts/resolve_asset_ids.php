#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Backfill assets.qualys_asset_id (the Qualys "AssetView" asset id) for hosts
 * that only have a qweb host id so far.
 *
 * Why this exists: the host-detection sync pulls from Host List Detection,
 * whose response only ever carries the qweb host id (stored as
 * assets.qualys_host_id). The Cloud Agent *uninstall* API, however, targets
 * hosts by their AssetView asset id - a different identifier this app never
 * otherwise sees. Without it, scripts/process_agent_uninstalls.php has nothing
 * to target. This script resolves qweb host id -> AssetView id via the Asset
 * Management Host Asset search endpoint (one read call per ~100 hosts) and
 * writes it back to assets.qualys_asset_id (and to any pending uninstall-queue
 * rows for those assets, so the worker can use it immediately).
 *
 * Read-only by default. It prints exactly what it WOULD write and changes
 * nothing unless you pass --confirm. Run it once without --confirm first and
 * eyeball the resolved pairs: this is also the check that the Host Asset
 * search behaves as documented on THIS subscription before anything
 * destructive (the uninstall worker) relies on the ids.
 *
 * Usage:
 *   php scripts/resolve_asset_ids.php            # dry run: show resolved pairs, write nothing
 *   php scripts/resolve_asset_ids.php --confirm  # persist qualys_asset_id
 *   php scripts/resolve_asset_ids.php --all      # also re-resolve assets that already have an id
 *   php scripts/resolve_asset_ids.php --batch=50 # ids per API call (default 100)
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;
use VulnDash\Lib\Database;
use VulnDash\Scripts\QualysApiClient;

$confirm = in_array('--confirm', $argv, true);
$all     = in_array('--all', $argv, true);
$batch   = 100;
foreach ($argv as $arg) {
    if (preg_match('/^--batch=(\d+)$/', $arg, $m)) {
        $batch = max(1, (int)$m[1]);
    }
}

$pdo = Database::getConnection();

$agentScopeTag = Config::get('qualys.agent_scope_tag') !== null ? (string)Config::get('qualys.agent_scope_tag') : null;

fwrite(STDOUT, "==========================================================\n");
fwrite(STDOUT, "  Resolve AssetView asset ids (qualys_asset_id backfill)\n");
fwrite(STDOUT, "----------------------------------------------------------\n");
fwrite(STDOUT, "  API base    : " . (string)Config::get('qualys.api_base_url') . "\n");
fwrite(STDOUT, "  Agent scope : " . ($agentScopeTag ?? '(none)') . "\n");
fwrite(STDOUT, "  Batch size  : {$batch}\n");
fwrite(STDOUT, "  Scope       : " . ($all ? 'ALL active assets' : 'active assets missing qualys_asset_id') . "\n");
fwrite(STDOUT, "  Mode        : " . ($confirm ? 'CONFIRM (will write)' : 'DRY RUN (no changes)') . "\n");
fwrite(STDOUT, "==========================================================\n\n");

// Which assets need resolving.
$sql = 'SELECT id, qualys_host_id, hostname, ip_address, qualys_asset_id
        FROM assets
        WHERE is_active = 1'
     . ($all ? '' : ' AND qualys_asset_id IS NULL')
     . ' ORDER BY hostname';
$assets = $pdo->query($sql)->fetchAll();

if ($assets === []) {
    fwrite(STDOUT, $all
        ? "No active assets found.\n"
        : "Nothing to do - every active asset already has a qualys_asset_id.\n");
    exit(0);
}

$hostIds = array_map(static fn ($a) => (int)$a['qualys_host_id'], $assets);
fwrite(STDOUT, count($assets) . " asset(s) to resolve. Calling Host Asset search...\n\n");

$client = new QualysApiClient(
    (string)Config::get('qualys.api_base_url'),
    (string)Config::get('qualys.username'),
    (string)Config::get('qualys.password'),
    (string)(Config::get('qualys.api_version') ?? '4.0'),
    $agentScopeTag,
    is_array(Config::get('qualys.excluded_tags')) ? Config::get('qualys.excluded_tags') : null
);

try {
    $map = $client->resolveAssetViewIdsByHostIds($hostIds, $batch);
} finally {
    // Record the API call(s) on the usage page regardless of outcome.
    try {
        ApiCallLogRepository::recordCalls($client->getCallLog());
    } catch (\Throwable $e) {
        fwrite(STDERR, "  (warning: could not record API call log: {$e->getMessage()})\n");
    }
}

$resolved = [];
$unresolved = [];
foreach ($assets as $a) {
    $qweb = (int)$a['qualys_host_id'];
    if (isset($map[$qweb])) {
        $resolved[(int)$a['id']] = $map[$qweb];
        $flag = ($a['qualys_asset_id'] !== null && (int)$a['qualys_asset_id'] !== $map[$qweb]) ? '  (CHANGED)' : '';
        fwrite(STDOUT, sprintf("  %-40s host=%-12d -> assetId=%d%s\n",
            (string)($a['hostname'] ?: $a['ip_address'] ?: '(unknown)'), $qweb, $map[$qweb], $flag));
    } else {
        $unresolved[] = $a;
        fwrite(STDOUT, sprintf("  %-40s host=%-12d -> NOT FOUND\n",
            (string)($a['hostname'] ?: $a['ip_address'] ?: '(unknown)'), $qweb));
    }
}

fwrite(STDOUT, "\n----------------------------------------------------------\n");
fwrite(STDOUT, "  Resolved   : " . count($resolved) . "\n");
fwrite(STDOUT, "  Not found  : " . count($unresolved) . "\n");

if (!$confirm) {
    fwrite(STDOUT, "\nDRY RUN - nothing written. Re-run with --confirm to persist these ids.\n");
    exit(0);
}

if ($resolved === []) {
    fwrite(STDOUT, "\nNothing resolved, so nothing to write.\n");
    exit(0);
}

// Persist. Backfill the asset, and also stamp any pending/processing queue
// rows for that asset so the uninstall worker has the id without re-resolving.
$pdo->beginTransaction();
try {
    $updAsset = $pdo->prepare('UPDATE assets SET qualys_asset_id = :aid WHERE id = :id');
    $updQueue = $pdo->prepare(
        'UPDATE agent_uninstall_queue
         SET qualys_asset_id = :aid
         WHERE asset_id = :id AND status IN (\'pending\', \'processing\')'
    );
    foreach ($resolved as $assetId => $assetViewId) {
        $updAsset->execute(['aid' => $assetViewId, 'id' => $assetId]);
        $updQueue->execute(['aid' => $assetViewId, 'id' => $assetId]);
    }
    $pdo->commit();
} catch (\Throwable $e) {
    $pdo->rollBack();
    fwrite(STDERR, "\nWrite failed, rolled back: {$e->getMessage()}\n");
    exit(1);
}

fwrite(STDOUT, "\nWrote qualys_asset_id for " . count($resolved) . " asset(s).\n");
if ($unresolved !== []) {
    fwrite(STDOUT, count($unresolved) . " still unresolved - these can't be targeted for uninstall until Qualys returns them.\n");
}
exit(0);
