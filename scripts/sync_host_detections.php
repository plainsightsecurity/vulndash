#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Pulls per-host vulnerability detections (and tag associations) from
 * Qualys and upserts them locally, computing the effective CVSS score and
 * CE+ status at ingest time (via CvssCalculator) so dashboard/list queries
 * stay index-only reads instead of recomputing anything per page load.
 *
 * Tag sync: scoping is by named Asset Tag (confirmed 2026-07), and Qualys
 * returns each host's current tags inline with its detections via the
 * show_tags=1 parameter (see QualysApiClient::fetchHostDetections()) -
 * there's no separate tag-sync API call or scheduled job needed. Local
 * `tags` rows are auto-created the first time an unseen Qualys tag shows
 * up on a host; `asset_tags` is fully replaced (delete-then-reinsert) for
 * each host on every run, so a tag removed from a host in Qualys is
 * correctly reflected here too - not just tags being added. That matters
 * for the tag-scoping model specifically: a stale asset_tags row would be
 * a real access-control bug (a client dashboard keeps seeing an asset
 * after Plainsight has untagged it from that client's scope), not just
 * stale display data, so this errs on re-deriving the full set each time
 * rather than only ever adding.
 *
 * Detection removal: Qualys's response for a host that appears in a given
 * run reflects that host's FULL current detection list (confirmed 2026-07
 * against this subscription's real API responses) - the same assumption
 * the tag reconciliation above already relies on. So the same
 * delete-then-reinsert logic applies to host_detections too: after
 * upserting everything Qualys just reported for a host, any LOCAL
 * detection row for that same host that ISN'T in what Qualys just sent is
 * deleted outright (confirmed 2026-07: no "Fixed" history is kept for a
 * detection Qualys stops reporting - it's just gone, same as if it had
 * never been found). This catches both cases: Qualys explicitly marking a
 * detection Fixed (which the upsert already handled before this) AND
 * Qualys simply no longer mentioning it at all for that host, which the
 * upsert alone could never detect since it only ever touches rows it's
 * told about.
 *
 * A host destroyed/decommissioned in Qualys entirely is a different case
 * from the above - it simply stops appearing in ANY future incremental
 * pull, so there's nothing to reconcile "against" the way detections/tags
 * are above (both of those rely on the host still showing up in a
 * response). This script deliberately does NOT try to infer that from
 * silence/staleness (e.g. "no scan in N days") - a slow but still-real
 * scan cadence would look identical to a destroyed host under any such
 * guess, and the requirement here is that an asset still in Qualys must
 * always still be in the dashboard, not "probably still in Qualys". See
 * scripts/reconcile_asset_inventory.php instead, which asks Qualys
 * directly (a full, unfiltered pull) rather than inferring - the only way
 * to actually know a host is gone instead of guessing it might be.
 *
 * Agent-only scope (2026-07): this now pulls only hosts carrying the
 * Qualys tag named in qualys.agent_scope_tag (src/config/config.php,
 * defaults to Qualys's own built-in "Cloud Agent" tag) - see
 * QualysApiClient's "Agent-only scope" docblock note for exactly how.
 * Scanner-only hosts simply never appear in this pull any more; they're
 * not reconciled away here (this script only ever adds/updates what it's
 * told about) - see scripts/reconcile_asset_inventory.php, which is what
 * actually removes a local asset Qualys no longer reports.
 *
 * Per-tag exclusion (2026-07, same day, once real data showed the gap):
 * qualys.excluded_tags (also in config) strips specific tag NAMES out of
 * every host's tag list regardless of whether the host itself is in
 * scope - a host can legitimately carry the agent scope tag AND an
 * unrelated tag (e.g. a dynamic IP-range tag that happens to also match
 * that host's IP) that has nothing to do with why it matched. See
 * QualysApiClient's "Per-tag exclusion" docblock note for the real host
 * that surfaced this.
 *
 * Run scripts/sync_knowledge_base.php first (or make sure it runs on a
 * schedule) - detections for QIDs not yet in the local knowledge_base
 * cache are skipped and picked up on the next run. Since 2026-11 each skip
 * is logged and recorded (MissingKbQidRepository), so a QID the KB sweep
 * never fetches shows on the dashboard's sync panel instead of its findings
 * silently never appearing.
 *
 * Actual cron entry (confirmed 2026-11) - hourly:
 *   18 * * * * php /var/www/dashboard.plainsightsecurity.co.uk/scripts/sync_host_detections.php >> /var/log/vulndash/detection_sync.log 2>&1
 *
 * Incremental filter and overlap (2026-11): the pull used to ask Qualys for
 * hosts with vm_scan_since = the last successful run's completion time.
 * For a Cloud Agent that's the time the scan ran on the endpoint, which is
 * earlier than the time its results became visible to the API - so a host
 * whose upload/processing took longer than one sync interval was already
 * behind the cursor when it landed and never came back from this pull at
 * all, leaving newly-installed agents invisible until the 6-hourly
 * reconcile found them. The filter is now vm_processed_after by default
 * (qualys.host_detection_incremental_filter; set it to 'vm_scan_since' to
 * go back), and the cursor is moved back by
 * qualys.host_detection_overlap_minutes (default 60) to cover the gap
 * between Qualys stamping a host processed and it being readable - the
 * same idea as kb_incremental_overlap_minutes for the KB sync. Re-sending
 * a host already synced is harmless (every write here is idempotent) and
 * costs nothing in calls while the estate fits in one page.
 *
 * New-host pass (2026-11): Host List Detection never returns a host with
 * no open detections (see QualysApiClient::fetchHostList()), so a newly
 * installed agent - one with a clean first scan, or one that hasn't
 * processed a scan at all yet - used to wait for the reconcile job's full
 * Host List pull, up to 6 hours. Each run now also makes that same full,
 * unfiltered Host List pull (on its own version rotation - see below)
 * and adds any host it returns that isn't stored locally yet (asset row
 * and tags only, via HostSyncWriter::upsertAssetAndTags()). It is
 * deliberately NOT date-filtered: an agent with no processed scan has no
 * scan or processed date to match, so any such filter would drop exactly
 * the hosts this pass exists for. One page per run while the estate fits
 * in qualys.host_page_size, and it spends the Host List counter, which
 * nothing else uses much, rather than the Host Detection one. It
 * deliberately never touches a host that IS
 * already stored, and never clears detections: judging "in the Host List
 * but not the detection pull, so everything is fixed" needs the full pulls
 * reconcile_asset_inventory.php makes, behind its mass-removal guard. The
 * one exception (2026-11): a stored host with no AssetView id gets the one
 * this pull carried (qualys.show_asset_id), so a zero-detection host - which
 * never comes through writeHost() above - has its id within the hour rather
 * than at the next reconcile. Fill only; a stored id is never changed here.
 * Disable with qualys.host_list_new_host_pass => false. A failure here
 * fails the run (status 'failed' in sync_log) after the detections above
 * have already been written - loud rather than silent, and the next run's
 * detection cursor stays put, so nothing that run would have seen is lost.
 *
 * Prune (2026-11): because that Host List pull is full and unfiltered, a
 * stored asset missing from it is gone from Qualys (or has left the agent
 * scope) - the same conclusion reconcile_asset_inventory.php draws, every 6
 * hours, from its own full pulls. So each run now also deletes those
 * assets, through src/Lib/AssetInventoryPruner.php: the one copy of the
 * rule, the mass-removal guard and the delete, shared with reconcile so the
 * two jobs can't disagree. A host removed from Qualys therefore leaves the
 * dashboard within the hour, at no extra API cost. If the guard refuses
 * (Qualys returned no hosts, or more than
 * qualys.reconcile_max_removal_percent of assets would go), nothing is
 * deleted and the run is marked failed with the reason - visible in the
 * dashboard's sync status panel - every hour until it's resolved; a genuine
 * mass decommission goes through a reviewed manual
 * `reconcile_asset_inventory.php --confirm --allow-mass-removal`, as before.
 * Only runs once the Host List pull has completed (a pull that throws
 * partway fails the run before this point). Disable with
 * qualys.host_list_prune_missing => false; it also needs the new-host pass
 * on, since that's the pull it reads.
 *
 * Host List pass interval (2026-11-23): the detection pull can run more often
 * than the Host List pass needs to - more frequent detection pulls get
 * on-demand scan results onto the dashboard sooner, but a full Host List
 * pull on every run would double that counter for nothing. With
 * qualys.host_list_pass_interval_minutes set (e.g. 60 with this job on
 * :18 and :48), the new-host pass and the prune run only when the last
 * completed pass STARTED at least that long ago, less a 5-minute tolerance
 * so a run starting a few seconds early still counts and the pass can't
 * drift onto the other slot. A pass that fails isn't recorded, so the next
 * run retries it. 0 (the default) keeps the pass on every run, as before.
 * Recorded in sync_state 'host_list_pass'. The 6-hourly reconcile's own
 * full pulls are unaffected.
 *
 * Auto interval (2026-11-24): cron still runs this every
 * sync.host_detection_cron_minutes (30), but each run first forecasts the
 * day's Qualys calls per endpoint and version (src/Lib/ApiBudget.php) and
 * picks the shortest of sync.host_detection_auto_intervals that fits the
 * limit less qualys.min_calls_reserve. If less than that has passed since
 * the last run that went ahead, it exits straight away (no sync_log row),
 * so the sync slows down as the estate grows past a page and speeds back
 * up when it fits again. Decision in sync_state 'host_detection_auto'.
 * --force runs regardless; sync.host_detection_auto_interval => false turns
 * it off. The same check emails admins (src/Lib/ApiBudgetAlerts.php) when
 * an endpoint runs low, the forecast doesn't fit at all, or the interval
 * changes. And each pull now skips a version Qualys last reported at the
 * reserve, moving on to the next one, rather than failing the run.
 *
 * Host List version rotation (2026-11-24): the pass used to reuse whichever
 * version the detection pull was assigned. With the pass on every other run
 * (60-minute interval, 30-minute sync) and four versions in the detection
 * rotation, that always landed it on the same two versions - every Host
 * List call went to /api/2.0/ and /api/4.0/ (12 a day each) while 3.0 and
 * 5.0 sat idle. It now rotates through qualys.host_detection_api_versions
 * on its own counter (sync_state 'host_list_rr'), advanced each time the
 * pass runs whether or not it succeeds, so the calls spread evenly (about
 * 6 a day per version with four versions). No fallback version: a failed
 * pull fails the run and the next pass simply moves on to the next version.
 *
 * Round-robins across API versions (qualys.host_detection_api_versions -
 * a separate config key from KB sync's qualys.kb_api_versions, since
 * there's no reason the two endpoints' available versions have to move
 * in lockstep) - confirmed 2026-07 via
 * scripts/check_host_detection_api_versions.php that both /api/2.0/ and
 * /api/3.0/ genuinely still work for Host List Detection on this
 * subscription and keep independent rate-limit counters, despite an
 * earlier EOS warning that had been read as "2.0 is retired here" (see
 * the note in src/config/config.php, worth updating once this is
 * confirmed settled) - it's now believed that was a warning of a
 * future retirement, not an immediate one, since both older versions
 * plainly still work.
 *
 * Worth knowing how this differs from sync_knowledge_base.php's own
 * round-robin: that one picks a version per WINDOW, because one run
 * there often makes many separate calls (backfill chunks, rescans). One
 * run here is a single incremental pull that just happens to page
 * internally when there's enough data - usually only 1-2 real calls, far
 * too few for an in-process round-robin counter (reset to 0 every run,
 * since this script runs as a brand new PHP process every 20 minutes) to
 * ever meaningfully cycle through anything. So the position is persisted
 * across runs instead, in sync_state under 'host_detections_rr' - each
 * run picks up where the last one left off and advances it regardless of
 * whether this run succeeds, since "which version to try next" isn't
 * something that should get stuck retrying a version that just failed.
 *
 * Fallback-on-failure is also coarser here than KB sync's, deliberately:
 * if the round-robin-picked version fails before yielding a single host,
 * this retries the WHOLE incremental pull on the primary version, not
 * just a sub-window - there's no equivalent to KB's per-window bisection
 * to retry a smaller piece, and Qualys's page-continuation URLs are tied
 * to whichever version issued them, so a partway failure can't resume on
 * a different version either. Safe to do (every upsert here is
 * idempotent) but does mean a failed-then-recovered run costs more
 * redundant work than KB sync's equivalent would - acceptable for how
 * rarely this should actually trigger, not something to over-engineer
 * around pre-emptively. The new-host pass has its own version rotation
 * ('host_list_rr', see above), with no fallback of its own.
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\ApiBudget;
use VulnDash\Lib\ApiBudgetAlerts;
use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\AssetInventoryPruner;
use VulnDash\Lib\Config;
use VulnDash\Lib\Database;
use VulnDash\Lib\HostSyncWriter;
use VulnDash\Lib\MissingKbQidRepository;
use VulnDash\Lib\TagScopeClassifier;
use VulnDash\Lib\VulnerabilityRepository;
use VulnDash\Scripts\QualysApiClient;

// Read-only diagnostic: --dry-run-prune reports what the remediation-tombstone
// prune WOULD remove (and the table's current size/date span) without syncing
// or deleting anything, so the retention behaviour can be eyeballed before it's
// trusted - in the same "dry-run before --confirm" spirit as the other scripts.
// Deliberately handled before the single-instance lock below: it only reads, so
// it shouldn't be blocked by (or block) a running sync.
$options = getopt('', ['dry-run-prune', 'force']);
if (array_key_exists('dry-run-prune', $options)) {
    $pdo = Database::getConnection();
    $retentionDays = max(1, (int)(Config::get('sync.resolution_retention_days') ?? 90));
    $cutoff = (new DateTimeImmutable())->modify("-{$retentionDays} days")->format('Y-m-d H:i:s');
    $total = (int)$pdo->query('SELECT COUNT(*) FROM detection_resolutions')->fetchColumn();
    $range = $pdo->query('SELECT MIN(resolved_at) AS mn, MAX(resolved_at) AS mx FROM detection_resolutions')->fetch() ?: ['mn' => null, 'mx' => null];
    $wouldStmt = $pdo->prepare('SELECT COUNT(*) FROM detection_resolutions WHERE resolved_at < :cutoff');
    $wouldStmt->execute(['cutoff' => $cutoff]);
    $wouldPrune = (int)$wouldStmt->fetchColumn();
    fwrite(STDOUT, "detection_resolutions prune (DRY RUN - nothing deleted):\n");
    fwrite(STDOUT, "  retention: {$retentionDays} days (sync.resolution_retention_days); prune cutoff = {$cutoff}\n");
    fwrite(STDOUT, "  table holds {$total} tombstone(s)" . ($range['mn'] ? " spanning {$range['mn']} .. {$range['mx']}" : ' (empty)') . "\n");
    fwrite(STDOUT, "  would delete {$wouldPrune} row(s) older than the cutoff, leaving " . ($total - $wouldPrune) . ".\n");
    exit(0);
}

// Guard against two invocations overlapping - see sync_knowledge_base.php
// for the same pattern and why it matters with a limited API call budget.
$lockPath = sys_get_temp_dir() . '/vulndash_host_detection_sync.lock';
$lockHandle = fopen($lockPath, 'c');
if ($lockHandle === false) {
    fwrite(STDERR, "Could not open lock file {$lockPath} - check its ownership/permissions (this is a real error, not a normal overlapping-run skip).\n");
    exit(1);
}
@chmod($lockPath, 0666);
if (!flock($lockHandle, LOCK_EX | LOCK_NB)) {
    fwrite(STDOUT, "Another host detection sync is already running - exiting.\n");
    exit(0);
}

$pdo = Database::getConnection();

// Auto interval and API budget alerts - see "Auto interval" in this file's
// docblock and src/Lib/ApiBudget.php. Decided before anything is logged, so
// a skipped run leaves no sync_log row behind. A failure here never stops
// the sync: it just runs as it would have without this.
$budgetReserve = max(0, (int)(Config::get('qualys.min_calls_reserve') ?? ApiBudget::DEFAULT_RESERVE));
try {
    $budgetIn = ApiBudget::currentInputs();
    $budgetReserve = $budgetIn['reserve'];
    $autoOn = ApiBudget::autoEnabled();
    if (!$autoOn) {
        $budgetIn['intervals'] = [$budgetIn['cron_minutes']];
    }
    $autoState = ApiBudget::autoState();
    $choice = ApiBudget::chooseInterval($budgetIn);
    $previousInterval = isset($autoState['interval']) ? (int)$autoState['interval'] : null;
    $lastRunStartedAt = isset($autoState['last_run_started_at']) ? (int)$autoState['last_run_started_at'] : null;
    $now = time();
    // Cron fires a few seconds late or early; don't miss a slot over it.
    $toleranceSec = min(5 * 60, intdiv($budgetIn['cron_minutes'] * 60, 2));
    $runNow = !$autoOn || array_key_exists('force', $options) || $lastRunStartedAt === null
        || $now - $lastRunStartedAt >= $choice['interval'] * 60 - $toleranceSec;

    $pdo->prepare("
        INSERT INTO sync_state (sync_type, state_json) VALUES ('host_detection_auto', :state)
        ON DUPLICATE KEY UPDATE state_json = VALUES(state_json)
    ")->execute(['state' => json_encode([
        'enabled'             => $autoOn,
        'interval'            => $choice['interval'],
        'fits'                => $choice['fits'],
        'peak'                => $choice['peak'],
        'decided_at'          => $now,
        'last_run_started_at' => $runNow ? $now : $lastRunStartedAt,
    ])]);

    fwrite(STDOUT, ($autoOn ? 'Auto interval' : 'Interval (auto off)') . ": every {$choice['interval']} min"
        . ' (forecast peak ' . $choice['peak'] . ' calls/day per endpoint and version, usable ' . ApiBudget::usable($budgetIn) . ')'
        . ($choice['fits'] ? '' : ' - DOES NOT FIT even at this interval') . "\n");

    try {
        foreach (ApiBudgetAlerts::check($budgetIn, $choice, $autoOn ? $previousInterval : null) as $line) {
            fwrite(STDOUT, "Admin alert sent: {$line}\n");
        }
    } catch (\Throwable $e) {
        fwrite(STDERR, 'API budget alert check failed (sync continues): ' . $e->getMessage() . "\n");
    }

    if (!$runNow) {
        fwrite(STDOUT, 'Skipping this run: the last one started ' . (int)round(($now - $lastRunStartedAt) / 60)
            . " min ago and the auto interval is {$choice['interval']} min. Use --force to run anyway.\n");
        exit(0);
    }
} catch (\Throwable $e) {
    fwrite(STDERR, 'API budget forecast failed (running this sync as normal): ' . $e->getMessage() . "\n");
}

$logStmt = $pdo->prepare('INSERT INTO sync_log (sync_type, started_at, status) VALUES (:type, :started, :status)');
$logStmt->execute(['type' => 'host_detections', 'started' => date('Y-m-d H:i:s'), 'status' => 'running']);
$logId = (int)$pdo->lastInsertId();

$client = null;
$clientPool = [];
$exitCode = 0;

try {
    $apiVersions = Config::get('qualys.host_detection_api_versions') ?? ['2.0', '3.0', '4.0'];
    $primaryVersion = (string)(Config::get('qualys.api_version') ?? '4.0');
    $agentScopeTag = Config::get('qualys.agent_scope_tag') !== null ? (string)Config::get('qualys.agent_scope_tag') : null;
    $excludedTags = is_array(Config::get('qualys.excluded_tags')) ? Config::get('qualys.excluded_tags') : null;

    // See "Incremental filter and overlap" and "New-host pass" in this
    // file's docblock.
    $sinceFilter = (string)(Config::get('qualys.host_detection_incremental_filter') ?? 'vm_processed_after');
    $overlapMinutes = max(0, (int)(Config::get('qualys.host_detection_overlap_minutes') ?? 60));
    $newHostPass = Config::get('qualys.host_list_new_host_pass') ?? true;
    $newHostPass = filter_var($newHostPass, FILTER_VALIDATE_BOOLEAN);
    $pruneMissing = Config::get('qualys.host_list_prune_missing') ?? true;
    $pruneMissing = filter_var($pruneMissing, FILTER_VALIDATE_BOOLEAN);

    // See "Host List pass interval" in this file's docblock.
    $hostListIntervalMinutes = max(0, (int)(Config::get('qualys.host_list_pass_interval_minutes') ?? 0));
    $hostListPassToleranceSec = 5 * 60;
    $hostListPassStartedAt = time();
    $hostListLastStartedAt = null;
    $hostListPassDue = true;
    if ($newHostPass && $hostListIntervalMinutes > 0) {
        $passStateStmt = $pdo->prepare('SELECT state_json FROM sync_state WHERE sync_type = :type');
        $passStateStmt->execute(['type' => 'host_list_pass']);
        $passState = json_decode((string)$passStateStmt->fetchColumn(), true);
        $hostListLastStartedAt = is_array($passState) && isset($passState['last_started_at']) ? (int)$passState['last_started_at'] : null;
        $hostListPassDue = $hostListLastStartedAt === null
            || $hostListPassStartedAt - $hostListLastStartedAt >= $hostListIntervalMinutes * 60 - $hostListPassToleranceSec;
    }

    foreach ($apiVersions as $version) {
        $clientPool[$version] = new QualysApiClient(
            (string)Config::get('qualys.api_base_url'),
            (string)Config::get('qualys.username'),
            (string)Config::get('qualys.password'),
            (string)$version,
            $agentScopeTag,
            $excludedTags
        );
    }
    // The one version this run falls back to if the round-robin-picked
    // one fails - see this file's own docblock for why that's a
    // whole-pull retry here rather than KB sync's per-window one.
    $client = $clientPool[$primaryVersion] ?? reset($clientPool);

    // Persisted across runs (unlike sync_knowledge_base.php's in-process
    // $rrIndex) - see this file's docblock for why one run here doesn't
    // make enough calls for an in-process counter to mean anything.
    $rrStateStmt = $pdo->prepare('SELECT state_json FROM sync_state WHERE sync_type = :type');
    $rrStateStmt->execute(['type' => 'host_detections_rr']);
    $rrStateJson = $rrStateStmt->fetchColumn();
    $rrState = $rrStateJson ? json_decode((string)$rrStateJson, true) : [];
    $rrIndex = (int)($rrState['index'] ?? 0);

    $versions = array_keys($clientPool);
    // Next version in the rotation that Qualys hasn't last reported as at
    // or below the reserve - rather than walking into the client's reserve
    // guard and failing the run. (See "Auto interval".)
    $picked = ApiBudget::pickVersion($versions, $rrIndex, '/fo/asset/host/vm/detection/', $budgetReserve);
    if ($picked === null) {
        throw new \RuntimeException("Every Host Detection API version is at or below the {$budgetReserve}-call reserve per Qualys's last report - nothing to pull with until calls free up.");
    }
    if ($picked['index'] !== $rrIndex) {
        fwrite(STDOUT, '/api/' . $versions[$rrIndex % count($versions)] . "/ Host Detection is at or below the reserve - using the next version with calls left.\n");
    }
    $rrIndex = $picked['index'];
    $pickedVersion = $picked['version'];
    $pickedClient = $clientPool[$pickedVersion];

    // Advance and persist immediately, independent of whether this run's
    // pull below actually succeeds - this is just "which version to try
    // next", not a completeness cursor, so it shouldn't get stuck
    // repeatedly retrying a version that just failed.
    $pdo->prepare('
        INSERT INTO sync_state (sync_type, state_json) VALUES (:type, :state)
        ON DUPLICATE KEY UPDATE state_json = VALUES(state_json)
    ')->execute([
        'type'  => 'host_detections_rr',
        'state' => json_encode(['index' => $rrIndex + 1]),
    ]);

    fwrite(STDOUT, "This run's assigned API version: /api/{$pickedVersion}/\n");

    // Every per-host write - asset row, tags, detections, and removal of
    // detections Qualys no longer reports - goes through HostSyncWriter, the
    // one copy of that logic shared with scripts/reconcile_asset_inventory.php
    // (which used to carry a near-copy that silently drifted; see that class's
    // docblock). Everything around it - the incremental window, round-robin,
    // snapshotting and tombstone pruning below - stays here, because those
    // genuinely differ between the two jobs.
    // Tag lookups go through the primary-version client so their calls are
    // logged with the rest of this run's - see TagScopeClassifier.
    $tagScope = new TagScopeClassifier($pdo, fn(array $ids): array => $client->searchTagsByIds($ids));
    $writer = new HostSyncWriter($pdo, $tagScope);

    // Incremental since the last successful run, less the overlap - null
    // (full pull) on a fresh install where no sync has ever succeeded yet.
    $lastSuccess = $pdo->query("
        SELECT completed_at FROM sync_log
        WHERE sync_type = 'host_detections' AND status = 'success' AND completed_at IS NOT NULL
        ORDER BY completed_at DESC LIMIT 1
    ")->fetchColumn();
    $sinceDate = $lastSuccess ? (new DateTimeImmutable($lastSuccess))->modify("-{$overlapMinutes} minutes") : null;

    fwrite(STDOUT, $sinceDate !== null
        ? "Incremental pull: {$sinceFilter} " . $sinceDate->format('Y-m-d H:i:s T') . " (last success {$lastSuccess} less {$overlapMinutes} min overlap)\n"
        : "No previous successful sync - full pull.\n");

    /**
     * Wraps this run's whole pull with the round-robin/fallback behaviour
     * described in this file's docblock - tries the picked version first,
     * and if it fails before yielding a single host, retries the entire
     * pull on the primary version instead. A failure after some hosts
     * have already come through re-throws rather than silently
     * restarting mid-stream, same reasoning as sync_knowledge_base.php's
     * equivalent guard. $servedBy ends up as whichever client actually
     * delivered the pull, so the new-host pass below can use the same one.
     */
    $servedBy = $pickedClient;
    $fetchHostDetectionsRoundRobin = function () use ($pickedClient, $client, $sinceDate, $sinceFilter, &$servedBy): iterable {
        $yieldedAny = false;
        try {
            foreach ($pickedClient->fetchHostDetections($sinceDate, null, $sinceFilter) as $host) {
                $yieldedAny = true;
                yield $host;
            }
            return;
        } catch (\Throwable $e) {
            if ($pickedClient === $client || $yieldedAny) {
                throw $e;
            }
            fwrite(STDOUT, "  (this run's assigned API version failed before returning anything - {$e->getMessage()} - retrying this whole pull on the primary version instead)\n");
        }
        $servedBy = $client;
        yield from $client->fetchHostDetections($sinceDate, null, $sinceFilter);
    };

    $recordsProcessed = 0;
    $detectionsRemoved = 0;
    $resolutionsRecorded = 0;
    $hostsSeen = [];

    foreach ($fetchHostDetectionsRoundRobin() as $host) {
        $hostsSeen[(int)$host['id']] = true;
        $result = $writer->writeHost($host);

        $recordsProcessed    += $result['written'];
        $detectionsRemoved   += $result['removed'];
        $resolutionsRecorded += $result['resolutions'];
    }

    // Detections skipped for a QID with no local KB row - recorded so the
    // gap shows on the dashboard instead of the finding silently missing.
    // See MissingKbQidRepository.
    $skippedQids = $writer->getSkippedQids();
    fwrite(STDOUT, MissingKbQidRepository::logLine($skippedQids, MissingKbQidRepository::record($pdo, $skippedQids)));

    // New-host pass - see this file's docblock. Runs before the snapshot
    // below so a host added here gets today's (zero) posture row too.
    $newHostsAdded = 0;
    $assetsPruned = 0;
    $pruneGuardReasons = [];
    if ($newHostPass && !$hostListPassDue) {
        $agoMin = (int)round(($hostListPassStartedAt - $hostListLastStartedAt) / 60);
        fwrite(STDOUT, "New-host pass (Host List): skipped - the last one started {$agoMin} min ago (qualys.host_list_pass_interval_minutes = {$hostListIntervalMinutes}); next due from "
            . date('H:i', $hostListLastStartedAt + $hostListIntervalMinutes * 60 - $hostListPassToleranceSec) . ".\n");
    }
    if ($newHostPass && $hostListPassDue) {
        // The Host List pass keeps its own place in the version rotation
        // ('host_list_rr') rather than borrowing the detection pull's - see
        // "Host List version rotation" in this file's docblock - and skips a
        // version Qualys last reported at the reserve, like the pull above.
        $hlRrStmt = $pdo->prepare('SELECT state_json FROM sync_state WHERE sync_type = :type');
        $hlRrStmt->execute(['type' => 'host_list_rr']);
        $hlRrState = json_decode((string)$hlRrStmt->fetchColumn(), true);
        $hlRrIndex = is_array($hlRrState) ? max(0, (int)($hlRrState['index'] ?? 0)) : 0;
        $hlPicked = ApiBudget::pickVersion($versions, $hlRrIndex, '/fo/asset/host/', $budgetReserve);
        if ($hlPicked === null) {
            fwrite(STDOUT, "New-host pass (Host List): skipped - every version is at or below the {$budgetReserve}-call reserve; it runs again once calls free up.\n");
            $hostListPassDue = false;
        }
    }
    if ($newHostPass && $hostListPassDue) {
        $existsStmt = $pdo->prepare('SELECT qualys_asset_id FROM assets WHERE qualys_host_id = :qualys_host_id');
        $fillAssetIdStmt = $pdo->prepare('UPDATE assets SET qualys_asset_id = :qualys_asset_id WHERE qualys_host_id = :qualys_host_id AND qualys_asset_id IS NULL');
        $listed = 0;
        $listedHostIds = [];
        $assetIdsFilled = 0;
        $hlRrIndex = $hlPicked['index'];
        $hostListVersion = $hlPicked['version'];
        $hostListClient = $clientPool[$hostListVersion];
        $pdo->prepare('
            INSERT INTO sync_state (sync_type, state_json) VALUES (:type, :state)
            ON DUPLICATE KEY UPDATE state_json = VALUES(state_json)
        ')->execute([
            'type'  => 'host_list_rr',
            'state' => json_encode(['index' => $hlRrIndex + 1]),
        ]);
        fwrite(STDOUT, "New-host pass (Host List): using /api/{$hostListVersion}/\n");

        foreach ($hostListClient->fetchHostList() as $host) {
            $listed++;
            $hostId = (int)$host['id'];
            $listedHostIds[$hostId] = true;
            if (isset($hostsSeen[$hostId])) {
                continue;
            }
            $existsStmt->execute(['qualys_host_id' => $hostId]);
            $storedAssetId = $existsStmt->fetchColumn();
            $existsStmt->closeCursor();
            if ($storedAssetId !== false) {
                // fetchColumn() gives false for no row, null for a row with no id.
                if ($storedAssetId === null && !empty($host['asset_id'])) {
                    $fillAssetIdStmt->execute(['qualys_asset_id' => (int)$host['asset_id'], 'qualys_host_id' => $hostId]);
                    $assetIdsFilled += $fillAssetIdStmt->rowCount();
                }
                continue;
            }

            $writer->upsertAssetAndTags($host);
            $newHostsAdded++;
            $label = $host['hostname'] ?: ($host['ip'] ?: "Qualys host ID {$hostId}");
            $tagNames = implode(', ', array_column($host['tags'] ?? [], 'name')) ?: '(no tags)';
            fwrite(STDOUT, "  new host with no open detections (or no processed scan yet): {$label}  os=" . ($host['os'] ?? '(none)') . "  tags={$tagNames}\n");
        }
        fwrite(STDOUT, "New-host pass (Host List): {$listed} host(s) returned, {$newHostsAdded} not yet stored and added"
            . ($assetIdsFilled > 0 ? ", AssetView id filled on {$assetIdsFilled} already-stored host(s)" : '') . ".\n");

        // Prune - see this file's docblock. Reached only once the Host List
        // pull above has completed, so absence from it means something.
        if ($pruneMissing) {
            $prunePlan = AssetInventoryPruner::plan($pdo, $listedHostIds + $hostsSeen, AssetInventoryPruner::maxRemovalPercent());
            foreach ($prunePlan['missing'] as $asset) {
                $label = $asset['hostname'] ?: ($asset['ip_address'] ?: "Qualys host ID {$asset['qualys_host_id']}");
                fwrite(STDOUT, "  no longer in Qualys: {$label} (local assets.id={$asset['id']}, Qualys host ID {$asset['qualys_host_id']})\n");
            }
            if ($prunePlan['guard_reasons'] !== []) {
                $pruneGuardReasons = $prunePlan['guard_reasons'];
                fwrite(STDOUT, "  MASS-REMOVAL GUARD - nothing deleted: " . implode('; ', $pruneGuardReasons) . "\n");
            } else {
                $assetsPruned = AssetInventoryPruner::deleteAssets($pdo, $prunePlan['missing']);
            }
            fwrite(STDOUT, "Prune (Host List): " . count($prunePlan['missing']) . " stored asset(s) no longer in Qualys, {$assetsPruned} deleted.\n");
        }

        // Reached only once the pull completed (it throws to the catch
        // otherwise), so a failed pass is retried by the next run.
        if ($hostListIntervalMinutes > 0) {
            $pdo->prepare('
                INSERT INTO sync_state (sync_type, state_json) VALUES (:type, :state)
                ON DUPLICATE KEY UPDATE state_json = VALUES(state_json)
            ')->execute([
                'type'  => 'host_list_pass',
                'state' => json_encode(['last_started_at' => $hostListPassStartedAt, 'last_started' => date('Y-m-d H:i:s', $hostListPassStartedAt)]),
            ]);
        }
    }

    // Refreshes today's row in asset_vuln_snapshot for every currently-
    // active asset - see VulnerabilityRepository::snapshotOpenCounts()'s
    // own docblock for why this is a fresh local aggregate rather than
    // tied to whichever hosts this particular incremental pull happened to
    // include, and why it's safe to call on every run rather than once a
    // day.
    $snapshotCount = VulnerabilityRepository::snapshotOpenCounts();

    fwrite(STDOUT, $tagScope->logLine());

    // Prune old remediation tombstones so detection_resolutions stays small.
    // Nothing reads a resolution older than the Trends movement window (30
    // days); the retention default (90) keeps a comfortable buffer over that,
    // and everything past it is dead weight. One cheap indexed delete per run
    // (idx_res_date), so the table reaches a small steady state rather than
    // growing forever. Preview what this removes any time with --dry-run-prune.
    $retentionDays = max(1, (int)(Config::get('sync.resolution_retention_days') ?? 90));
    $pruneCutoff = (new DateTimeImmutable())->modify("-{$retentionDays} days")->format('Y-m-d H:i:s');
    $pruneStmt = $pdo->prepare('DELETE FROM detection_resolutions WHERE resolved_at < :cutoff');
    $pruneStmt->execute(['cutoff' => $pruneCutoff]);
    $resolutionsPruned = $pruneStmt->rowCount();

    foreach ($clientPool as $version => $c) {
        $rateInfo = $c->getLastRateLimitInfo();
        if ($rateInfo !== null && $rateInfo['remaining'] !== null) {
            fwrite(STDOUT, "Qualys API calls remaining on /api/{$version}/: {$rateInfo['remaining']}" . ($rateInfo['limit'] !== null ? "/{$rateInfo['limit']}" : '') . ($rateInfo['window_sec'] !== null ? " (per {$rateInfo['window_sec']}s window)" : '') . " (last endpoint called)\n");
        }
    }

    fwrite(STDOUT, "Host detection sync complete: {$recordsProcessed} detections processed, {$detectionsRemoved} removed (no longer reported by Qualys), {$resolutionsRecorded} recorded as resolved, {$newHostsAdded} new zero-detection host(s) added, {$assetsPruned} asset(s) no longer in Qualys deleted, {$resolutionsPruned} old resolution tombstone(s) pruned (retention {$retentionDays}d), {$snapshotCount} asset(s) snapshotted for today's vulnerability posture history.\n");

    if ($pruneGuardReasons !== []) {
        // Everything else this run did stands; the refusal is recorded as a
        // failure so it can't go unnoticed - see "Prune" in the docblock.
        $guardMessage = 'Mass-removal guard refused to delete assets no longer in Qualys: ' . implode('; ', $pruneGuardReasons)
            . ' - if this is a genuine decommission, review a dry run of scripts/reconcile_asset_inventory.php and run it by hand with --confirm --allow-mass-removal.';
        $pdo->prepare('UPDATE sync_log SET status = :status, completed_at = :completed, records_processed = :count, error_message = :err WHERE id = :id')
            ->execute(['status' => 'failed', 'completed' => date('Y-m-d H:i:s'), 'count' => $recordsProcessed, 'err' => $guardMessage, 'id' => $logId]);
        fwrite(STDERR, "Host detection sync: {$guardMessage}\n");
        $exitCode = 1;
    } else {
        $pdo->prepare('UPDATE sync_log SET status = :status, completed_at = :completed, records_processed = :count WHERE id = :id')
            ->execute(['status' => 'success', 'completed' => date('Y-m-d H:i:s'), 'count' => $recordsProcessed, 'id' => $logId]);
    }
} catch (\Throwable $e) {
    $pdo->prepare('UPDATE sync_log SET status = :status, completed_at = :completed, error_message = :err WHERE id = :id')
        ->execute(['status' => 'failed', 'completed' => date('Y-m-d H:i:s'), 'err' => $e->getMessage(), 'id' => $logId]);

    fwrite(STDERR, 'Host detection sync failed: ' . $e->getMessage() . "\n");
    $exitCode = 1;
} finally {
    if (!empty($clientPool)) {
        try {
            $allCalls = array_merge(...array_values(array_map(fn($c) => $c->getCallLog(), $clientPool)));
            ApiCallLogRepository::recordCalls($allCalls);
        } catch (\Throwable $logError) {
            fwrite(STDERR, 'Warning: failed to persist API call log: ' . $logError->getMessage() . "\n");
        }
    }
    flock($lockHandle, LOCK_UN);
    fclose($lockHandle);
}

// exit() deliberately lives out here, not inside the catch block above -
// see sync_knowledge_base.php's matching comment: exit()/die() skip any
// enclosing finally block entirely, which would have silently skipped the
// API call log persistence and lock cleanup above on every failure.
exit($exitCode);
