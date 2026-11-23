#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Removes local assets - and, via the existing ON DELETE CASCADE on
 * asset_tags/host_detections, everything attached to them - that no
 * longer exist in Qualys at all: a host that's been destroyed or
 * decommissioned there.
 *
 * Agent-only scope (2026-07): both Qualys pulls this script makes are now
 * restricted to the tag named in qualys.agent_scope_tag (see
 * QualysApiClient's "Agent-only scope" docblock note), per Mark's
 * decision to pivot this from a combined agent+scan dashboard to an
 * agent-only internal vulnerability management tool. This makes the
 * "removes local assets not found in Qualys" behaviour above do double
 * duty: a host that's been genuinely destroyed in Qualys, AND a host
 * that's still perfectly alive in Qualys but is scanner-only (no longer
 * carries the agent scope tag), both now look identical from this
 * script's point of view - neither appears in the (now tag-filtered) pull
 * - and both get removed the same way. That's the intended effect of the
 * pivot (scanner-only assets are meant to disappear from this dashboard
 * entirely), but it does mean the "NOT found anywhere in Qualys's current
 * inventory" wording below is no longer literally accurate for every host
 * it lists - some of those hosts are still very much in Qualys, just
 * outside the new scope. See the dry-run output itself, which spells this
 * out explicitly rather than leaving it to a comment only read by whoever
 * next opens this file.
 *
 * Per-tag exclusion (2026-07, same day, once real data showed the gap):
 * qualys.excluded_tags strips specific tag NAMES out of every host's tag
 * list regardless of whether the host itself is in scope - a host can
 * legitimately carry the agent scope tag AND an unrelated tag (e.g. a
 * dynamic IP-range tag matching that host's IP for an unrelated reason)
 * that has nothing to do with why it matched. This is what actually fixes
 * a deleted scan-artifact tag reappearing after this script runs again -
 * removing the host from scope entirely wasn't possible (it's a real,
 * legitimately-scoped agent host), so the fix strips the specific
 * unwanted tag names instead of the whole host. See QualysApiClient's
 * "Per-tag exclusion" docblock note for the real host that surfaced this.
 *
 * PRACTICAL CONSEQUENCE WORTH KNOWING BEFORE DEPLOYING THIS CHANGE: the
 * existing cron entry below already runs this with --confirm every hour.
 * The very first run after deploying an updated QualysApiClient.php (with
 * qualys.agent_scope_tag set in config) will delete every currently
 * scanner-tracked asset, its tags, its detections, and its
 * asset_vuln_snapshot history rows, all in one pass - not something that
 * needs a second confirmation, since --confirm is already wired into the
 * schedule. Strongly recommended: run this manually WITHOUT --confirm
 * once first, read the "would remove" list all the way through, and
 * confirm it's exactly the scanner-only hosts expected (not, say, an
 * agent host that's temporarily missing the scope tag due to an
 * unrelated Qualys-side tagging delay) before letting the next scheduled
 * --confirm run fire for real.
 *
 * ALSO refreshes hostname/IP/DNS name/OS/tracking method and tag
 * assignments for every host Qualys still reports - not just existence
 * checking. This matters for a reason separate from deletion: the normal
 * incremental sync (scripts/sync_host_detections.php) only ever sees a
 * host that's had a fresh VM scan/agent assessment since last run
 * (vm_scan_since) - so a hostname (or tag) that changes on the Qualys side
 * WITHOUT a new scan triggering it - a DNS rename, an admin editing
 * inventory directly, a Cloud Agent inventory sync that runs on its own
 * schedule separate from its vulnerability assessment - would never reach
 * this dashboard at all until that host's next actual scan, which could be
 * a long wait on a slow scan cadence. This script's full, unfiltered pull
 * doesn't have that blind spot: it already has every host's current
 * hostname/tags in hand for the existence check above, so upserting that
 * data too costs nothing extra against the Qualys API - it's already been
 * paid for by the same call.
 *
 * PENDING-TAG PROMOTION (fixed 2026-07-23): the tag half of that refresh
 * used to be this script's own private "look the Qualys tag ID up, INSERT
 * a new row if it isn't there" pair, which knew nothing about pending tags
 * (a row pre-created by name with qualys_tag_id NULL, so a client account
 * can be scoped to a tag before any agent carrying it has reported). It
 * now goes through UserRepository::resolveSyncedTagId(), the same resolver
 * scripts/sync_host_detections.php and scripts/diagnose_tags.php --full
 * already used, which matches a pending row by name and promotes it in
 * place instead.
 *
 * This script, not the incremental sync, was where that mattered most: it
 * runs hourly against a FULL pull, while sync_host_detections.php only
 * sees hosts assessed since its last run - so for a newly-tagged host this
 * was almost always the job that got there first, and what it did was
 * insert a SECOND tags row for a tag that already existed locally as a
 * pending one. From that moment the pending row could never promote (the
 * resolver's step 1, exact match on the Qualys tag ID, found the duplicate
 * every time), leaving the pre-created row orphaned with its accounts
 * attached and no assets, and the duplicate holding the assets with no
 * accounts. Observed on "FaiceTechAgents", resolved by deleting the
 * orphaned row by hand. Note that this fix is preventive only - it stops
 * new pairs forming and does NOT untangle one that already exists. Check
 * for a leftover with:
 *   SELECT LOWER(TRIM(name)) n, COUNT(*) c FROM tags GROUP BY n HAVING c > 1;
 * Deleting the orphan (as above) is the simplest resolution, but note it
 * cascades user_tags - every account assigned to it needs re-assigning to
 * the surviving row afterwards, or it fail-closes to seeing nothing.
 *
 * ALSO upserts and reconciles detections, same logic and same reasoning as
 * scripts/sync_host_detections.php (see that script's docblock for the
 * detail): a QID too new to be in the local knowledge_base cache yet gets
 * skipped there and picked up next time that specific host is rescanned -
 * which, same blind spot as hostname/tags above, could be a long wait.
 * Since this script already has that host's current, complete detection
 * list in hand from the same full pull, retrying the KB lookup here costs
 * nothing extra either - if the KB has since caught up, the finding shows
 * up on this run instead of waiting for the next real scan. Detections
 * Qualys no longer reports for a host get removed here too, the same
 * delete-outright (no history kept) policy as the normal sync - covering
 * hosts that haven't been rescanned recently enough for the incremental
 * job to have caught that on its own yet.
 *
 * Why this is its own script rather than folded into the normal, much more
 * frequent scripts/sync_host_detections.php run: that script is incremental
 * (vm_scan_since), so on any given run the vast majority of hosts simply
 * don't appear at all - that's the NORMAL state for a host that just isn't
 * due for a rescan yet, not a sign it's gone. There's no way to tell
 * "genuinely destroyed" apart from "hasn't been rescanned this cycle" from
 * an incremental pull alone.
 *
 * A time-based guess (e.g. "no scan reported in N days, assume it's gone")
 * was tried and deliberately rejected here: it can't tell a truly-destroyed
 * host apart from one that's simply on a slower, completely normal, scan or
 * agent cadence - and the actual requirement is that an asset still in
 * Qualys must always still be in the dashboard, not "probably still in
 * Qualys". A guess can only ever be probably right; it can't guarantee
 * that. The only way to actually know is to ask Qualys directly - a full,
 * unfiltered pull (the same one scripts/diagnose_tags.php --full uses) -
 * and compare that against what's stored locally: anything local NOT in
 * that full pull is confirmed gone, not inferred.
 *
 * SHARED PRUNE (2026-11): the "which local assets are missing, may we
 * delete them, delete them" step - including the asset half of the
 * mass-removal guard below - now lives in src/Lib/AssetInventoryPruner.php,
 * because scripts/sync_host_detections.php now makes a full, unfiltered
 * Host List pull every hour too and prunes from it with the same rule and
 * guard. So a host removed from Qualys normally leaves the dashboard within
 * the hour, and this job's prune is the backstop. What stays here is what
 * only this job can judge, because only it makes the full detection pull:
 * clearing all findings on a host whose last finding was fixed, and the
 * guard's third reason that goes with it.
 *
 * This makes a full, unfiltered Host List Detection call, which is a
 * heavier request than the normal incremental sync - that's the tradeoff
 * behind running this on its own schedule, separate from
 * scripts/sync_host_detections.php's much more frequent one: more often
 * means fresher (a destroyed host, or a renamed one, gets noticed sooner),
 * less often means fewer full pulls against your Qualys API budget. See
 * the actual configured cadence below.
 *
 * SAFETY: defaults to a dry run - reports exactly what it WOULD remove
 * without touching the database at all (this includes the metadata/tag
 * refresh above - a dry run writes nothing whatsoever, not even the
 * non-destructive parts). Pass --confirm to actually write. Strongly
 * recommended: run it a few times without --confirm first and
 * sanity-check the output against what you know about your own
 * environment before trusting it to run unattended via cron - in
 * particular, check the "zero-detection asset: ..." lines (printed
 * either way, confirm or not) show a real hostname/OS/tags for hosts you
 * know are agent-managed and clean, not blank or garbled fields - that's
 * the direct sign the new Host List field mapping needs a fix before this
 * is trustworthy unattended.
 *
 * One assumption worth knowing about, since it's the crux of why this
 * script is safe to trust: this relies on Qualys's Host List Detection API
 * returning every host matching your API user's scope in a full pull,
 * including a host that currently has zero open detections at all (a
 * totally clean host with no findings). That's the standard behaviour of
 * this endpoint, but it hasn't specifically been exercised against an
 * all-clean host on this subscription. If a host you know is still alive
 * and clean is ever reported here as missing from Qualys, that assumption
 * is the first thing to check - not a reason to just add --confirm anyway.
 *
 * ALSO catches an asset that has zero open detections at all - see
 * QualysApiClient::fetchHostList()'s docblock for the full reasoning (the
 * short version: fetchHostDetections() appears to simply never return a
 * host with nothing to detect, since that endpoint is shaped around
 * detection records rather than plain asset inventory - reported 2026-07
 * as "an agent with zero vulnerabilities never appears on the dashboard
 * at all"). This is a genuinely separate Qualys API call (Host List, not
 * Host List Detection) made once per run alongside the existing full
 * pull above - a real, additional cost against your API budget, not a
 * free byproduct of the first call the way the metadata/tag/detection
 * refresh above is. Its field mapping also isn't yet confirmed against a
 * real response (unlike everything else in this script) - see this
 * script's own SAFETY note below on validating that before trusting it
 * unattended.
 *
 * Usage:
 *   php scripts/reconcile_asset_inventory.php             # dry run - reports only, changes nothing
 *   php scripts/reconcile_asset_inventory.php --confirm   # actually deletes/refreshes what the dry run reported
 *   php scripts/reconcile_asset_inventory.php --page-size=2   # dry run, but forces a tiny
 *                                                               # truncation_limit on BOTH the
 *                                                               # Host List Detection pull and
 *                                                               # the Host List supplemental
 *                                                               # pull below, so each has to
 *                                                               # follow its own multi-page
 *                                                               # continuation loop for real
 *                                                               # instead of getting this
 *                                                               # subscription's whole
 *                                                               # inventory back in one page.
 *                                                               # The host counts printed at
 *                                                               # the end should match a normal
 *                                                               # run with no --page-size - if
 *                                                               # they don't, the pagination
 *                                                               # loop itself is the thing to
 *                                                               # check (QualysApiClient.php's
 *                                                               # extractContinuationUrl()), not
 *                                                               # anything downstream of it.
 *                                                               # Safe without --confirm (the
 *                                                               # default): nothing gets written
 *                                                               # either way, this only changes
 *                                                               # how many requests it takes to
 *                                                               # read the same data.
 *   php scripts/reconcile_asset_inventory.php --confirm --allow-mass-removal
 *                                                               # lets a run through the
 *                                                               # mass-removal guard below -
 *                                                               # only for a deliberate,
 *                                                               # reviewed run, never in cron.
 *
 * Actual cron entry (confirmed 2026-11) - every 6 hours, throttled from
 * hourly on 2026-10-17 when the licence dropped to 25 calls per endpoint
 * per version per 24h:
 *   40 0,6,12,18 * * * php /var/www/dashboard.plainsightsecurity.co.uk/scripts/reconcile_asset_inventory.php --confirm >> /var/log/vulndash/asset_inventory_reconcile.log 2>&1
 * (written here as 0,6,12,18 - the crontab's step syntax would end this
 * comment block early)
 *
 * Each run is a PAIR of full pulls (Host List Detection + the Host List
 * call above), one call per page per endpoint - worth factoring in if API
 * budget ever gets tight, since a less frequent schedule here costs
 * freshness on the things only this job does (clearing a host's last fixed
 * findings, refreshing hostname/tags for hosts the hourly sync hasn't seen).
 *
 * API version rotation (added 2026-10): Qualys counts each endpoint on
 * each API version separately (25 calls per rolling 24h since the 2026-10
 * licence change), and this job's two full pulls are the calls that grow
 * fastest as the estate grows - one per page, per endpoint, per run. Pinned
 * to a single version (qualys.reconcile_api_version), that one counter is
 * what runs out first. Listing several in qualys.reconcile_api_versions
 * spreads the runs across them instead: each run uses the next version in
 * the list for BOTH pulls, so a run's pages and its two endpoints all land
 * on one version and its log reads cleanly. The position is kept in
 * sync_state ('asset_reconcile_rr'), the same way
 * scripts/sync_host_detections.php keeps its own, and is only advanced by a
 * --confirm run - a dry run stays write-free and simply reports (and uses)
 * the version the next real run will use. There's no fallback to another
 * version if the picked one fails: the run fails loudly, deletes nothing
 * (deletion only happens after both pulls complete), and the next run moves
 * on to the next version. Without qualys.reconcile_api_versions, behaviour
 * is unchanged - qualys.reconcile_api_version as before.
 *
 * Page size: both pulls use qualys.host_page_size hosts per page (see
 * QualysApiClient's class docblock) unless --page-size overrides it for
 * the run - which is also how to try a larger page size against the live
 * API, as a dry run, before putting it in config.
 *
 * MASS-REMOVAL GUARD (added 2026-10): everything destructive here is
 * driven by absence - a host missing from both pulls is deleted, and a host
 * in the Host List but missing from the detection pull has all its findings
 * cleared as remediated. So a Qualys response that is valid but wrongly
 * empty would read as "the whole estate is gone" or "everything is fixed".
 * That is not hypothetical: Qualys suspended this subscription for about
 * two weeks (27 Sep - 11 Oct 2026) until it was licensed, every detection
 * call returning an empty result, and this job only escaped wiping the
 * local inventory because it wasn't running at the time. A single endpoint
 * can also go dark on its own - KnowledgeBase access on qg1 needed a
 * separate entitlement - which is why clearing findings is guarded too, not
 * just deleting assets.
 *
 * Before deleting or clearing anything, the run now refuses (exit code 1,
 * nothing deleted or cleared; the non-destructive refresh above has
 * already happened, which is harmless) if:
 *   - both pulls returned no hosts at all while assets are stored locally;
 *   - more than qualys.reconcile_max_removal_percent (default 50) of local
 *     assets would be deleted; or
 *   - more than that share of the assets that currently have findings would
 *     have ALL of them cleared.
 * The first two come from AssetInventoryPruner::plan() (shared with the
 * hourly sync, see "SHARED PRUNE" above); the third is this job's own.
 * Not "either pull returned nothing": a fully patched estate legitimately
 * returns zero hosts from the detection pull. A dry run reports what the
 * guard would do without enforcing it. A genuine mass decommission goes
 * through a deliberate manual run with --allow-mass-removal, after a dry
 * run to review the list.
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\AssetInventoryPruner;
use VulnDash\Lib\Config;
use VulnDash\Lib\Database;
use VulnDash\Lib\HostSyncWriter;
use VulnDash\Lib\MissingKbQidRepository;
use VulnDash\Lib\TagScopeClassifier;
use VulnDash\Scripts\QualysApiClient;

$options = getopt('', ['confirm', 'page-size::', 'allow-mass-removal']);
$confirm = array_key_exists('confirm', $options);
$pageSize = isset($options['page-size']) ? (int)$options['page-size'] : null;
$allowMassRemoval = array_key_exists('allow-mass-removal', $options);

// Guard against two invocations overlapping - same pattern as the other
// sync scripts, own lock file since this is a separate job on its own
// schedule.
$lockPath = sys_get_temp_dir() . '/vulndash_asset_inventory_reconcile.lock';
$lockHandle = fopen($lockPath, 'c');
if ($lockHandle === false) {
    fwrite(STDERR, "Could not open lock file {$lockPath} - check its ownership/permissions (this is a real error, not a normal overlapping-run skip).\n");
    exit(1);
}
@chmod($lockPath, 0666);
if (!flock($lockHandle, LOCK_EX | LOCK_NB)) {
    fwrite(STDOUT, "Another asset inventory reconciliation is already running - exiting.\n");
    exit(0);
}

$client = null;
$exitCode = 0;

try {
    $agentScopeTag = Config::get('qualys.agent_scope_tag') !== null ? (string)Config::get('qualys.agent_scope_tag') : null;
    $excludedTags  = is_array(Config::get('qualys.excluded_tags')) ? Config::get('qualys.excluded_tags') : null;

    $pdo = Database::getConnection();

    // See "API version rotation" in this file's docblock.
    $reconcileVersions = Config::get('qualys.reconcile_api_versions');
    $reconcileVersions = is_array($reconcileVersions)
        ? array_values(array_filter(array_map(static fn($v): string => trim((string)$v), $reconcileVersions), static fn(string $v): bool => $v !== ''))
        : [];

    if ($reconcileVersions !== []) {
        $rrStateStmt = $pdo->prepare('SELECT state_json FROM sync_state WHERE sync_type = :type');
        $rrStateStmt->execute(['type' => 'asset_reconcile_rr']);
        $rrStateJson = $rrStateStmt->fetchColumn();
        $rrState = $rrStateJson ? json_decode((string)$rrStateJson, true) : null;
        $rrIndex = is_array($rrState) ? max(0, (int)($rrState['index'] ?? 0)) : 0;

        $reconcileVersion = $reconcileVersions[$rrIndex % count($reconcileVersions)];

        // Advanced before the pulls, regardless of how this run goes - it's
        // "which version next", not a completeness cursor, so a version that
        // fails shouldn't be retried on every run after it.
        if ($confirm) {
            $pdo->prepare('
                INSERT INTO sync_state (sync_type, state_json) VALUES (:type, :state)
                ON DUPLICATE KEY UPDATE state_json = VALUES(state_json)
            ')->execute([
                'type'  => 'asset_reconcile_rr',
                'state' => json_encode(['index' => $rrIndex + 1]),
            ]);
        }

        fwrite(STDOUT, "[API version for both pulls: /api/{$reconcileVersion}/ - rotating through " . implode(', ', $reconcileVersions) . ' (qualys.reconcile_api_versions)' . ($confirm ? '' : '; dry run, so the rotation is not advanced') . "]\n");
    } else {
        // Its own version setting, falling back to qualys.api_version, so this
        // job can move off Host List Detection 4.0 (EOS December 2025, EOL June
        // 2026 per Qualys's 10.36.1 API release notes) without moving the KB
        // sync's fallback too. Both endpoints this job calls were confirmed
        // working on /api/5.0/ on 2026-10-17, each with its own 25-call counter.
        $reconcileVersion = (string)(Config::get('qualys.reconcile_api_version') ?? Config::get('qualys.api_version') ?? '4.0');
        fwrite(STDOUT, "[API version for both pulls: /api/{$reconcileVersion}/]\n");
    }

    $client = new QualysApiClient(
        (string)Config::get('qualys.api_base_url'),
        (string)Config::get('qualys.username'),
        (string)Config::get('qualys.password'),
        $reconcileVersion,
        $agentScopeTag,
        $excludedTags
    );

    fwrite(STDOUT, ($confirm ? "[--confirm given - will actually write]\n" : "[DRY RUN - reporting only, nothing will be written; pass --confirm to actually write]\n"));
    if ($pageSize !== null) {
        fwrite(STDOUT, "[--page-size={$pageSize} given - forcing this truncation_limit on both Qualys pulls below (in place of qualys.host_page_size), e.g. to exercise the multi-page continuation loop or to try a larger page before configuring it]\n");
    } else {
        fwrite(STDOUT, '[page size: ' . $client->getHostPageSize() . " hosts per call (qualys.host_page_size)]\n");
    }
    if ($agentScopeTag !== null) {
        fwrite(STDOUT, "[scoped to Qualys tag \"{$agentScopeTag}\" (qualys.agent_scope_tag) - a host outside this scope is treated the same as one destroyed in Qualys: removed below]\n");
        fwrite(STDOUT, "Pulling all \"{$agentScopeTag}\"-tagged hosts from Qualys (no incremental filter) - this may take a while...\n");
    } else {
        fwrite(STDOUT, "Pulling ALL hosts from Qualys (no incremental filter, no tag scope configured) - this may take a while...\n");
    }
    if (!empty($excludedTags)) {
        fwrite(STDOUT, '[excluding tag name(s) from sync regardless of host scope (qualys.excluded_tags): ' . implode(', ', $excludedTags) . "]\n");
    }

    // Every per-host write - asset row, tags, detections, and removal of
    // detections Qualys no longer reports - goes through HostSyncWriter, the
    // one copy of that logic shared with scripts/sync_host_detections.php.
    // This script used to carry its own near-copy, which is how all three
    // bugs in that class's docblock got in: a private tag lookup that
    // couldn't promote a pending tag, an upsert missing detection_type, and
    // deletions with no remediation tombstone. See HostSyncWriter for why
    // the pull/prune/snapshot logic around it stays per-script.
    // Tag lookups (TagScopeClassifier) only happen on a write, so a dry run
    // never makes one.
    $tagScope = new TagScopeClassifier($pdo, fn(array $ids): array => $client->searchTagsByIds($ids));
    $writer = new HostSyncWriter($pdo, $tagScope);

    $qualysHostIds = [];
    $hostCount = 0;
    $refreshedCount = 0;
    $detectionsWritten = 0;
    $detectionsRemoved = 0;
    $resolutionsRecorded = 0;
    foreach ($client->fetchHostDetections(null, $pageSize) as $host) {
        $qualysHostIds[(int)$host['id']] = true;
        $hostCount++;

        if ($confirm) {
            // Detections are upserted and then reconciled against exactly
            // what Qualys just reported for this host - see
            // HostSyncWriter::writeHost(). Unlike the incremental sync, this
            // pull is full and unfiltered, so it is usually the job that
            // first observes a remediation: the tombstones written here are
            // most of what the Trends "Resolved" figure counts.
            $result = $writer->writeHost($host);
            $refreshedCount++;
            $detectionsWritten   += $result['written'];
            $detectionsRemoved   += $result['removed'];
            $resolutionsRecorded += $result['resolutions'];
        }
    }
    fwrite(STDOUT, "Qualys returned {$hostCount} host(s) with detection data.\n");

    // Same KB-gap recording as the hourly sync (see MissingKbQidRepository) -
    // this pull is full, so it sees every host's QIDs, not just recent ones.
    // Only a --confirm run writes detections, so only it can have skipped any.
    if ($confirm) {
        $skippedQids = $writer->getSkippedQids();
        fwrite(STDOUT, MissingKbQidRepository::logLine($skippedQids, MissingKbQidRepository::record($pdo, $skippedQids)));
    }

    // Supplemental pass: catches an asset Qualys knows about but that
    // fetchHostDetections() apparently never returns at all when it has
    // zero open detections - see fetchHostList()'s docblock in
    // QualysApiClient.php for the full reasoning (and the honest caveat
    // that this endpoint's field mapping isn't yet confirmed against a
    // real response). Only processes a host NOT already seen above -
    // fetchHostDetections()'s data is a strict superset for a host that
    // does have detections, so there's nothing to gain re-processing one
    // of those here, only API response bytes to parse for no benefit.
    $zeroDetectionCount = 0;
    $zeroDetectionHostIds = [];
    foreach ($client->fetchHostList($pageSize) as $host) {
        $hostId = (int)$host['id'];
        if (isset($qualysHostIds[$hostId])) {
            continue;
        }
        $qualysHostIds[$hostId] = true;
        $zeroDetectionCount++;

        // Printed regardless of --confirm, specifically because
        // fetchHostList()'s field mapping is unconfirmed (see its
        // docblock) - this is how to actually check hostname/OS/tags are
        // coming through correctly rather than blank or garbled, before
        // ever trusting this with --confirm.
        $label = $host['hostname'] ?: ($host['ip'] ?: "(no hostname/IP)");
        $tagNames = implode(', ', array_column($host['tags'] ?? [], 'name')) ?: '(no tags)';
        $trackingMethod = $host['tracking_method'] ?? null;
        // tracking_method used to be the field that caused a real
        // regression (2026-07): a missing value here got written as NULL,
        // which flipped every tag on the asset from "Agent Tags" to
        // "Scans" in UserRepository's former tag_type classification
        // (removed along with that split once this became an agent-only
        // tool - see UserRepository.php). That specific failure mode is
        // gone now, but tracking_method is still worth getting right: it's
        // still stored, still shown in diagnostics (this line, and
        // diagnose_tags.php), and a host missing it here is a sign
        // something's off with what Qualys just returned - loud and
        // explicit on purpose, not folded quietly into the rest of the
        // line, so a still-missing value is impossible to miss.
        $trackingLabel = $trackingMethod !== null ? $trackingMethod : '*** MISSING ***';
        fwrite(STDOUT, "  zero-detection asset: {$label}  os=" . ($host['os'] ?? '(none)') . "  tracking_method={$trackingLabel}  tags={$tagNames}\n");

        if ($confirm) {
            $writer->upsertAssetAndTags($host);
            $refreshedCount++;
        }
        // Its findings, if any are stored, are cleared further down - only
        // once the mass-removal guard has seen the whole picture.
        $zeroDetectionHostIds[] = $hostId;
    }
    fwrite(STDOUT, "Qualys returned {$zeroDetectionCount} additional host(s) with zero open detections (via the separate Host List endpoint).\n\n");

    $tagCountStmt = $pdo->prepare('SELECT COUNT(*) FROM asset_tags WHERE asset_id = :asset_id');
    $detectionCountStmt = $pdo->prepare('SELECT COUNT(*) FROM host_detections WHERE asset_id = :asset_id');

    // Which local assets both pulls missed, and the asset half of the
    // mass-removal guard - shared with the hourly sync, see "SHARED PRUNE"
    // in this file's docblock.
    $maxRemovalPercent = AssetInventoryPruner::maxRemovalPercent();
    $prunePlan = AssetInventoryPruner::plan($pdo, $qualysHostIds, $maxRemovalPercent);
    $toRemove = $prunePlan['missing'];

    // A host returned by the Host List endpoint but NOT by the Host List
    // Detection pull - which, for an endpoint that never returns a host with
    // nothing to report, is a positive statement that it has no open
    // detections left, not missing data. So anything still stored locally
    // for it has been fixed and is removed below, with the usual remediation
    // tombstones.
    //
    // This is the ONLY place that judgement can be made: such a host never
    // appears in either script's detection pull, so its rows were never
    // reconciled, while its presence in the Host List kept the asset from
    // being deleted. Remediating the LAST finding on a host used to mean that
    // finding stayed on the dashboard permanently (found 2026-07-23 on
    // "storage"). It is guarded alongside asset deletion because a detection
    // pull that is wrongly empty would make every host look like this.
    $toClear = [];
    if ($zeroDetectionHostIds !== []) {
        $placeholders = implode(',', array_fill(0, count($zeroDetectionHostIds), '?'));
        $clearStmt = $pdo->prepare("
            SELECT a.id, a.qualys_host_id, a.hostname, a.ip_address, COUNT(d.id) AS detection_count
            FROM assets a
            JOIN host_detections d ON d.asset_id = a.id
            WHERE a.qualys_host_id IN ($placeholders)
            GROUP BY a.id, a.qualys_host_id, a.hostname, a.ip_address
            ORDER BY a.hostname, a.ip_address
        ");
        $clearStmt->execute($zeroDetectionHostIds);
        $toClear = $clearStmt->fetchAll();
    }

    // Mass-removal guard - see this file's docblock. The asset-deletion
    // reasons come from the shared plan above; clearing findings is this
    // job's own.
    $assetsWithFindings = (int)$pdo->query('SELECT COUNT(DISTINCT asset_id) FROM host_detections')->fetchColumn();

    $guardReasons = $prunePlan['guard_reasons'];
    if ($assetsWithFindings > 0 && count($toClear) * 100 > $maxRemovalPercent * $assetsWithFindings) {
        $guardReasons[] = sprintf(
            '%d of %d asset(s) with findings (%.0f%%) would have ALL of them cleared as remediated, more than the %s%% allowed by qualys.reconcile_max_removal_percent',
            count($toClear), $assetsWithFindings, count($toClear) * 100 / $assetsWithFindings, AssetInventoryPruner::formatPercent($maxRemovalPercent)
        );
    }
    $guardBlocks = $guardReasons !== [] && !$allowMassRemoval;

    if (!empty($toClear)) {
        fwrite(STDOUT, count($toClear) . " asset(s) returned only by the Host List endpoint still have stored findings - these are treated as remediated and cleared:\n");
        foreach ($toClear as $asset) {
            $label = $asset['hostname'] ?: ($asset['ip_address'] ?: "(no hostname/IP - Qualys host ID {$asset['qualys_host_id']})");
            fwrite(STDOUT, "  - {$label} (local assets.id={$asset['id']}): {$asset['detection_count']} detection(s)\n");
        }
        fwrite(STDOUT, "\n");
    }

    if (empty($toRemove)) {
        fwrite(STDOUT, "Nothing to remove - every locally-stored asset was present in Qualys's current inventory.\n");
    } else {
        fwrite(STDOUT, count($toRemove) . " local asset(s) not returned by either Qualys pull this run:\n");
        if ($agentScopeTag !== null) {
            fwrite(STDOUT, "(Both pulls above are scoped to Qualys's \"{$agentScopeTag}\" tag - a host below may still exist in Qualys and simply be outside that scope now, which is the intended effect of the agent-only pivot, not necessarily destroyed/decommissioned there.)\n");
        }
        fwrite(STDOUT, "\n");

        foreach ($toRemove as $asset) {
            $tagCountStmt->execute(['asset_id' => $asset['id']]);
            $tagCount = (int)$tagCountStmt->fetchColumn();
            $detectionCountStmt->execute(['asset_id' => $asset['id']]);
            $detectionCount = (int)$detectionCountStmt->fetchColumn();

            $label = $asset['hostname'] ?: ($asset['ip_address'] ?: "(no hostname/IP - Qualys host ID {$asset['qualys_host_id']})");
            fwrite(STDOUT, "  - {$label} (local assets.id={$asset['id']}, Qualys host ID {$asset['qualys_host_id']}): {$tagCount} tag assignment(s), {$detectionCount} detection(s) would be removed with it.\n");
        }
    }

    if ($guardReasons !== []) {
        fwrite(STDOUT, "\n*** MASS-REMOVAL GUARD ***\n");
        foreach ($guardReasons as $reason) {
            fwrite(STDOUT, "  - {$reason}\n");
        }
        if ($allowMassRemoval) {
            fwrite(STDOUT, "  --allow-mass-removal given - going ahead anyway.\n");
        } elseif ($confirm) {
            fwrite(STDOUT, "  Nothing has been deleted or cleared. If this is genuinely intended, review the lists above and re-run by hand with --confirm --allow-mass-removal.\n");
        } else {
            fwrite(STDOUT, "  A --confirm run would refuse to delete or clear anything for this reason.\n");
        }
    }

    if ($confirm && !$guardBlocks) {
        foreach ($toClear as $asset) {
            $cleared = $writer->removeAllDetections((int)$asset['id']);
            $detectionsRemoved   += $cleared['removed'];
            $resolutionsRecorded += $cleared['resolutions'];
        }

        if (!empty($toRemove)) {
            $deleted = AssetInventoryPruner::deleteAssets($pdo, $toRemove);
            fwrite(STDOUT, "\nDeleted {$deleted} asset(s) (tag assignments and detections removed with them via cascade).\n");
        }
    } elseif (!$confirm && (!empty($toRemove) || !empty($toClear))) {
        fwrite(STDOUT, "\nDry run only - nothing was deleted or cleared. Re-run with --confirm to actually do the above.\n");
    }

    if ($confirm) {
        fwrite(STDOUT, $tagScope->logLine());
        fwrite(STDOUT, "\nRefreshed hostname/IP/OS/tags for {$refreshedCount} asset(s) total; {$detectionsWritten} detection(s) written, {$detectionsRemoved} removed and recorded as resolved ({$resolutionsRecorded} tombstone(s) written).\n");
    }

    if ($confirm && $guardBlocks) {
        fwrite(STDERR, 'Asset inventory reconciliation refused to delete or clear anything (mass-removal guard): ' . implode('; ', $guardReasons) . "\n");
        $exitCode = 1;
    }

    $callCount = count($client->getCallLog());
    $pageNote = '';
    if ($pageSize !== null) {
        // More than one call per endpoint is the only proof a continuation
        // page was actually followed - with a page larger than the estate,
        // nothing was.
        $pageNote = $callCount > 2
            ? " (forced truncation_limit={$pageSize} - more than one call per endpoint, so at least one pull followed a continuation page)"
            : " (forced truncation_limit={$pageSize} - every pull fitted in one page, so no continuation page was exercised)";
    }
    fwrite(STDOUT, "\nQualys API calls made this run: {$callCount}{$pageNote}\n");

    $rateInfo = $client->getLastRateLimitInfo();
    if ($rateInfo !== null && $rateInfo['remaining'] !== null) {
        fwrite(STDOUT, "Qualys API calls remaining: {$rateInfo['remaining']}" . ($rateInfo['limit'] !== null ? "/{$rateInfo['limit']}" : '') . ($rateInfo['window_sec'] !== null ? " (per {$rateInfo['window_sec']}s window)" : '') . "\n");
    }
} catch (\Throwable $e) {
    fwrite(STDERR, 'Asset inventory reconciliation failed: ' . $e->getMessage() . "\n");
    $exitCode = 1;
} finally {
    if ($client !== null) {
        try {
            ApiCallLogRepository::recordCalls($client->getCallLog());
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
