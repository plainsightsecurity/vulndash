#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Keeps the local `knowledge_base` cache in sync with Qualys.
 *
 * Qualys's global KnowledgeBase is large (decades of QIDs) and this
 * endpoint has no built-in pagination/truncation - a single "give me
 * everything" call is impractical, and the account this was built against
 * has a limited API call budget (Qualys's usual default is 300 calls per
 * rolling hour - check your own subscription's actual limit via the
 * X-RateLimit-Limit header this script logs after every call). So the
 * initial backfill is deliberately spread out:
 *
 *   - One run = one API call per (now possibly-bisected, see below) chunk,
 *     for a bounded calendar-date range (published_after/published_before),
 *     not the whole KB at once.
 *   - Progress (how far the backfill has got) is persisted in the
 *     `sync_state` table, so each run picks up where the last one left
 *     off - safe to run as often or as rarely as you like (hourly cron is
 *     a reasonable default; see the chunk size note below for how that
 *     maps to total backfill time).
 *   - Once the cursor reaches today, the backfill is marked complete and
 *     every run after that goes back to the cheap, normal incremental
 *     mode (last_modified_after since the last successful run) - a single
 *     small call per run from then on, not a growing one.
 *
 * Chunk size: qualys.kb_backfill_chunk_days in src/config/config.php
 * (defaults to 90 - one quarter at a time). Smaller = smaller/faster
 * individual responses but more total runs to finish; larger = fewer runs
 * but each one takes longer and returns more data. Qualys's KB goes back to
 * the late 1990s, so at the default chunk size and one run/hour, a full
 * backfill takes roughly 100 hours (~4 days) - tune this up or down
 * without needing a code change if that's not the right trade-off for your
 * call budget.
 *
 * --- Silent truncation incident (2026-07) and the safety net below -------
 *
 * Discovered 2026-07: several QIDs Qualys's own weekly "new QIDs added"
 * email listed were confirmed present via the API (scripts/diagnose_kb.php
 * --qid=<id> proved this directly, querying Qualys for those exact QIDs)
 * but never made it into this table, despite dozens of hourly incremental
 * runs since having a last_modified_after window that should have covered
 * them, and despite this script logging every one of those runs as a
 * plain, unremarkable success. One QID from the same batch DID sync
 * correctly. Nothing about that pattern is explained by the date filter
 * being wrong - it points at a single call silently returning fewer
 * records than actually matched, with nothing in the response (or in this
 * script, previously) to say so.
 *
 * This isn't a truncation format this app already knows how to detect: the
 * KnowledgeBase Download endpoint is a legacy "fo" API that - unlike
 * Host List/Host List Detection elsewhere in this app - has no documented
 * truncation_limit parameter or <WARNING><CODE>1980</CODE>> continuation
 * marker at all (Qualys's own docs for this endpoint list neither, and
 * this app already learned the hard way that the endpoint rejects
 * truncation_limit outright as an unrecognized parameter - see
 * QualysApiClient's class docblock). So there's no documented signal to
 * check for, and no confirmed cap value to defend against - the exact
 * mechanism (a hidden per-response record cap, a byte-size cap, something
 * else) was never directly observed, only inferred from the pattern above.
 *
 * The defense below doesn't depend on knowing the real mechanism or
 * threshold. Every last_modified_after/before (and, now, every
 * published_after/before) window this script fetches is treated as
 * possibly-incomplete rather than trusted outright: if a single call
 * returns qualys.kb_max_records_per_window records or more (default 500 -
 * deliberately conservative, well under the 1000-per-page default Qualys
 * documents for its OTHER "fo" endpoints, chosen as a working assumption
 * since the real cap for this endpoint, if any, has never been confirmed),
 * that response is NOT upserted as-is. Instead the time window is split in
 * half and each half is re-fetched and re-checked the same way,
 * recursively, until every leaf window's record count is comfortably
 * under the threshold - at which point, and only then, are its records
 * upserted. A window that still hits the threshold at a 1-second
 * granularity throws a hard error rather than silently accepting a
 * possibly-truncated response (see syncWindowWithSafetyNet() below) -
 * that's a real problem to look at directly, not something to paper over.
 *
 * In normal operation (a typical hour's worth of KB churn) this adds
 * nothing but one extra `if` per window - the threshold is high enough
 * that ordinary runs never trigger a split. It only does extra work on the
 * rare burst (like the batch of near-identical "EOL/Obsolete OS" QIDs that
 * caused this incident), which is exactly when the old code silently lost
 * data.
 *
 * --- CPU/load incident (2026-07-13) and the throttling below -----------
 *
 * The very first --rescan-since run against real data hit a window with
 * 89,277 genuinely-matching records (a mass metadata refresh across a large
 * slice of Qualys's KB, not a small batch like the incident above - the
 * kind of bulk "service modified" update Qualys is known to run
 * periodically). The safety net correctly rejected and split that window,
 * exactly as designed - but the ORIGINAL version of this code fully
 * buffered every one of those 89,277 rows (full title/diagnosis/
 * consequence/solution text and all) into a PHP array before ever checking
 * the count, for a window it was always going to reject anyway. Repeating
 * that across every oversized window on the way down drove the box's own
 * load average to 7-11 - a real, separate problem from the data-loss
 * incident above, caused by this fix's own first version.
 *
 * Fixed by making syncWindowWithSafetyNet() stop reading a window's
 * response the moment more than qualys.kb_max_records_per_window rows have
 * been seen, rather than finishing the iteration first - peak memory and
 * parse cost per call are now bounded by that threshold regardless of the
 * window's true size, whether it's 101 records or 89,277. The default
 * threshold was also lowered (500 -> 100) so a rejected call gives up even
 * sooner. A deliberate pause between every physical call
 * (qualys.kb_call_delay_ms, default 300ms) was added on top of that, so a
 * long historical walk can't monopolize the box for hours at a stretch,
 * and to reduce (not eliminate - QualysApiClient's existing 409
 * retry/backoff still covers an occasional miss) how often this collides
 * with your other cron jobs against Qualys's 2-concurrent-call limit.
 *
 * Catching up on the existing gap: this defense only protects runs from
 * this point forward - it can't retroactively know what a past run's
 * cursor walked past and dropped. Use --rescan-since to re-walk a past
 * window with the safety net now in place; see Usage below.
 *
 * --- Call-budget storm (2026-11) and resumable incremental sweeps -------
 *
 * From 2026-11-03 every run failed at the call reserve, spending all 88
 * usable KB calls a day (22 on each of four API versions) and getting
 * nowhere. A Qualys bulk update had stamped 1900+ QIDs with the same
 * second, more than once. Bisecting a ~2-day window down to one second
 * costs ~18 calls per dense second (plus the sibling halves), and with
 * the licence's 25 calls per endpoint per version per 24h, a few dense
 * seconds were enough to exhaust the budget mid-walk. The run then threw,
 * the cursor never moved, the 24h trailing overlap kept the same dense
 * seconds inside every later window, and every later run repeated the
 * identical descent - a loop that could never finish on its own. The
 * new-QID fast-path sat after the sweep, so brand-new QIDs stopped
 * arriving too.
 *
 * Three changes break that loop without loosening the safety net:
 *
 *   - Known dense seconds are remembered (sync_state row
 *     'knowledge_base_dense_seconds', 30 days). A last_modified window
 *     containing one is split around it before any fetch, so the descent
 *     is paid once, not on every run. The second itself is handled by the
 *     QID-range pass below, never by the time sweep.
 *   - Incremental progress survives a failed run. Bisection walks the
 *     window earliest-first and upserts each leaf before moving on, so
 *     everything up to the last completed leaf is a verified, contiguous
 *     prefix. On failure that point is saved as 'resume_floor' and the
 *     next run starts there - but never later than (this run's start -
 *     the overlap), since changes stamped within the overlap of a run may
 *     not have been indexed when that run fetched them. Each day's budget
 *     now moves the sweep forward instead of repeating it.
 *   - The new-QID fast-path runs before the sweep, so a storm in the
 *     sweep can't starve it of calls.
 *
 * Completing dense seconds by QID range (2026-11-04): splitting by time
 * stops at one second, and the first fix still kept only the first
 * qualys.kb_max_records_per_window - 1 records of such a second. The live
 * dense second 2026-11-03 06:00:01 turned out to hold at least 4,372
 * records, not 1,900. scripts/check_kb_id_date_combo.php then confirmed
 * that this endpoint applies id_min/id_max together with a last_modified
 * window, so a dense second is now finished by bisecting its QID range
 * instead - same threshold, same early-stop, same idempotent upsert -
 * until every piece is under the threshold. Nothing is accepted capped.
 *
 *   - A dense second found by the sweep is completed on the spot.
 *   - Before each incremental sweep, a dense-second pass completes any
 *     remembered second that isn't verified yet (including ones recorded
 *     by the first fix, and ones now outside the window), wherever it
 *     falls.
 *   - A second verified within the indexing-lag overlap of its own
 *     timestamp is verified once more after that overlap has passed, as
 *     the trailing re-scan does for ordinary changes. After that it is
 *     settled and never fetched again. That costs at most two QID-range
 *     passes per dense second, instead of one per run for a whole day.
 *
 * Oversized windows split by QID range, not time (2026-11-09): from
 * 2026-11-07 Qualys has run a bulk KB update twice a day, at 06:00 and
 * 18:00 UTC, each stamping ~2,000-3,300 QIDs with the same second. Each one
 * still cost ~40 of the ~88 usable daily calls, almost all of it the time
 * descent: a run's window is 6h plus the 24h overlap, and halving that down
 * to one second is ~17 levels, both halves fetched at every level, before
 * the QID-range completion even starts. Two bursts a day left nothing
 * spare. So an oversized last_modified window is now completed by QID
 * range straight away, at whatever width it is - the same QID-range
 * bisection that finishes a dense second, which this endpoint applies
 * together with any last_modified window (confirmed 2026-11-04). The cost
 * then follows how many records the window holds, not how narrow its
 * densest second is: a ~7,000-record window is a handful of QID pieces at
 * the 1,900 threshold, not a 17-level descent. Same threshold, same early
 * stop, nothing capped is ever upserted - and unlike the old 1-second
 * branch, nothing is written from a window until it is verified.
 *
 * The descent used to be how dense seconds were found. They are now found
 * from the records themselves: while the window is completed by QID range,
 * records are counted per second of qualys_last_modified, and any second
 * holding at least half the threshold is remembered as a dense second -
 * already verified, since every record in it was just fetched. The second
 * before it is remembered too: the descent's history shows each burst as a
 * pair of seconds with identical counts (2026-11-08 06:00:00 and 06:00:01,
 * both 2,040, then both 3,263), which is what Qualys's window bounds
 * including the end second would produce - a piece ending at T still holds
 * T's records. Remembering T-1 as well keeps that piece out of later runs'
 * sweeps, exactly as the descent used to by finding both. From then on the
 * existing machinery takes over: later windows step around both, and the
 * pair is re-verified once after the overlap, as one 2-second window rather
 * than two passes over the same records. If qualys_last_modified
 * ever turns out not to be the timestamp the last_modified filter uses, the
 * fallback is cost, not loss: the burst simply isn't recognised, and every
 * run whose window holds it completes that window by QID range again.
 * Backfill (published-date windows) has no QID-range route and still
 * splits by time.
 *
 * Patch date (2026-11-04): the upsert below also stores
 * patch_published_date (database/migrations/2026-11-add-patch-published-date.sql),
 * the CE+ patch clock's start date. It arrives in the same response, so it
 * costs nothing extra: each QID picks it up the next time this sync sees
 * it. scripts/backfill_patch_published_date.php can fill it sooner for the
 * QIDs actually detected on hosts.
 *
 * Suggested cron entry (every 4 hours, on the hour - written as an
 * explicit hour list rather than the usual "star-slash-4" shorthand,
 * since that exact character sequence would terminate this very
 * docblock comment early):
 *   0 0,4,8,12,16,20 * * * php /var/www/dashboard.plainsightsecurity.co.uk/scripts/sync_knowledge_base.php >> /var/log/vulndash/kb_sync.log 2>&1
 *   (adjust the schedule to taste based on your own rate limit and how
 *   quickly you want the initial backfill to finish)
 *
 * Usage:
 *   php scripts/sync_knowledge_base.php                        # normal cron run - backfill or incremental,
 *                                                                # whichever the persisted cursor says
 *   php scripts/sync_knowledge_base.php --rescan-since=2026-04-01
 *                                                                # one-off: re-walk last_modified_after
 *                                                                # 2026-04-01 through now with the safety
 *                                                                # net above, upserting (idempotently) any
 *                                                                # QID a past run may have silently
 *                                                                # dropped. Does NOT touch sync_state or
 *                                                                # the normal cursor - entirely separate
 *                                                                # from, and safe to run alongside or
 *                                                                # instead of, a normal cron run. Safe to
 *                                                                # re-run: every write is the same
 *                                                                # ON DUPLICATE KEY UPDATE upsert as
 *                                                                # everywhere else in this script, so
 *                                                                # re-scanning an already-fine window just
 *                                                                # re-confirms it rather than duplicating
 *                                                                # or corrupting anything. Pick how far
 *                                                                # back to go deliberately, not by
 *                                                                # default - this incident was only
 *                                                                # discovered by chance, so there's no
 *                                                                # reliable way to know how far back it
 *                                                                # actually goes; going back further costs
 *                                                                # more API calls but finds more.
 *   php scripts/sync_knowledge_base.php --rescan-since=2026-07-01 --rescan-until=2026-08-01
 *                                                                # same as above, but bounded to a specific
 *                                                                # window instead of running all the way to
 *                                                                # now - lets a large catch-up be done as
 *                                                                # several separate, non-overlapping chunks
 *                                                                # (e.g. one calendar month at a time,
 *                                                                # newest first) rather than one long walk.
 *                                                                # Recommended over one big --rescan-since
 *                                                                # for anything more than a few weeks back:
 *                                                                # smaller blast radius if one chunk dies
 *                                                                # partway through (see the CPU/load and
 *                                                                # crash incidents below - both hit mid-walk
 *                                                                # on a --rescan-since with no upper bound),
 *                                                                # and each chunk is small enough to often
 *                                                                # finish within a single hourly rate-limit
 *                                                                # window rather than reliably exhausting it.
 *                                                                # --rescan-until only makes sense paired
 *                                                                # with --rescan-since - it bounds the far
 *                                                                # end of that walk, nothing else.
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;
use VulnDash\Lib\Database;
use VulnDash\Scripts\QualysApiClient;

/**
 * How long a known dense second is remembered. Only a window that still
 * reaches back to it benefits - the incremental floor is at most a few
 * days back, so 30 days mainly serves a --rescan-since over the same stretch.
 */
const KB_DENSE_SECOND_RETENTION_DAYS = 30;

/**
 * New-QID fast-path.
 *
 * The steady-state incremental sweep finds changed QIDs by last_modified, but
 * can be slow to see a BRAND-NEW one: Qualys doesn't make a record queryable
 * by its last_modified filter the instant it's assigned (the same indexing lag
 * the trailing overlap absorbs for MODIFIED QIDs - see this file's docblock),
 * so a run whose window closes before a new QID becomes date-visible won't
 * return it, and only a later run's overlap will. Until then a genuinely new
 * QID - exactly the kind of freshly-published vulnerability worth surfacing
 * quickly - is missing from the local KB, and any host_detections row that
 * references it can't join to a title/CVSS/CVE list.
 *
 * Qualys assigns QIDs in increasing numeric order, though, so any genuinely
 * new QID is always numerically ABOVE every QID already stored locally. That
 * makes a single cheap id_min=(local max + 1) range call enough to pick new
 * QIDs up immediately, independently of any date field - one extra API call
 * per run, no date/indexing dependency, no walking the whole ID space.
 *
 * This is deliberately NOT a completeness guarantee and does not replace
 * scripts/reconcile_kb_by_id.php: reconcile walks the entire QID space to
 * catch a gap ANYWHERE (including below the local max - a QID with a null/odd
 * date that an old sweep skipped); this only closes the common "newly
 * published, not yet last_modified-indexed" gap at the top of the range. The
 * two are complementary - this is the cheap every-run early-capture, reconcile
 * is the exhaustive periodic backstop.
 *
 * $fetchRange is injected (rather than a client taken directly) so the DB-
 * facing logic here - anchor on the local max, upsert what comes back, count -
 * is unit-testable without a live Qualys call; the caller wires it to a
 * round-robin client with the same fallback the date sweeps use.
 *
 * $written, if given, is incremented as each record is written, so a caller
 * still knows how many were written if the fetch throws partway.
 *
 * @param callable(int, int): iterable<int, array<string, mixed>> $fetchRange
 * @return array{ran: bool, local_max: ?int, id_min: int, id_max: int, count: int, unverified: bool}
 */
function kbRunNewQidFastPath(\PDO $pdo, \PDOStatement $upsert, callable $fetchRange, int $span, int $threshold, ?int &$written = null): array
{
    $localMax = $pdo->query('SELECT MAX(qid) FROM knowledge_base')->fetchColumn();
    // Empty KB - nothing to anchor id_min on. Only reachable if this somehow
    // runs before any backfill has stored a single QID; the caller gates it on
    // backfill being complete, so this is just defensive.
    if ($localMax === null || $localMax === false) {
        return ['ran' => false, 'local_max' => null, 'id_min' => 0, 'id_max' => 0, 'count' => 0, 'unverified' => false];
    }
    $localMax = (int)$localMax;
    $idMin = $localMax + 1;
    $idMax = $localMax + max(1, $span);

    // Stream-and-upsert one row at a time (no buffering) - the same bounded-
    // memory discipline the date-window safety net uses, so an unexpectedly
    // large "new QID" burst can't materialise thousands of full rows at once.
    $count = 0;
    foreach ($fetchRange($idMin, $idMax) as $vuln) {
        $upsert->execute($vuln);
        $count++;
        if ($written !== null) {
            $written++;
        }
    }

    // Same conservative reasoning as the time-window safety net: this endpoint
    // truncates silently, with no pagination signal, so a response at/above the
    // threshold can't be trusted as complete. Unlike a time window this can't
    // be bisected cheaply here, so rather than guess we flag it and lean on
    // reconcile_kb_by_id.php (which the caller's message names) as the backstop.
    $unverified = $count >= $threshold;

    return ['ran' => true, 'local_max' => $localMax, 'id_min' => $idMin, 'id_max' => $idMax, 'count' => $count, 'unverified' => $unverified];
}

$options = getopt('', ['rescan-since::', 'rescan-until::']);
$rescanSince = isset($options['rescan-since']) && trim((string)$options['rescan-since']) !== ''
    ? new DateTimeImmutable((string)$options['rescan-since'])
    : null;
$rescanUntil = isset($options['rescan-until']) && trim((string)$options['rescan-until']) !== ''
    ? new DateTimeImmutable((string)$options['rescan-until'])
    : null;

if ($rescanUntil !== null && $rescanSince === null) {
    fwrite(STDERR, "--rescan-until only makes sense together with --rescan-since (it bounds the far end of that walk - on its own there's nothing to bound).\n");
    exit(1);
}
if ($rescanSince !== null && $rescanUntil !== null && $rescanUntil <= $rescanSince) {
    fwrite(STDERR, "--rescan-until ({$rescanUntil->format('Y-m-d H:i:s')}) must be after --rescan-since ({$rescanSince->format('Y-m-d H:i:s')}).\n");
    exit(1);
}

// Guard against two invocations overlapping (e.g. cron firing again while
// a previous run is still going) - each wasted overlapping call eats into
// an already-limited budget for no benefit, and Qualys's concurrency limit
// can be as low as 2 simultaneous calls on some subscriptions. Shared with
// --rescan-since too - a rescan and a normal cron run hitting the API at
// the same time is exactly the kind of overlap this exists to prevent.
$lockPath = sys_get_temp_dir() . '/vulndash_kb_sync.lock';
$lockHandle = fopen($lockPath, 'c');
if ($lockHandle === false) {
    // A real problem (e.g. the file exists but is owned by a different user
    // than whoever's running this - root vs www-data is the common case) -
    // NOT the same thing as another instance genuinely holding the lock, so
    // this must not be treated the same way as that (silently doing
    // nothing forever while looking like normal, expected behaviour).
    fwrite(STDERR, "Could not open lock file {$lockPath} - check its ownership/permissions (this is a real error, not a normal overlapping-run skip).\n");
    exit(1);
}
// Whichever user creates this file first "owns" it by default, which then
// blocks every other user from ever acquiring the lock - make it usable
// interchangeably regardless of whether it's touched by root (manual runs)
// or www-data (cron) from here on.
@chmod($lockPath, 0666);
if (!flock($lockHandle, LOCK_EX | LOCK_NB)) {
    fwrite(STDOUT, "Another knowledge base sync is already running - exiting.\n");
    exit(0);
}

$pdo = Database::getConnection();

// --rescan-since is a manual, one-off diagnostic/repair pass, not a normal
// cron run, but it deliberately still logs under the same 'knowledge_base'
// sync_type rather than a new one - sync_log.sync_type is a fixed ENUM
// (see database_schema.sql), and adding a value would mean a migration.
// Reusing 'knowledge_base' means a rescan run shows up in the same history
// SyncStatusRepository reads for the dashboard's admin sync panel, so a
// rescan that's actively running or that fails could transiently show as
// the routine cron job's own status until the next real cron run overwrites
// it. Acceptable for now since a rescan is something run deliberately and
// watched, not a background job - flagging this as a real tradeoff worth a
// second look if that proves confusing in practice, not a decision to
// treat as settled.
$logStmt = $pdo->prepare('INSERT INTO sync_log (sync_type, started_at, status) VALUES (:type, :started, :status)');
$logStmt->execute([
    'type'    => 'knowledge_base',
    'started' => date('Y-m-d H:i:s'),
    'status'  => 'running',
]);
$logId = (int)$pdo->lastInsertId();

$client = null;
$clientPool = [];

// Declared out here so the catch block can see how far an incremental
// sweep got before it failed - see the 2026-11 section of this file's
// docblock. $verifiedThrough is the end of the contiguous prefix of the
// window that has been fully fetched and upserted; $incrementalResume is
// set only once an incremental sweep is about to start.
$verifiedThrough = null;
$incrementalResume = null;

// Every record written to knowledge_base this run, counted as it's written.
// $recordsProcessed below is only totalled once each step returns, so a run
// that fails partway would otherwise log 0 despite having written thousands
// (as happened on 2026-11-05 06:10). This is what a failed run records.
$recordsWritten = 0;

$exitCode = 0;

try {
    // Round-robins KnowledgeBase calls across API versions - added 2026-07
    // after directly confirming (scripts/check_kb_api_versions.php) that
    // this subscription's KB endpoint still works on /api/2.0/ and
    // /api/3.0/ too, and that each version keeps its own independent
    // hourly rate-limit counter (confirmed: each showed 299/300
    // immediately after a single call on that version alone). Qualys's
    // documented default is 300 calls/hour - PER version - so cycling
    // through three versions raises the effective ceiling before a rescan
    // has to stall and wait out a reset from ~300/hour to ~900/hour,
    // without changing anything about how any single window is fetched or
    // verified.
    //
    // Configurable via qualys.kb_api_versions (defaults to all three
    // below) specifically so a version can be dropped without a code
    // change if it ever stops working - this subscription's own history
    // is a real example of that happening (Host List Detection got an EOS
    // warning that retired its access to /api/2.0/ entirely - see the note
    // in src/config/config.php). If that happens to KB too, the round
    // robin below already falls back to the primary (4.0) client whenever
    // a call on another version fails, so a single version going away
    // degrades this to "back to normal speed", not "sync breaks".
    $apiVersions = Config::get('qualys.kb_api_versions') ?? ['2.0', '3.0', '4.0'];
    $primaryVersion = (string)(Config::get('qualys.api_version') ?? '4.0');

    foreach ($apiVersions as $version) {
        $clientPool[$version] = new QualysApiClient(
            (string)Config::get('qualys.api_base_url'),
            (string)Config::get('qualys.username'),
            (string)Config::get('qualys.password'),
            (string)$version
        );
    }
    // The one version everything falls back to on failure, and the one
    // used for anything in this file that isn't a round-robin-eligible KB
    // window fetch (there isn't anything else right now, but keeping a
    // single canonical $client avoids every other part of this script
    // needing to know about the pool).
    $client = $clientPool[$primaryVersion] ?? reset($clientPool);

    $rrIndex = 0;
    /**
     * Picks the next client in the pool, round-robin, cycling through
     * every configured API version in turn.
     */
    $pickClient = function () use (&$rrIndex, $clientPool): QualysApiClient {
        $versions = array_keys($clientPool);
        $picked = $clientPool[$versions[$rrIndex % count($versions)]];
        $rrIndex++;
        return $picked;
    };

    /**
     * Builds a $fetchWindow closure for syncWindowWithSafetyNet(), wired
     * to round-robin across the client pool with a same-window retry on
     * the primary client if the picked version's call fails - so one
     * version having a bad day (or being retired outright) degrades to
     * "this window used the primary client instead", not a crashed run.
     *
     * @param bool $usePublishedDates true for backfill (published_after/
     *        before), false for incremental/rescan (last_modified_after/
     *        before) - the only thing that differs between call sites.
     *
     * The returned closure takes an optional QID range, used only with
     * last_modified windows to complete a dense second - see the 2026-11
     * section of this file's docblock.
     */
    $makeFetchWindow = function (bool $usePublishedDates) use ($pickClient, $client): callable {
        return function (\DateTimeImmutable $a, \DateTimeImmutable $b, ?int $idMin = null, ?int $idMax = null) use ($pickClient, $client, $usePublishedDates): iterable {
            $picked = $pickClient();
            $source = $usePublishedDates
                ? $picked->fetchKnowledgeBaseChunk(null, $a, $b)
                : $picked->fetchKnowledgeBaseChunk($a, null, null, $b, $idMin, $idMax);

            // fetchKnowledgeBaseChunk() is itself a generator - it doesn't
            // make the actual HTTP call (or validate the response) until
            // the FIRST advance, so a try/catch around just the call above
            // would never catch anything; it has to wrap the iteration
            // itself, which is why this whole closure is a generator too
            // (it yields onward as it goes, rather than buffering).
            //
            // $yieldedAny guards against a rarer failure mode: if this
            // version's connection dropped PARTWAY through (after some
            // real rows already came through), falling back would re-walk
            // the same window from the start and risk yielding some rows
            // twice. That's only safe to auto-recover when NOTHING has
            // been yielded yet - which is exactly what happens for the
            // failure this exists to handle (an EOS/retired-version error
            // surfaces immediately, before any row is ever parsed) - so a
            // partial-then-failed stream is treated as a real failure to
            // surface, not something to paper over.
            $yieldedAny = false;
            try {
                foreach ($source as $vuln) {
                    $yieldedAny = true;
                    yield $vuln;
                }
                return;
            } catch (\Throwable $e) {
                if ($picked === $client || $yieldedAny) {
                    throw $e;
                }
                fwrite(STDOUT, "  (a call on this window's assigned API version failed before returning anything - {$e->getMessage()} - retrying this same window on the primary version instead)\n");
            }

            $fallbackSource = $usePublishedDates
                ? $client->fetchKnowledgeBaseChunk(null, $a, $b)
                : $client->fetchKnowledgeBaseChunk($a, null, null, $b, $idMin, $idMax);
            yield from $fallbackSource;
        };
    };

    // Must list every key QualysApiClient::parseKnowledgeBaseFile() yields -
    // see its docblock (patch_published_date added 2026-11-04).
    $upsert = $pdo->prepare('
        INSERT INTO knowledge_base
            (qid, title, severity_level, category, cvss_base, cvss_vector, cvss3_base, cvss3_vector,
             cve_ids, vendor_reference, patchable, pci_flag, diagnosis, consequence, solution,
             published_datetime, patch_published_date, qualys_last_modified)
        VALUES
            (:qid, :title, :severity_level, :category, :cvss_base, :cvss_vector, :cvss3_base, :cvss3_vector,
             :cve_ids, :vendor_reference, :patchable, :pci_flag, :diagnosis, :consequence, :solution,
             :published_datetime, :patch_published_date, :qualys_last_modified)
        ON DUPLICATE KEY UPDATE
            title = VALUES(title), severity_level = VALUES(severity_level), category = VALUES(category),
            cvss_base = VALUES(cvss_base), cvss_vector = VALUES(cvss_vector),
            cvss3_base = VALUES(cvss3_base), cvss3_vector = VALUES(cvss3_vector),
            cve_ids = VALUES(cve_ids), vendor_reference = VALUES(vendor_reference),
            patchable = VALUES(patchable), pci_flag = VALUES(pci_flag),
            diagnosis = VALUES(diagnosis), consequence = VALUES(consequence), solution = VALUES(solution),
            published_datetime = VALUES(published_datetime), patch_published_date = VALUES(patch_published_date),
            qualys_last_modified = VALUES(qualys_last_modified)
    ');

    $maxRecordsPerWindow = (int)(Config::get('qualys.kb_max_records_per_window') ?? 100);
    $callDelayMs = (int)(Config::get('qualys.kb_call_delay_ms') ?? 300);

    /**
     * Fetches one time window via $fetchWindow($after, $before), and
     * doesn't trust the response as complete if it returns
     * $maxRecordsPerWindow records or more - see this file's own docblock
     * above for the incident this defends against and why that threshold
     * is an educated-guess safety margin, not a confirmed cap. A
     * suspiciously-full response is never upserted as-is: a last_modified
     * window is completed by QID range instead (see the 2026-11-09 docblock
     * section), and a published-date window is split in half by time with
     * each half re-verified the same way, recursively. Only once a piece's
     * count is comfortably under the threshold are its rows actually
     * written.
     *
     * Deliberately stops reading a window's response the moment it's
     * confirmed oversized, rather than finishing the full iteration first -
     * see the 2026-07-13 incident this defends against: a --rescan-since
     * run hit a window with 89,277 real matching records, and the OLD code
     * fully buffered every one of them (each a complete KB row - title,
     * diagnosis, consequence, solution text and all) into a PHP array
     * before ever checking the count, for a window it was always going to
     * reject and re-split anyway. That's what drove the box's load average
     * to 7-11 - not the recursion itself, which is cheap, but repeatedly
     * materializing tens of thousands of full rows per rejected call. Now,
     * the moment more than $maxRecordsPerWindow rows have been seen, the
     * loop breaks immediately - XMLReader stops parsing the rest of the
     * response, fetchKnowledgeBaseChunk()'s own finally block cleans up
     * the temp file right away, and this function never learns or needs
     * the window's true total. Peak memory and parse cost per call are
     * now bounded by $maxRecordsPerWindow regardless of how large the
     * window's real matching set is.
     *
     * A deliberate pause after every physical call (qualys.kb_call_delay_ms,
     * default 300ms) - also added after the same incident - keeps a long
     * walk (a historical --rescan-since especially, which can be hundreds
     * of calls back to back) from hammering the box at full speed for
     * hours on end, and reduces how often this collides with your other
     * cron jobs' own Qualys calls against the 2-concurrent-call limit
     * (QualysApiClient's existing 409 retry/backoff still handles an
     * occasional collision safely either way - this just makes one less
     * likely).
     *
     * A published-date window that still hits the threshold at 1 second
     * wide can't be split any further by time - Qualys's own timestamp
     * granularity is 1 second, so this happens when a single backend
     * operation (most likely a bulk update) touches more records than the
     * threshold and stamps all of them with the same "as of" timestamp.
     * Rather than treating this as fatal and aborting the entire
     * (potentially many-day) walk over one bad second, what was retrieved
     * is upserted anyway, the exact timestamp is flagged loudly and
     * tracked, and the walk continues - see $unverifiedWindows and the
     * summary printed at the end of this run for anything that hit this
     * case.
     *
     * @param callable(\DateTimeImmutable, \DateTimeImmutable): iterable<int, array<string, mixed>> $fetchWindow
     * @return int total records upserted across this window and any
     *         sub-windows it had to be split into
     */
    // Populated by $syncWindowWithSafetyNet below whenever a 1-second
    // window still can't be trusted as complete - see that function for
    // why this is tracked and reported rather than treated as fatal.
    $unverifiedWindows = [];
    // Known dense seconds this run stepped around instead of re-fetching.
    $skippedDenseSeconds = [];

    // Dense seconds (1-second last_modified windows that still held the
    // threshold or more) found by earlier runs, as unix time => details.
    // Saved the moment one is found, not at the end of the run, because the
    // runs that find them are exactly the ones likely to die at the call
    // reserve before reaching the end - see the 2026-11 docblock section.
    $denseStateKey = 'knowledge_base_dense_seconds';
    $denseStmt = $pdo->prepare('SELECT state_json FROM sync_state WHERE sync_type = :type');
    $denseStmt->execute(['type' => $denseStateKey]);
    $denseState = json_decode((string)$denseStmt->fetchColumn(), true);
    $knownDenseSeconds = [];
    $denseRetainFrom = time() - KB_DENSE_SECOND_RETENTION_DAYS * 86400;
    foreach ((is_array($denseState) && is_array($denseState['seconds'] ?? null) ? $denseState['seconds'] : []) as $utc => $info) {
        $ts = strtotime((string)$utc);
        if ($ts !== false && $ts >= $denseRetainFrom && is_array($info)) {
            $knownDenseSeconds[$ts] = $info;
        }
    }
    ksort($knownDenseSeconds);

    $saveDenseSeconds = function () use ($pdo, $denseStateKey, &$knownDenseSeconds): void {
        $seconds = [];
        foreach ($knownDenseSeconds as $ts => $info) {
            $seconds[gmdate('Y-m-d\TH:i:s\Z', $ts)] = $info;
        }
        $pdo->prepare('
            INSERT INTO sync_state (sync_type, state_json) VALUES (:type, :state)
            ON DUPLICATE KEY UPDATE state_json = VALUES(state_json)
        ')->execute(['type' => $denseStateKey, 'state' => json_encode(['seconds' => $seconds])]);
    };

    // Dense seconds completed this run, for the sync_log note.
    $completedDenseSeconds = [];

    // Top of a dense second's QID range: above every QID held locally, the
    // configured id-space ceiling, and a new-QID span beyond both, so a
    // brand-new QID stamped in that second still falls inside. An empty
    // stretch at the top costs one cheap call at most.
    $denseIdCeiling = null;
    $getDenseIdCeiling = function () use ($pdo, &$denseIdCeiling): int {
        if ($denseIdCeiling === null) {
            $localMax = (int)($pdo->query('SELECT MAX(qid) FROM knowledge_base')->fetchColumn() ?: 0);
            $hardCeiling = (int)(Config::get('qualys.kb_id_range_hard_ceiling') ?? 0);
            $span = (int)(Config::get('qualys.kb_new_qid_fastpath_span') ?? 1000000);
            $denseIdCeiling = max($localMax, $hardCeiling) + max(1, $span);
        }
        return $denseIdCeiling;
    };

    /**
     * One last_modified window - a dense second, or (2026-11-09) any
     * oversized window - narrowed to QIDs [$idMin, $idMax]: the QID-range
     * counterpart of $syncWindowWithSafetyNet's time bisection, with the
     * same threshold and early stop. Confirmed usable 2026-11-04 (see the
     * docblock). Both halves of a split include the midpoint QID: id_min is
     * confirmed inclusive, id_max isn't, and fetching one QID twice is
     * harmless given the idempotent upsert.
     *
     * $secondCounts, if given, collects how many verified records each
     * second of qualys_last_modified held (UTC unix time => count) - how an
     * oversized window's dense seconds are found now that no time descent
     * reaches them. A QID fetched twice at a midpoint is counted twice,
     * which can only over-count a second by one, never hide it.
     *
     * @param array<int, int>|null $secondCounts
     */
    $syncDenseIdRange = function (
        callable $fetchWindow,
        \DateTimeImmutable $after,
        \DateTimeImmutable $before,
        int $idMin,
        int $idMax,
        int $depth,
        ?array &$secondCounts = null
    ) use (&$syncDenseIdRange, $upsert, $maxRecordsPerWindow, $callDelayMs, &$recordsWritten): int {
        $indent = str_repeat('  ', $depth);
        fwrite(STDOUT, "{$indent}QIDs {$idMin}-{$idMax}\n");

        $rows = [];
        $count = 0;
        $exceeded = false;
        foreach ($fetchWindow($after, $before, $idMin, $idMax) as $vuln) {
            $count++;
            if ($count >= $maxRecordsPerWindow) {
                $exceeded = true;
                break;
            }
            $rows[] = $vuln;
        }

        if ($callDelayMs > 0) {
            usleep($callDelayMs * 1000);
        }

        if ($exceeded) {
            fwrite(STDOUT, "{$indent}  -> at least {$maxRecordsPerWindow} record(s) - splitting the QID range\n");
            if ($idMax - $idMin <= 1) {
                // Two QIDs can't hold the threshold unless it is set absurdly
                // low - fail loudly rather than accept a capped response.
                throw new \RuntimeException("QIDs {$idMin}-{$idMax} in the window from {$after->format('Y-m-d H:i:s')} still returned {$maxRecordsPerWindow}+ records, which two QIDs cannot - check qualys.kb_max_records_per_window.");
            }
            $midpoint = intdiv($idMin + $idMax, 2);
            $left = $syncDenseIdRange($fetchWindow, $after, $before, $idMin, $midpoint, $depth + 1, $secondCounts);
            $right = $syncDenseIdRange($fetchWindow, $after, $before, $midpoint, $idMax, $depth + 1, $secondCounts);
            return $left + $right;
        }

        fwrite(STDOUT, "{$indent}  -> {$count} record(s)\n");
        foreach ($rows as $vuln) {
            $upsert->execute($vuln);
            $recordsWritten++;
            if ($secondCounts !== null && !empty($vuln['qualys_last_modified'])) {
                // Stored UTC by QualysApiClient::toMysqlDatetime().
                $ts = strtotime((string)$vuln['qualys_last_modified'] . ' UTC');
                if ($ts !== false) {
                    $secondCounts[$ts] = ($secondCounts[$ts] ?? 0) + 1;
                }
            }
        }
        return $count;
    };

    /*
     * Planned QID-range pieces (2026-11-12). Halving [1, ceiling] blind
     * spent most of a run's calls on responses that were only discarded:
     * Qualys's changed QIDs sit in a narrow band, so a 5,000-record window
     * went 4-5 halvings deep - each one a full download (hundreds of MB on
     * the 2026-11-11/12 runs) thrown away at the threshold - before any
     * piece was small enough to keep. Roughly a third of KB calls.
     *
     * But because of the trailing overlap, most of each window was already
     * fetched by earlier runs: the local KB knows which QIDs carry a
     * qualys_last_modified inside it. So the QID range is cut up front, from
     * those QIDs, into pieces each holding $plannedPieceTarget of them. The
     * target is well under the threshold (qualys.kb_planned_piece_fill,
     * default 0.45) to leave room for what the local KB can't see yet -
     * changes made since the last run, about a third of a 36-hour window.
     *
     * The guarantee is unchanged: every piece goes through
     * $syncDenseIdRange, which still halves any piece that comes back at the
     * threshold, and the pieces cover [1, ceiling] with shared boundary QIDs
     * exactly as a halving does. A bad estimate costs calls, never records.
     * qualys.kb_planned_piece_fill = 0 turns planning off (one piece, the
     * old behaviour).
     */
    $plannedPieceFill = (float)(Config::get('qualys.kb_planned_piece_fill') ?? 0.45);
    $plannedPieceFill = $plannedPieceFill > 0 ? min(1.0, $plannedPieceFill) : 0.0;
    $plannedPieceTarget = $plannedPieceFill > 0 ? max(1, (int)floor($maxRecordsPerWindow * $plannedPieceFill)) : 0;
    $localWindowQids = $pdo->prepare(
        'SELECT qid FROM knowledge_base
         WHERE qualys_last_modified >= :after AND qualys_last_modified < :before
         ORDER BY qid'
    );

    /**
     * @return array{estimate: int, pieces: array<int, array{0: int, 1: int}>}
     *         estimate is how many local QIDs fall in the window
     */
    $planIdPieces = function (\DateTimeImmutable $after, \DateTimeImmutable $before) use ($localWindowQids, $plannedPieceTarget, $getDenseIdCeiling): array {
        $ceiling = $getDenseIdCeiling();
        if ($plannedPieceTarget <= 0) {
            return ['estimate' => 0, 'pieces' => [[1, $ceiling]]];
        }
        $utc = new \DateTimeZone('UTC');
        $localWindowQids->execute([
            'after'  => $after->setTimezone($utc)->format('Y-m-d H:i:s'),
            'before' => $before->setTimezone($utc)->format('Y-m-d H:i:s'),
        ]);
        $qids = array_map('intval', $localWindowQids->fetchAll(\PDO::FETCH_COLUMN));

        $pieces = [];
        $lo = 1;
        foreach ($qids as $i => $qid) {
            // Cut before the QID that would start the next piece.
            if ($i > 0 && $i % $plannedPieceTarget === 0 && $qid > $lo) {
                $pieces[] = [$lo, $qid];
                $lo = $qid;
            }
        }
        $pieces[] = [$lo, max($lo + 1, $ceiling)];
        return ['estimate' => count($qids), 'pieces' => $pieces];
    };

    /**
     * Fetches a last_modified window across its whole QID range in planned
     * pieces (see above), each through $syncDenseIdRange.
     *
     * @param array<int, int>|null $secondCounts
     */
    $syncPlannedIdRange = function (
        callable $fetchWindow,
        \DateTimeImmutable $after,
        \DateTimeImmutable $before,
        int $depth,
        ?array &$secondCounts = null,
        ?array $plan = null
    ) use ($planIdPieces, $syncDenseIdRange): int {
        $plan = $plan ?? $planIdPieces($after, $before);
        if (count($plan['pieces']) > 1) {
            fwrite(STDOUT, str_repeat('  ', $depth) . "planned " . count($plan['pieces']) . " QID-range piece(s) from {$plan['estimate']} QID(s) the local KB already holds in this window\n");
        }
        $total = 0;
        foreach ($plan['pieces'] as [$lo, $hi]) {
            $total += $syncDenseIdRange($fetchWindow, $after, $before, $lo, $hi, $depth, $secondCounts);
        }
        return $total;
    };

    /**
     * Completes one dense second across its whole QID range and records it
     * as verified. verified_at is when fetching began, since that is what
     * the indexing-lag rule (see the dense-second pass below) compares
     * against. Throws on failure, leaving the second unverified for the
     * next run's pass.
     *
     * With $withLeadIn, the window starts one second earlier and the
     * lead-in second $t - 1 is marked verified along with $t.
     */
    $completeDenseSecond = function (int $t, int $depth, bool $withLeadIn = false) use ($makeFetchWindow, $syncPlannedIdRange, &$knownDenseSeconds, $saveDenseSeconds, &$completedDenseSeconds): int {
        $second = (new \DateTimeImmutable('@' . $t))->setTimezone(new \DateTimeZone('UTC'));
        $after = $withLeadIn ? $second->modify('-1 second') : $second;
        $before = $second->modify('+1 second');
        $startedAt = gmdate('Y-m-d\TH:i:s\Z');
        $indent = str_repeat('  ', $depth);
        fwrite(STDOUT, "{$indent}Completing dense second {$second->format('Y-m-d\TH:i:s\Z')}" . ($withLeadIn ? ' with the second before it' : '') . " by QID range:\n");

        $count = $syncPlannedIdRange($makeFetchWindow(false), $after, $before, $depth + 1);

        foreach ($withLeadIn ? [$t - 1, $t] : [$t] as $marked) {
            $info = $knownDenseSeconds[$marked] ?? ['found_at' => $startedAt];
            $info['verified_at'] = $startedAt;
            $info['verified_records'] = $count;
            $knownDenseSeconds[$marked] = $info;
        }
        $saveDenseSeconds();
        $completedDenseSeconds[] = $second->format('Y-m-d\TH:i:s\Z') . ($withLeadIn ? ' with the second before it' : '') . " ({$count} records)";
        fwrite(STDOUT, "{$indent}  dense second complete: {$count} record(s) across its QID range.\n");
        return $count;
    };

    /**
     * Remembers, as already-verified dense seconds, every second an
     * oversized window's QID-range completion found holding at least half
     * the threshold - plus the second before each, for the end-bound reason
     * in the 2026-11-09 docblock section. Both were fetched in full just
     * now, so verified_at is when that window's fetching began; the
     * dense-second pass then re-verifies each once after the overlap, like
     * any other dense second. Saved straight away, for the same reason
     * $knownDenseSeconds always is.
     *
     * @param array<int, int> $secondCounts
     * @return int how many seconds were newly remembered
     */
    $rememberDenseFromCounts = function (array $secondCounts, string $startedAt, int $depth) use ($maxRecordsPerWindow, &$knownDenseSeconds, $saveDenseSeconds, &$completedDenseSeconds): int {
        $minRecords = max(1, intdiv($maxRecordsPerWindow, 2));
        $indent = str_repeat('  ', $depth);
        $remembered = 0;
        foreach ($secondCounts as $ts => $n) {
            if ($n < $minRecords) {
                continue;
            }
            foreach ([$ts - 1 => true, $ts => false] as $t => $isLeadIn) {
                $info = $knownDenseSeconds[$t] ?? ['found_at' => $startedAt];
                $info['verified_at'] = $startedAt;
                $info['verified_records'] = $isLeadIn ? ($secondCounts[$t] ?? 0) + $n : $n;
                if ($isLeadIn) {
                    $info['lead_in_to'] = gmdate('Y-m-d\TH:i:s\Z', $ts);
                }
                if (!isset($knownDenseSeconds[$t])) {
                    $remembered++;
                }
                $knownDenseSeconds[$t] = $info;
            }
            fwrite(STDOUT, "{$indent}dense second found by QID range: " . gmdate('Y-m-d\TH:i:s\Z', $ts) . " ({$n} records) - remembered with the second before it, both already verified.\n");
            $completedDenseSeconds[] = gmdate('Y-m-d\TH:i:s\Z', $ts) . " ({$n} records, found by QID range)";
        }
        if ($remembered > 0) {
            ksort($knownDenseSeconds);
            $saveDenseSeconds();
        }
        if (max($secondCounts ?: [0]) < $minRecords) {
            // Nothing to step around next time, so a later run whose window
            // still holds these records completes it by QID range again.
            // Expected for churn spread over many seconds; if a single
            // burst was expected here, qualys_last_modified may not be the
            // timestamp Qualys's last_modified filter uses.
            fwrite(STDOUT, "{$indent}no single second held {$minRecords}+ records, so no dense second was remembered - the next run whose window still holds these records will complete it by QID range again.\n");
        }
        return $remembered;
    };

    /**
     * $skipKnownDense is true only for last_modified windows (incremental
     * and --rescan-since). Dense seconds are last_modified timestamps, so
     * they mean nothing to the backfill's published-date windows - and it
     * is also what routes an oversized window to QID-range completion
     * rather than time bisection (2026-11-09).
     *
     * A window containing a known dense second [T, T+1] is split into
     * [after, T] and [T+1, before] before anything is fetched. Whether
     * Qualys treats each bound as inclusive or exclusive has never been
     * confirmed; if a neighbouring piece still includes the dense records,
     * it is simply completed by QID range, and the second before the dense
     * one is remembered alongside it (see $rememberDenseFromCounts), so
     * later runs stop paying for it either way.
     */
    $syncWindowWithSafetyNet = function (
        callable $fetchWindow,
        \DateTimeImmutable $after,
        \DateTimeImmutable $before,
        int $depth = 0,
        bool $skipKnownDense = false
    ) use (&$syncWindowWithSafetyNet, $upsert, $maxRecordsPerWindow, $callDelayMs, &$unverifiedWindows, &$skippedDenseSeconds, &$knownDenseSeconds, $planIdPieces, $syncPlannedIdRange, $plannedPieceTarget, $rememberDenseFromCounts, &$verifiedThrough, &$recordsWritten): int {
        $indent = str_repeat('  ', $depth);
        fwrite(STDOUT, "{$indent}Window: {$after->format('Y-m-d H:i:s')} to {$before->format('Y-m-d H:i:s')}\n");

        if ($skipKnownDense && $knownDenseSeconds !== []) {
            $afterTs = $after->getTimestamp();
            $beforeTs = $before->getTimestamp();
            $inside = array_values(array_filter(
                array_keys($knownDenseSeconds),
                static fn(int $t): bool => $t >= $afterTs && $t + 1 <= $beforeTs
            ));
            if ($inside !== []) {
                fwrite(STDOUT, "{$indent}  contains " . count($inside) . " known dense second(s) - splitting around them rather than fetching them again.\n");
                $total = 0;
                $cursorTs = $afterTs;
                foreach ($inside as $t) {
                    if ($t > $cursorTs) {
                        $total += $syncWindowWithSafetyNet($fetchWindow, $after->setTimestamp($cursorTs), $after->setTimestamp($t), $depth + 1, true);
                    }
                    $info = $knownDenseSeconds[$t];
                    $denseUtc = gmdate('Y-m-d\TH:i:s\Z', $t);
                    if (isset($info['verified_at'])) {
                        fwrite(STDOUT, "{$indent}  Window: {$after->setTimestamp($t)->format('Y-m-d H:i:s')} (+1s) - known dense second, completed by QID range at {$info['verified_at']} (" . ($info['verified_records'] ?? '?') . " records); not part of the time sweep.\n");
                    } else {
                        // Only reachable in a --rescan-since, or if this
                        // run's dense-second pass didn't get to it.
                        fwrite(STDOUT, "{$indent}  Window: {$after->setTimestamp($t)->format('Y-m-d H:i:s')} (+1s) - known dense second, not completed yet; the next incremental run's dense-second pass will do it.\n");
                        $skippedDenseSeconds[] = $denseUtc;
                    }
                    $cursorTs = $t + 1;
                    $verifiedThrough = $after->setTimestamp($cursorTs);
                }
                if ($beforeTs > $cursorTs) {
                    $total += $syncWindowWithSafetyNet($fetchWindow, $after->setTimestamp($cursorTs), $before, $depth + 1, true);
                }
                return $total;
            }
        }

        // A last_modified window the local KB already knows is too big for
        // one response skips the whole-window probe: it could only be
        // discarded at the threshold. Straight to planned QID pieces (see
        // $planIdPieces) - the same completion an oversized probe leads to
        // below, one wasted download sooner.
        $plan = null;
        if ($skipKnownDense && $plannedPieceTarget > 0) {
            $plan = $planIdPieces($after, $before);
            if ($plan['estimate'] > $plannedPieceTarget) {
                fwrite(STDOUT, "{$indent}  local KB already holds {$plan['estimate']} QID(s) modified in this window - completing it by QID range without the whole-window probe.\n");
                $startedAt = gmdate('Y-m-d\TH:i:s\Z');
                $secondCounts = [];
                $total = $syncPlannedIdRange($fetchWindow, $after, $before, $depth + 1, $secondCounts, $plan);
                fwrite(STDOUT, "{$indent}  window complete: {$total} record(s) across its QID range.\n");
                $rememberDenseFromCounts($secondCounts, $startedAt, $depth + 1);
                $verifiedThrough = $before;
                return $total;
            }
        }

        $rows = [];
        $count = 0;
        $exceeded = false;
        foreach ($fetchWindow($after, $before) as $vuln) {
            $count++;
            if ($count >= $maxRecordsPerWindow) {
                // Confirmed oversized - stop here. This window is being
                // split and re-verified regardless of its true total, so
                // there's no value in continuing to parse (or holding in
                // memory) however many thousands more rows the rest of
                // the response contains - see this function's docblock.
                $exceeded = true;
                break;
            }
            $rows[] = $vuln;
        }

        if ($callDelayMs > 0) {
            usleep($callDelayMs * 1000);
        }

        $windowSeconds = $before->getTimestamp() - $after->getTimestamp();
        if ($exceeded) {
            fwrite(STDOUT, "{$indent}  -> at least {$maxRecordsPerWindow} record(s) (stopped counting early - this window is being split regardless of its true total)\n");
            if ($skipKnownDense) {
                // A last_modified window: complete it by QID range at its
                // full width instead of descending by time - see the
                // 2026-11-09 docblock section. Nothing from the capped
                // response above is used; every record comes from a
                // verified QID piece. Throws on failure, leaving
                // $verifiedThrough at the start of this window.
                fwrite(STDOUT, "{$indent}  completing this window by QID range rather than halving it by time.\n");
                $startedAt = gmdate('Y-m-d\TH:i:s\Z');
                $secondCounts = [];
                $total = $syncPlannedIdRange($fetchWindow, $after, $before, $depth + 1, $secondCounts, $plan);
                fwrite(STDOUT, "{$indent}  window complete: {$total} record(s) across its QID range.\n");
                $rememberDenseFromCounts($secondCounts, $startedAt, $depth + 1);
                $verifiedThrough = $before;
                return $total;
            }
            if ($windowSeconds <= 1) {
                // Genuinely unsplittable by time alone - Qualys's own
                // timestamp granularity is 1 second, so if a single
                // backend operation (a bulk update, most likely - it
                // would stamp every record it touches with the same "as
                // of" timestamp) touched more records than the threshold
                // within that same second, there is no finer time window
                // left to isolate it with. This is a different problem
                // from the "silently truncated" case this whole safety
                // net defends against - it's a real limit of bisecting by
                // time specifically, not evidence of truncation.
                //
                // Only published-date windows (backfill) get here now -
                // last_modified ones are completed by QID range above - and
                // they have no QID-range completion, so the capped subset
                // is all there is. Aborting the entire (potentially
                // many-day) walk over one bad second is the wrong trade-off
                // - what WAS retrieved (a real, if possibly incomplete,
                // subset) is upserted, this exact timestamp is flagged
                // loudly and tracked for the summary at the end of this
                // run, and the walk continues rather than losing everything
                // else it would otherwise recover. This is a real,
                // disclosed gap, not a silent one - see the summary printed
                // at the end and follow up on each timestamp listed there
                // specifically (e.g. via scripts/diagnose_kb.php against
                // candidate QIDs, or with Qualys support directly).
                foreach ($rows as $vuln) {
                    $upsert->execute($vuln);
                    $recordsWritten++;
                }
                $unverifiedWindows[] = $after->format('Y-m-d H:i:s');
                fwrite(STDOUT, "{$indent}  *** UNVERIFIED COMPLETENESS: {$maxRecordsPerWindow}+ records in this single second, cannot rule out more existing beyond the " . count($rows) . " retrieved here. Upserting what was retrieved and continuing rather than aborting the rest of this run - see summary at the end. ***\n");
                $verifiedThrough = $before;
                return count($rows);
            }
            $midpoint = $after->modify('+' . intdiv($windowSeconds, 2) . ' seconds');
            fwrite(STDOUT, "{$indent}  not trusting this as complete, splitting and re-verifying both halves.\n");
            $left = $syncWindowWithSafetyNet($fetchWindow, $after, $midpoint, $depth + 1, $skipKnownDense);
            $right = $syncWindowWithSafetyNet($fetchWindow, $midpoint, $before, $depth + 1, $skipKnownDense);
            return $left + $right;
        }

        fwrite(STDOUT, "{$indent}  -> {$count} record(s)\n");
        foreach ($rows as $vuln) {
            $upsert->execute($vuln);
            $recordsWritten++;
        }
        $verifiedThrough = $before;
        return $count;
    };

    $recordsProcessed = 0;
    $now = new DateTimeImmutable('now');

    // Runtime banner (added 2026-07). Every run - including a routine cron
    // run that ends up processing 0 records - must leave an unambiguous
    // fingerprint in the log saying which MODE it ran in, the EXACT window
    // it queried, and the config thresholds driving the safety net. Without
    // this, a "0 records" run is indistinguishable between three completely
    // different situations that each need a completely different response:
    //   - genuinely nothing changed in the window (correct, no action);
    //   - still in BACKFILL, walking a published-date stretch by calendar
    //     date, so recent last_modified churn of OLD QIDs is simply not
    //     being queried yet (expected until backfill finishes);
    //   - in INCREMENTAL with a cursor at/after 'now', so the last_modified
    //     window is empty or inverted and every run trivially returns 0
    //     (a real fault - the cursor is the thing to fix, not the sync).
    // The window is printed in UTC specifically - i.e. exactly what
    // QualysApiClient::toQualysDatetime() actually sends to Qualys - NOT the
    // Europe/London wall-clock the per-window "Window:" lines below print,
    // because a timezone/cursor gap is precisely the kind of fault this is
    // meant to expose and the London rendering would hide an offset. Purely
    // diagnostic: prints only, changes no control flow and no data.
    $fmtUtc = static fn(\DateTimeImmutable $dt): string =>
        $dt->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');

    fwrite(STDOUT, "=== knowledge_base sync (run started " . $fmtUtc($now) . ") ===\n");
    fwrite(STDOUT, "  safety net: any window returning >= {$maxRecordsPerWindow} record(s) is re-verified (last_modified windows by QID range, published-date windows by halving); {$callDelayMs}ms pause between calls\n");

    if ($rescanSince !== null) {
        $rescanEnd = $rescanUntil ?? $now;
        fwrite(STDOUT, "  mode: RESCAN (last_modified window; sync_state cursor untouched)\n");
        fwrite(STDOUT, "--rescan-since given: re-walking {$rescanSince->format('Y-m-d H:i:s')} to " . ($rescanUntil !== null ? $rescanEnd->format('Y-m-d H:i:s') : 'now') . " with the safety net, ignoring the normal sync_state cursor.\n");
        fwrite(STDOUT, "  querying last_modified_after={$fmtUtc($rescanSince)} last_modified_before={$fmtUtc($rescanEnd)}\n\n");
        $recordsProcessed = $syncWindowWithSafetyNet(
            $makeFetchWindow(false),
            $rescanSince,
            $rescanEnd,
            0,
            true
        );
    } else {
        // --- Load backfill state -------------------------------------------
        $stateStmt = $pdo->prepare('SELECT state_json FROM sync_state WHERE sync_type = :type');
        $stateStmt->execute(['type' => 'knowledge_base']);
        $stateJson = $stateStmt->fetchColumn();
        $state = $stateJson ? json_decode((string)$stateJson, true) : [];
        $backfillComplete = !empty($state['backfill_complete']);
        // Safely before Qualys's own KnowledgeBase existed, so the very first
        // run starts from the true beginning rather than needing a real date.
        $cursor = isset($state['backfill_cursor']) ? new DateTimeImmutable($state['backfill_cursor']) : new DateTimeImmutable('1999-01-01');

        if (!$backfillComplete) {
            $chunkDays = (int)(Config::get('qualys.kb_backfill_chunk_days') ?? 90);
            $chunkEnd = $cursor->modify("+{$chunkDays} days");
            $isFinalChunk = $chunkEnd >= $now;
            if ($isFinalChunk) {
                $chunkEnd = $now;
            }

            fwrite(STDOUT, "  mode: BACKFILL (published-date walk; backfill_complete=false, backfill_cursor=" . ($state['backfill_cursor'] ?? '<none, starting 1999-01-01>') . ")\n");
            fwrite(STDOUT, "Backfill chunk: {$cursor->format('Y-m-d')} to {$chunkEnd->format('Y-m-d')}" . ($isFinalChunk ? ' (final chunk)' : '') . "\n");
            fwrite(STDOUT, "  querying published_after={$fmtUtc($cursor)} published_before={$fmtUtc($chunkEnd)}\n");

            $recordsProcessed = $syncWindowWithSafetyNet(
                $makeFetchWindow(true),
                $cursor,
                $chunkEnd
            );

            $newState = $isFinalChunk
                ? ['backfill_complete' => true, 'backfill_cursor' => $chunkEnd->format('Y-m-d')]
                : ['backfill_complete' => false, 'backfill_cursor' => $chunkEnd->format('Y-m-d')];

            $pdo->prepare('
                INSERT INTO sync_state (sync_type, state_json) VALUES (:type, :state)
                ON DUPLICATE KEY UPDATE state_json = VALUES(state_json)
            ')->execute(['type' => 'knowledge_base', 'state' => json_encode($newState)]);

            if ($isFinalChunk) {
                fwrite(STDOUT, "Backfill complete as of this run - future runs will use the normal incremental mode.\n");
            }
        } else {
            // Steady-state incremental: only what's changed since the last
            // successful run. The cursor is persisted explicitly in
            // sync_state (key 'knowledge_base_incremental', separate from
            // the backfill cursor above) as the upper bound THIS run
            // actually used for its fetch window - NOT derived from
            // sync_log.completed_at. Deriving it from completed_at would
            // leave a real gap exactly as wide as however long each run
            // takes to execute (the window between "when the fetch window
            // actually ended" and "when this row got written afterwards"),
            // silently missing anything modified in that gap - the old
            // unbounded fetch (no last_modified_before at all) never had
            // this problem because it had no upper bound to fall short of,
            // but bisection needs a concrete, splittable range, so an
            // upper bound is now unavoidable and has to be tracked
            // properly instead. Falls back to the last successful
            // sync_log completion (or, failing that, the dawn of Qualys's
            // KB) only on the very first run after this cursor was
            // introduced, when sync_state has nothing stored yet - not a
            // steady-state behaviour, just a one-time smooth transition
            // from the old cursor mechanism to this one.
            $incrementalStateStmt = $pdo->prepare('SELECT state_json FROM sync_state WHERE sync_type = :type');
            $incrementalStateStmt->execute(['type' => 'knowledge_base_incremental']);
            $incrementalStateJson = $incrementalStateStmt->fetchColumn();
            $incrementalState = $incrementalStateJson ? json_decode((string)$incrementalStateJson, true) : [];

            if (isset($incrementalState['cursor'])) {
                $sinceDate = new DateTimeImmutable($incrementalState['cursor']);
                $cursorSource = "sync_state('knowledge_base_incremental').cursor = {$incrementalState['cursor']}";
            } else {
                $lastSuccess = $pdo->query("
                    SELECT completed_at FROM sync_log
                    WHERE sync_type = 'knowledge_base' AND status = 'success' AND completed_at IS NOT NULL
                    ORDER BY completed_at DESC LIMIT 1
                ")->fetchColumn();
                $sinceDate = $lastSuccess ? new DateTimeImmutable($lastSuccess) : new DateTimeImmutable('1999-01-01');
                $cursorSource = $lastSuccess
                    ? "fallback: last successful sync_log.completed_at = {$lastSuccess} (one-time transition from the old cursor mechanism)"
                    : "fallback: 1999-01-01 (no prior successful KB sync at all)";
            }

            // Incremental indexing-lag overlap (added 2026-07). Qualys does
            // not make a KB change queryable by its last_modified filter the
            // instant the record is stamped - there is an indexing delay. The
            // old code swept [cursor, now] once and advanced the cursor to
            // 'now', so anything modified in the trailing minutes (not yet
            // indexed) returned nothing AND was then skipped for good once
            // the cursor moved past it. Confirmed 2026-07: a 1-hour window a
            // cron run logged as 0 returned 26 records - including QID
            // 6661871, stamped 2026-07-18 13:41:52Z - when the identical
            // query was re-run hours later.
            //
            // The fix is a TRAILING RE-SCAN, not a holdback. Each run starts
            // its window qualys.kb_incremental_overlap_minutes BEFORE the
            // stored cursor and still runs up to 'now', so the recent past is
            // re-examined every run: a change Qualys indexed slowly gets a
            // second, third, ... look instead of being seen once (when it may
            // still be invisible) and never again. The upsert is idempotent,
            // so re-reading that trailing band costs nothing but a modestly
            // larger response - no duplicates, no corruption. Capture is
            // GUARANTEED for any index lag up to the overlap value itself
            // (verified by phase-sweep: for lag <= overlap every mod-time
            // phase is caught; between overlap and overlap+run-gap it becomes
            // phase-dependent; beyond that it isn't caught here at all).
            // reconcile_kb_by_id.php is the id-range completeness backstop for
            // anything that ever lags past the overlap. A holdback-only variant
            // (query up to now-lag, advance cursor to there) was tried first
            // and rejected: a simulation showed it still drops records whose
            // true lag exceeds the floor, because it advances the cursor past
            // them before they become visible. The trailing re-scan does not.
            $incrementalOverlapMinutes = (int)(Config::get('qualys.kb_incremental_overlap_minutes') ?? 60);
            $queryFloor = $sinceDate->modify("-{$incrementalOverlapMinutes} minutes");

            fwrite(STDOUT, "  mode: INCREMENTAL (backfill_complete=true; last_modified window)\n");
            fwrite(STDOUT, "  cursor source: {$cursorSource}\n");
            fwrite(STDOUT, "  indexing-lag overlap: re-scanning {$incrementalOverlapMinutes} min before the cursor to absorb Qualys last_modified indexing delay (qualys.kb_incremental_overlap_minutes)\n");

            // A previous run that failed partway saved how far it got - see
            // the 2026-11 section of this file's docblock, and the catch
            // block below for how resume_floor is chosen. Only ever moves
            // the floor forward, and is cleared by the next successful run.
            if (isset($incrementalState['resume_floor'])) {
                $resumeFloor = new DateTimeImmutable((string)$incrementalState['resume_floor']);
                if ($resumeFloor > $queryFloor && $resumeFloor < $now) {
                    fwrite(STDOUT, "  resuming: a previous run failed partway after verifying everything before {$fmtUtc($resumeFloor)} - starting there instead of {$fmtUtc($queryFloor)}\n");
                    $queryFloor = $resumeFloor;
                }
            }

            fwrite(STDOUT, "  querying last_modified_after={$fmtUtc($queryFloor)} last_modified_before={$fmtUtc($now)}\n");
            if ($sinceDate > $now) {
                // Stored cursor is in the FUTURE relative to this run - a real
                // fault (clock skew, or a bad/hand-edited cursor value), not
                // the normal case. Not fatal: $queryFloor is now - overlap, so
                // the fetch below still runs over a sane trailing band rather
                // than an inverted window. But it must never be silent - if a
                // cursor is ahead of 'now', that is the thing to investigate.
                fwrite(STDOUT, "  *** WARNING: stored cursor ({$fmtUtc($sinceDate)}) is AHEAD of now ({$fmtUtc($now)}) - clock skew or a bad cursor value. The trailing overlap keeps this run's window sane, but the cursor itself should be checked. ***\n");
            }

            // --- New-QID fast-path (id_min = local max QID + 1) -------------
            // Runs only in steady-state incremental mode (backfill complete),
            // and BEFORE the last_modified sweep: it costs one call, and a
            // sweep that runs into the call reserve (the 2026-11 storm - see
            // this file's docblock) must not starve it, or brand-new QIDs stop
            // arriving at exactly the time the sweep is struggling. See
            // kbRunNewQidFastPath()'s docblock for why this exists and why it
            // complements rather than replaces reconcile_kb_by_id.php.
            if ((bool)(Config::get('qualys.kb_new_qid_fastpath_enabled') ?? true)) {
                $fastPathSpan = (int)(Config::get('qualys.kb_new_qid_fastpath_span') ?? 1000000);

                // One extra call, round-robined across the client pool like the
                // date sweeps, with the same "fall back to the primary version
                // if the picked one errors before yielding anything" recovery
                // (a retired/EOS version surfaces its error immediately, before
                // any row, so re-running the range on the primary can't double
                // up rows). fetchKnowledgeBaseByIdRange() is a generator, so the
                // try/catch has to wrap the iteration, not just the call.
                $fetchRange = function (int $idMin, int $idMax) use ($pickClient, $client): iterable {
                    $picked = $pickClient();
                    $yieldedAny = false;
                    try {
                        foreach ($picked->fetchKnowledgeBaseByIdRange($idMin, $idMax) as $vuln) {
                            $yieldedAny = true;
                            yield $vuln;
                        }
                        return;
                    } catch (\Throwable $e) {
                        if ($picked === $client || $yieldedAny) {
                            throw $e;
                        }
                        fwrite(STDOUT, "  (new-QID fast-path call on the assigned API version failed before returning anything - {$e->getMessage()} - retrying on the primary version)\n");
                    }
                    yield from $client->fetchKnowledgeBaseByIdRange($idMin, $idMax);
                };

                $fp = kbRunNewQidFastPath($pdo, $upsert, $fetchRange, $fastPathSpan, $maxRecordsPerWindow, $recordsWritten);
                if ($fp['ran']) {
                    fwrite(STDOUT, "  new-QID fast-path: local max QID {$fp['local_max']}, querying id_min={$fp['id_min']} id_max={$fp['id_max']} (span {$fastPathSpan}) -> {$fp['count']} QID(s) fetched/upserted.\n");
                    if ($fp['unverified']) {
                        fwrite(STDOUT, "  *** new-QID fast-path returned {$fp['count']} record(s) (>= the {$maxRecordsPerWindow} safety threshold): this endpoint can truncate silently, so completeness of this id range isn't guaranteed here - run scripts/reconcile_kb_by_id.php as the exhaustive backstop if you weren't already. ***\n");
                    }
                    if ($callDelayMs > 0) {
                        usleep($callDelayMs * 1000);
                    }
                    // Counted into this run's total so sync_log.records_processed
                    // and the "records processed" banner reflect new QIDs picked
                    // up here, not just those the date sweep returned.
                    $recordsProcessed += $fp['count'];
                } else {
                    fwrite(STDOUT, "  new-QID fast-path: skipped (knowledge_base is empty - nothing to anchor id_min on).\n");
                }
            } else {
                fwrite(STDOUT, "  new-QID fast-path: disabled (qualys.kb_new_qid_fastpath_enabled=false).\n");
            }

            // --- Dense-second pass -----------------------------------------
            // Completes every remembered dense second that isn't settled,
            // wherever it falls relative to this run's window - see the
            // 2026-11 section of this file's docblock. Settled means
            // verified at least one overlap after its own timestamp, so
            // nothing stamped in it can still have been waiting to be
            // indexed. One verified sooner is left alone until that point
            // has passed, then verified once more. Runs before the sweep:
            // each costs a handful of calls, while the sweep can need far
            // more.
            $overlapSec = $incrementalOverlapMinutes * 60;
            $nowTs = $now->getTimestamp();
            //
            // A lead-in second (see $rememberDenseFromCounts) is done
            // together with the second it leads into, as one 2-second
            // window: that covers both whichever way Qualys treats the end
            // bound, for one QID-range pass instead of two.
            $due = [];
            foreach ($knownDenseSeconds as $t => $info) {
                $verifiedTs = isset($info['verified_at']) ? strtotime((string)$info['verified_at']) : false;
                if ($verifiedTs !== false && ($verifiedTs >= $t + $overlapSec || $nowTs < $t + $overlapSec)) {
                    continue;
                }
                $leadsInto = isset($info['lead_in_to']) ? strtotime((string)$info['lead_in_to']) : false;
                $due[$leadsInto !== false && isset($knownDenseSeconds[$leadsInto]) ? $leadsInto : $t] = true;
            }
            ksort($due);
            foreach (array_keys($due) as $t) {
                $leadIn = isset($knownDenseSeconds[$t - 1]['lead_in_to'])
                    && strtotime((string)$knownDenseSeconds[$t - 1]['lead_in_to']) === $t;
                $recordsProcessed += $completeDenseSecond($t, 1, $leadIn);
            }

            // What the catch block needs to save a resume point if the sweep
            // dies partway (the cursor itself is left alone on failure).
            $incrementalResume = [
                'cursor'  => $fmtUtc($sinceDate),
                'floor'   => $queryFloor,
                'now'     => $now,
                'overlap' => $incrementalOverlapMinutes,
            ];
            $verifiedThrough = null;
            $recordsProcessed += $syncWindowWithSafetyNet(
                $makeFetchWindow(false),
                $queryFloor,
                $now,
                0,
                true
            );

            // Only reached if the safety net above completed without
            // throwing - a partial failure must NOT advance this cursor past
            // whatever's still unverified. The catch block instead saves a
            // resume_floor covering only the verified prefix (see the 2026-11
            // docblock section); writing the cursor here drops that, since a
            // whole window has now been verified.
            //
            // The cursor advances to 'now' (the upper bound this run used).
            // Anything modified in the trailing minutes that wasn't yet
            // indexed and so wasn't returned this run is NOT lost by that
            // advance: the next run's window starts overlap-minutes before
            // this cursor and re-scans it. That trailing re-scan, not the
            // cursor position, is what closes the indexing-lag gap.
            //
            // setTimezone(UTC) is not decorative - $now was constructed as
            // new DateTimeImmutable('now') with no explicit zone, so it
            // carries bootstrap.php's Europe/London default. Formatting it
            // with a literal '\Z' suffix would print a London wall-clock
            // value mislabelled as UTC (out by the current offset, 1h during
            // BST), which the NEXT run's $sinceDate would read back at face
            // value - silently opening a gap that wide every run. Confirmed
            // 2026-07: a batch of 45+ QIDs modified at 2026-07-16 01:01:26
            // fell inside exactly one such gap when this line lacked the
            // conversion. Converting to real UTC first matches what
            // QualysApiClient::toQualysDatetime() already does for the live
            // call. (With the trailing overlap now in place, a slip like that
            // would additionally be re-caught next run rather than lost - but
            // the correct conversion is kept regardless, on its own merits.)
            $pdo->prepare('
                INSERT INTO sync_state (sync_type, state_json) VALUES (:type, :state)
                ON DUPLICATE KEY UPDATE state_json = VALUES(state_json)
            ')->execute([
                'type'  => 'knowledge_base_incremental',
                'state' => json_encode(['cursor' => $now->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z')]),
            ]);
        }
    }

    foreach ($clientPool as $version => $c) {
        $rateInfo = $c->getLastRateLimitInfo();
        if ($rateInfo !== null && $rateInfo['remaining'] !== null) {
            fwrite(STDOUT, "Qualys API calls remaining on /api/{$version}/: {$rateInfo['remaining']}" . ($rateInfo['limit'] !== null ? "/{$rateInfo['limit']}" : '') . ($rateInfo['window_sec'] !== null ? " (per {$rateInfo['window_sec']}s window)" : '') . "\n");
        }
    }
    $totalCallsThisRun = array_sum(array_map(fn($c) => count($c->getCallLog()), $clientPool));
    fwrite(STDOUT, "Qualys API calls made this run (all versions combined): {$totalCallsThisRun}\n");

    $unverifiedNote = null;
    if (!empty($unverifiedWindows)) {
        $unverifiedNote = 'Unverified completeness at: ' . implode(', ', $unverifiedWindows);
        fwrite(STDOUT, "\n*** " . count($unverifiedWindows) . " second(s) had {$maxRecordsPerWindow}+ records and could not be fully verified - completeness not guaranteed for these exact timestamps (see UNVERIFIED COMPLETENESS lines above for what was still upserted):\n");
        foreach ($unverifiedWindows as $ts) {
            fwrite(STDOUT, "    {$ts}\n");
        }
        fwrite(STDOUT, "  Worth a closer look - e.g. scripts/diagnose_kb.php against candidate QIDs from this period, or Qualys support directly - but NOT worth re-running this whole sync over; nothing else here is in doubt. ***\n");
    }
    if (!empty($skippedDenseSeconds)) {
        // Kept in the note on every run that steps around them, so a known
        // gap stays visible on the dashboard rather than going quiet after
        // the run that first found it.
        $skippedNote = 'Known dense second(s) skipped, still unverified: ' . implode(', ', $skippedDenseSeconds);
        $unverifiedNote = $unverifiedNote !== null ? $unverifiedNote . '; ' . $skippedNote : $skippedNote;
        fwrite(STDOUT, "\n*** {$skippedNote} ***\n");
    }
    if (!empty($completedDenseSeconds)) {
        $completedNote = 'Dense second(s) completed by QID range: ' . implode(', ', $completedDenseSeconds);
        $unverifiedNote = $unverifiedNote !== null ? $unverifiedNote . '; ' . $completedNote : $completedNote;
        fwrite(STDOUT, "{$completedNote}\n");
    }

    $pdo->prepare('UPDATE sync_log SET status = :status, completed_at = :completed, records_processed = :count, error_message = :note WHERE id = :id')
        ->execute([
            'status'    => 'success',
            'completed' => date('Y-m-d H:i:s'),
            'count'     => $recordsProcessed,
            'note'      => $unverifiedNote,
            'id'        => $logId,
        ]);

    fwrite(STDOUT, "Knowledge base sync complete: {$recordsProcessed} records processed.\n");
} catch (\Throwable $e) {
    $errorMessage = $e->getMessage();

    // Save how far an incremental sweep got, so the next run doesn't start
    // the whole window again - see the 2026-11 section of this file's
    // docblock. Everything before $verifiedThrough was fetched and upserted
    // during this run, but a change stamped within the overlap of this
    // run's start may not have been indexed yet when it was fetched, so the
    // resume point is the earlier of the two. It never moves the floor
    // backwards, and the cursor is left exactly as it was.
    if ($incrementalResume !== null && $verifiedThrough !== null && $verifiedThrough > $incrementalResume['floor']) {
        $lagFloor = $incrementalResume['now']->modify("-{$incrementalResume['overlap']} minutes");
        $resumeFrom = $verifiedThrough < $lagFloor ? $verifiedThrough : $lagFloor;
        if ($resumeFrom > $incrementalResume['floor']) {
            $toUtc = static fn(\DateTimeImmutable $dt): string =>
                $dt->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
            try {
                $pdo->prepare('
                    INSERT INTO sync_state (sync_type, state_json) VALUES (:type, :state)
                    ON DUPLICATE KEY UPDATE state_json = VALUES(state_json)
                ')->execute([
                    'type'  => 'knowledge_base_incremental',
                    'state' => json_encode([
                        'cursor'       => $incrementalResume['cursor'],
                        'resume_floor' => $toUtc($resumeFrom),
                    ]),
                ]);
                $errorMessage .= ' Progress saved: verified through ' . $toUtc($verifiedThrough)
                    . ', so the next run resumes from ' . $toUtc($resumeFrom)
                    . ' instead of ' . $toUtc($incrementalResume['floor']) . '.';
            } catch (\Throwable $stateError) {
                fwrite(STDERR, 'Warning: failed to save the resume point, so the next run will start this whole window again: ' . $stateError->getMessage() . "\n");
            }
        }
    }

    $pdo->prepare('UPDATE sync_log SET status = :status, completed_at = :completed, records_processed = :count, error_message = :err WHERE id = :id')
        ->execute(['status' => 'failed', 'completed' => date('Y-m-d H:i:s'), 'count' => $recordsWritten, 'err' => $errorMessage, 'id' => $logId]);

    fwrite(STDERR, 'Knowledge base sync failed: ' . $errorMessage . "\n");
    fwrite(STDOUT, "Records written before it stopped: {$recordsWritten}\n");
    $exitCode = 1;
} finally {
    if (!empty($clientPool)) {
        try {
            $allCalls = array_merge(...array_values(array_map(fn($c) => $c->getCallLog(), $clientPool)));
            ApiCallLogRepository::recordCalls($allCalls);
        } catch (\Throwable $logError) {
            // Never let a logging failure mask the real outcome above, or
            // stop the lock from being released.
            fwrite(STDERR, 'Warning: failed to persist API call log: ' . $logError->getMessage() . "\n");
        }
    }
    flock($lockHandle, LOCK_UN);
    fclose($lockHandle);
}

// exit() deliberately lives out here, not inside the catch block above -
// exit()/die() skip any enclosing finally block entirely (unlike a normal
// exception or a return statement, which both still let finally run first)
// - so calling it from inside catch would have silently skipped the API
// call log persistence and lock cleanup above on every single failure,
// which defeats the entire point of logging failures being the case that
// matters most.
exit($exitCode);
