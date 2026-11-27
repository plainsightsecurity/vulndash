<?php
declare(strict_types=1);

namespace VulnDash\Scripts;

/**
 * Thin wrapper around the Qualys VM/VMDR "fo" API (XML, HTTP Basic Auth).
 *
 * Verification status, so it's clear what's been checked against reality
 * and what hasn't:
 *
 *   - fetchKnowledgeBaseChunk()'s field mapping and fetchHostDetections()'s
 *     host/detection field parsing are both now confirmed against real
 *     responses from Plainsight's own qg3 (US Platform 3) subscription
 *     (July 2026) - including a host with real tags and detections (agent
 *     "bernard"). One correction made from that real response: per-host
 *     tags are wrapped in <TAGS>, not <TAG_LIST> as first assumed from
 *     Qualys's general API conventions - this class now checks <TAGS>
 *     first and falls back to <TAG_LIST> defensively, in case a different
 *     subscription/API version uses the other name.
 *   - The multi-page continuation LOOP itself (extractContinuationUrl()'s
 *     <CODE>1980</CODE> handling in fetchHostDetections()) is built
 *     against Qualys's documented truncation format and is exercised on
 *     every real call this subscription makes, but has never actually had
 *     to follow a second page for real - this subscription has always had
 *     far fewer hosts than the 1000-per-page truncation_limit, so nothing
 *     has ever triggered a real multi-page response to confirm the loop
 *     against. Both fetchHostDetections() and fetchHostList() now accept
 *     an optional $pageSize override specifically so this can be verified
 *     deliberately (force e.g. truncation_limit=2 against the live API and
 *     watch it actually stitch multiple pages together) rather than
 *     waiting to find out for real once host count grows - see
 *     scripts/diagnose_tags.php's and
 *     scripts/reconcile_asset_inventory.php's --page-size option.
 *   - Rate-limit header handling (see getLastRateLimitInfo() and the 409
 *     backoff in requestToFileByUrl()) is built from Qualys's documented
 *     header names and behaviour. First hit for real 2026-10-16/17, once
 *     the licence dropped to 25 calls per endpoint per version per 24h: a 409 came back
 *     with X-RateLimit-ToWait-Sec in the tens of thousands, the old backoff
 *     slept for that long, and both the detection sync and the reconcile
 *     job sat asleep holding their locks for ~11h (their MySQL connections
 *     timing out underneath them, so the sync_log row could never have
 *     been closed even once they woke). See "Rate/concurrency limits"
 *     below for what replaced that.
 *   - fetchHostList() (added 2026-07, to catch a zero-detection asset that
 *     fetchHostDetections() never returns) is NOT yet confirmed against a
 *     real response - its field names are a best guess based on
 *     fetchHostDetections()'s confirmed shape, not documentation or a
 *     live test. Run reconcile_asset_inventory.php without --confirm
 *     first and check that a known zero-vulnerability host actually shows
 *     up correctly (real hostname/OS/tags, not blank fields) before
 *     trusting this unattended.
 *   - Agent-only scope (added 2026-07, per Mark's decision to pivot this
 *     from a combined agent+scan dashboard to an agent-only internal
 *     vulnerability management tool): both fetchHostDetections() and
 *     fetchHostList() now accept an optional $agentScopeTag via the
 *     constructor and, when set, add Qualys's documented Asset Tags
 *     filter block (use_tags=1, tag_set_by=name, tag_include_selector=any,
 *     tag_set_include={tag}) to restrict results to hosts carrying that
 *     tag. This parameter block is confirmed against Qualys's own current
 *     API documentation for both endpoints (docs.qualys.com's Host
 *     Detection List and Host List pages, both list an identical "Asset
 *     Tags" parameter section) - NOT yet exercised against a real
 *     response from this subscription, since a live call wasn't possible
 *     while building this. The default scope tag is Qualys's own built-in
 *     "Cloud Agent" tag (automatically applied by Qualys to every Cloud
 *     Agent-managed host - not something this subscription defines), set
 *     via qualys.agent_scope_tag in src/config/config.php. Leaving that
 *     config key unset (or passing null here) disables the filter
 *     entirely and restores the old "every host" behaviour - this is the
 *     safe default specifically so a config that hasn't been updated yet
 *     doesn't silently change what gets pulled.
 *   - Per-tag exclusion (added 2026-07, same day as the above, once real
 *     data showed the gap): $agentScopeTag filters which HOSTS come back,
 *     not which of a returned host's own tags get kept - a host can
 *     legitimately match the agent scope AND still carry an unrelated tag
 *     that has nothing to do with why it matched. Confirmed against a
 *     real host on this subscription (Qualys host ID 665852098,
 *     "ubuntuqualys"): it genuinely carries "Cloud Agent" (why it matches
 *     the scope) AND "LinodesExternalScan"/"Internet Facing Assets" (an
 *     unrelated dynamic tag matching on IP range, nothing to do with the
 *     agent) at the same time, so filtering by host alone let those two
 *     right back onto an otherwise-correctly-scoped host on every sync,
 *     even after being manually deleted locally. $excludedTags (also via
 *     the constructor, from qualys.excluded_tags in config) strips any
 *     tag whose name matches (case-insensitive, trimmed) out of a host's
 *     'tags' array before this class ever yields it - applied in both
 *     parseHostDetectionFile() and parseHostListFile(), so neither
 *     endpoint can reintroduce an excluded tag regardless of which one a
 *     given host came back through.
 *   - Incremental filter choice (added 2026-11): fetchHostDetections()
 *     takes the name of the host-level date filter to apply to $sinceDate -
 *     'vm_scan_since' (when the scan ran on the host) or
 *     'vm_processed_after' (when Qualys finished processing its results).
 *     See incrementalFilterParams() for why the difference matters on an
 *     agent estate. vm_processed_after is the filter Qualys's own
 *     incremental-extract guidance uses for this endpoint; it has NOT yet
 *     been exercised against this subscription. If Qualys rejects it, the
 *     request fails loudly through throwIfQualysErrorBody() like any other
 *     bad parameter - nothing is silently skipped.
 *   - AssetView id from the host pulls (added 2026-11): both host pulls can
 *     ask Qualys to include each host's <ASSET_ID> (show_asset_id=1), the
 *     AssetView id the on-demand scan and uninstall APIs target. Without
 *     it, assets.qualys_asset_id could only be filled by a separate Host
 *     Asset search call per 100 hosts (resolveAssetViewIdsByHostIds()),
 *     made lazily when a scan or uninstall was first requested. Off unless
 *     qualys.show_asset_id is true, because the parameter has NOT yet been
 *     sent to this subscription on every API version in rotation, and an
 *     unsupported parameter fails the whole pull (throwIfQualysErrorBody()).
 *     Turn it on only after scripts/check_asset_id_from_host_pulls.php has
 *     shown every version accepts it and that its ASSET_ID values match the
 *     ids the Host Asset search already resolved.
 *
 * API versioning: Qualys progressively retires /api/2.0/ per endpoint in
 * favour of higher version numbers (2.0 -> 3.0 -> 4.0 -> 5.0, at each
 * endpoint's own pace, with an "EOS" warning appearing in responses some
 * months before the old path stops working at all). This subscription's
 * own EOS warning pointed Host List Detection at /api/4.0/ as of July
 * 2026, and /api/4.0/ was confirmed working for KnowledgeBase too. The
 * version is a config value (qualys.api_version in src/config/config.php,
 * defaulting to '4.0' if not set) rather than hardcoded, so bumping it
 * again later doesn't need a code change.
 *
 * Page size (added 2026-10): fetchHostDetections() and fetchHostList() ask
 * for qualys.host_page_size hosts per page (default 1000, which is what
 * was hard-coded before). Every page is a separate call against the same
 * 25-per-24h counter, so a full pull of N hosts costs ceil(N / page size)
 * calls - with the estate heading into the thousands, this is the main
 * lever on how many calls the host pulls need. Whether Qualys serves a much
 * larger page reliably (response time, size) has NOT been tested on this
 * subscription: try a value with
 * `php scripts/reconcile_asset_inventory.php --page-size=N` (a dry run,
 * writes nothing) and check the host counts match a normal run before
 * setting it in config. Anything that isn't a positive whole number is
 * ignored in favour of the default, with a warning.
 *
 * Rate/concurrency limits: Qualys's default subscription limits are 300
 * API calls per rolling hour and 2 concurrent calls (both configurable per
 * subscription by Qualys support - check your actual limits via the
 * X-RateLimit-Limit / X-Concurrency-Limit-Limit headers, exposed here via
 * getLastRateLimitInfo() after any call). Every call this class makes is
 * sequential, never concurrent, so the concurrency limit (as low as 2 by
 * default) is never at risk from within a single script run - the real
 * risk is two cron-triggered runs overlapping, which is why both
 * scripts/sync_knowledge_base.php and scripts/sync_host_detections.php
 * take out a non-blocking file lock before doing anything else.
 *
 * Since 2026-10 this subscription's licence allows only 25 calls per
 * endpoint per API version per rolling 24h (X-RateLimit-Window-Sec:
 * 86400 - see budgetKeyForUrl() for the evidence), so two guards
 * now sit in front of every request, both here rather than in each script
 * so every caller - cron syncs and manual diagnostics alike - gets them:
 *
 *   - Fail fast on a long wait: if a 409 asks for a wait longer than
 *     qualys.max_rate_limit_wait_sec (default 300s), the request throws
 *     straight away instead of sleeping. A run that sleeps for hours holds
 *     its lock, blocks every later cron run, and loses its DB connection -
 *     failing promptly gets a readable reason into sync_log instead.
 *   - Call reserve: the last rate-limit headers seen per endpoint and
 *     version (plus the timestamps of calls made since, so calls ageing out
 *     of the rolling window are credited back) are kept in a small JSON file
 *     in the system temp dir, shared by every process that uses this class.
 *     Before each request, if the estimated calls left on that endpoint are
 *     at or below qualys.min_calls_reserve (default 3), or Qualys has said
 *     to wait until a time not yet reached, the request throws without
 *     being sent - so routine syncs can't drain the last few calls needed
 *     for a manual diagnostic. Set VULNDASH_IGNORE_CALL_RESERVE=1 on a
 *     one-off manual run to spend the reserve deliberately. The state file
 *     is advisory only: if it can't be read or written, requests go ahead
 *     and the fail-fast check still applies.
 */
class QualysApiClient implements \VulnDash\Lib\AgentProvisioningApi
{
    /**
     * Qualys's own typical page size for Host List Detection pulls - the
     * default when qualys.host_page_size isn't set (see the class docblock).
     */
    private const HOST_DETECTION_PAGE_SIZE = 1000;

    private const MAX_RETRIES_ON_CONCURRENCY_LIMIT = 5;

    /** Longest 409 wait honoured by sleeping - see the class docblock. */
    private const DEFAULT_MAX_RATE_LIMIT_WAIT_SEC = 300;

    /** Calls per endpoint-and-version held back from routine use - see the class docblock. */
    private const DEFAULT_MIN_CALLS_RESERVE = 3;

    /** Shared across processes, like the sync scripts' lock files. */
    private const BUDGET_STATE_FILE = 'vulndash_qualys_call_budget.json';

    /** Caps the per-version call history kept in the state file. */
    private const BUDGET_MAX_TRACKED_CALLS = 2000;

    /**
     * Host-level date filters the host pulls accept for $sinceDate - see
     * incrementalFilterParams(). Anything else is refused rather than sent.
     */
    private const INCREMENTAL_FILTERS = ['vm_scan_since', 'vm_processed_after'];

    private string $baseUrl;
    private string $username;
    private string $password;
    private string $apiVersion;
    private ?string $agentScopeTag;

    /** @var array<string, true> lowercased-trimmed tag names to strip, keyed for O(1) lookup */
    private array $excludedTagNames;

    /** @var array{limit: ?int, remaining: ?int, window_sec: ?int, to_wait_sec: ?int}|null */
    private ?array $lastRateLimitInfo = null;

    /** @var array{bytes: int, duration_sec: float}|null */
    private ?array $lastResponseStats = null;

    /** @var array<int, array{endpoint: string, api_version: string, called_at: string, http_status: ?int, duration_sec: ?float, response_bytes: ?int, rate_limit_remaining: ?int, rate_limit_limit: ?int}> */
    private array $callLog = [];

    private int $maxRateLimitWaitSec;
    private int $minCallsReserve;
    private int $hostPageSize;
    private bool $showAssetId;

    /**
     * @param string|null $agentScopeTag when set, restricts
     *        fetchHostDetections()/fetchHostList() to hosts carrying this
     *        Qualys tag (by name) via the tag_set_include filter - see
     *        this class's own docblock ("Agent-only scope") for why and
     *        how. Has no effect on the KnowledgeBase methods, which are
     *        global and not host/tag-scoped at all.
     * @param string[]|null $excludedTags tag NAMES (not IDs) to strip from
     *        every host's 'tags' array before this class ever yields it -
     *        see this class's own docblock ("Per-tag exclusion") for why
     *        this is a separate thing from $agentScopeTag: that param
     *        filters which HOSTS come back at all; this one filters which
     *        of a returned host's own tags get kept, since a host can
     *        legitimately match the agent scope AND still carry an
     *        unrelated tag worth ignoring. Matched case-insensitively,
     *        trimmed - "Internet Facing Assets" and " internet facing
     *        assets " are the same exclusion. Null/empty excludes nothing.
     */
    public function __construct(string $baseUrl, string $username, string $password, string $apiVersion = '4.0', ?string $agentScopeTag = null, ?array $excludedTags = null)
    {
        $this->baseUrl       = rtrim($baseUrl, '/');
        $this->username      = $username;
        $this->password      = $password;
        $this->apiVersion    = $apiVersion;
        $this->agentScopeTag = $agentScopeTag !== null && trim($agentScopeTag) !== '' ? trim($agentScopeTag) : null;

        $this->excludedTagNames = [];
        foreach ($excludedTags ?? [] as $name) {
            $key = strtolower(trim((string)$name));
            if ($key !== '') {
                $this->excludedTagNames[$key] = true;
            }
        }

        // Read from config here rather than taken as constructor args so
        // every existing caller (cron syncs and diagnostics) picks the
        // guards up without each one needing editing.
        $maxWait = self::configValue('qualys.max_rate_limit_wait_sec');
        $this->maxRateLimitWaitSec = max(0, $maxWait !== null ? (int)$maxWait : self::DEFAULT_MAX_RATE_LIMIT_WAIT_SEC);

        $reserve = self::configValue('qualys.min_calls_reserve');
        $this->minCallsReserve = max(0, $reserve !== null ? (int)$reserve : self::DEFAULT_MIN_CALLS_RESERVE);
        if (in_array(strtolower((string)getenv('VULNDASH_IGNORE_CALL_RESERVE')), ['1', 'true', 'yes'], true)) {
            $this->minCallsReserve = 0;
        }

        // A bad value falls back to the default rather than being sent:
        // 0 in particular isn't passed through, because what Qualys does
        // with truncation_limit=0 hasn't been tested here and could mean
        // one unbounded response.
        $this->hostPageSize = self::HOST_DETECTION_PAGE_SIZE;
        $pageSizeSetting = self::configValue('qualys.host_page_size');
        if ($pageSizeSetting !== null) {
            if (filter_var($pageSizeSetting, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) !== false) {
                $this->hostPageSize = (int)$pageSizeSetting;
            } else {
                self::warn('qualys.host_page_size must be a positive whole number - ignoring ' . var_export($pageSizeSetting, true) . ' and using the default of ' . self::HOST_DETECTION_PAGE_SIZE . '.');
            }
        }

        // Off by default - see "AssetView id from the host pulls" in the
        // class docblock for why it waits on the diagnostic.
        $this->showAssetId = filter_var(self::configValue('qualys.show_asset_id') ?? false, FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * Hosts per page the host pulls ask for when no per-call $pageSize is
     * given - so a script can say in its output what it actually used.
     */
    public function getHostPageSize(): int
    {
        return $this->hostPageSize;
    }

    /**
     * Overrides qualys.show_asset_id for this instance - so the diagnostic
     * can send the parameter before config turns it on for the syncs.
     */
    public function setShowAssetId(bool $showAssetId): void
    {
        $this->showAssetId = $showAssetId;
    }

    public function getShowAssetId(): bool
    {
        return $this->showAssetId;
    }

    /** @return array<string, int> */
    private function assetIdParams(): array
    {
        return $this->showAssetId ? ['show_asset_id' => 1] : [];
    }

    /**
     * Config lookup that degrades to null when the app's Config class
     * isn't loaded, so this class still works from a bare require.
     */
    private static function configValue(string $key)
    {
        return class_exists(\VulnDash\Lib\Config::class) ? \VulnDash\Lib\Config::get($key) : null;
    }

    /**
     * @param array<int, array{qualys_tag_id: string, name: string}> $tags
     * @return array<int, array{qualys_tag_id: string, name: string}>
     */
    private function filterExcludedTags(array $tags): array
    {
        if ($this->excludedTagNames === []) {
            return $tags;
        }

        return array_values(array_filter(
            $tags,
            fn(array $tag): bool => !isset($this->excludedTagNames[strtolower(trim($tag['name']))])
        ));
    }

    /**
     * Builds the four `use_tags`/`tag_set_by`/`tag_include_selector`/
     * `tag_set_include` params Qualys's Asset Tags filter block needs,
     * shared verbatim by fetchHostDetections() and fetchHostList() since
     * both endpoints document the identical parameter set. Returns an
     * empty array when no scope tag is configured, so callers can just
     * merge this in without an extra conditional at each call site.
     *
     * @return array<string, int|string>
     */
    private function agentScopeParams(): array
    {
        if ($this->agentScopeTag === null) {
            return [];
        }

        return [
            'use_tags'             => 1,
            'tag_set_by'           => 'name',
            'tag_include_selector' => 'any',
            'tag_set_include'      => $this->agentScopeTag,
        ];
    }

    /**
     * The one host-level date filter for an incremental fetchHostDetections()
     * pull. Empty when $sinceDate is null (a full pull).
     *
     * Why the choice of filter matters (2026-11): vm_scan_since is when the
     * scan RAN on the host, which for a Cloud Agent is a timestamp on the
     * endpoint itself, set before the results are uploaded and processed.
     * An incremental pull that asks for "scanned since my last run" can
     * therefore miss a host whose results took longer than one sync
     * interval to land - by the time they are visible, the scan time is
     * already behind the cursor - leaving only the full reconcile pull to
     * find it, hours later. vm_processed_after is when Qualys finished
     * processing the results, so anything visible to the API after the
     * cursor is returned regardless of how long the upload took.
     *
     * Both are host-level filters: a returned host still carries its FULL
     * current detection list, which HostSyncWriter::reconcileDetections()
     * depends on. (The detection-level detection_processed_after filter
     * would NOT be safe here - it trims the detection list itself.)
     *
     * @return array<string, string>
     */
    private function incrementalFilterParams(?\DateTimeImmutable $sinceDate, string $sinceFilter): array
    {
        if (!in_array($sinceFilter, self::INCREMENTAL_FILTERS, true)) {
            throw new \InvalidArgumentException("Unsupported incremental host filter '{$sinceFilter}' - expected one of: " . implode(', ', self::INCREMENTAL_FILTERS) . '.');
        }
        if ($sinceDate === null) {
            return [];
        }
        return [$sinceFilter => $this->toQualysDatetime($sinceDate)];
    }

    /**
     * Size and wall-clock time of the most recent API response - meant
     * for the sync scripts to log, so a chunk size (e.g.
     * qualys.kb_backfill_chunk_days) can be tuned empirically against a
     * real, tightly-limited call budget instead of guessed at blindly.
     *
     * @return array{bytes: int, duration_sec: float}|null
     */
    public function getLastResponseStats(): ?array
    {
        return $this->lastResponseStats;
    }

    /**
     * Rate-limit info from the most recent API response, so callers (the
     * sync scripts) can log remaining budget without needing their own
     * curl handling. Null if no call has been made yet, or if the last
     * call's response didn't include these headers (Qualys's docs note a
     * concurrency-limit block can come back with no rate info at all).
     *
     * @return array{limit: ?int, remaining: ?int, window_sec: ?int, to_wait_sec: ?int}|null
     */
    public function getLastRateLimitInfo(): ?array
    {
        return $this->lastRateLimitInfo;
    }

    /**
     * Every actual HTTP request this instance has made so far, in call
     * order - one entry per physical request to Qualys, including each
     * retried 409 (a retry really did hit the endpoint, and Qualys's docs
     * don't guarantee a rejected call is free against quota, so it's
     * counted rather than assumed harmless) and every page of a paginated
     * pull (fetchHostDetections() can make many requests for what looks
     * like one logical call to its own caller).
     *
     * Meant to be read once at the end of a script's run and persisted via
     * VulnDash\Lib\ApiCallLogRepository::recordCalls() - this class stays
     * database-agnostic itself, consistent with the rest of it; it just
     * hands back what happened; the caller decides what to do with that.
     *
     * @return array<int, array{endpoint: string, api_version: string, called_at: string, http_status: ?int, duration_sec: ?float, response_bytes: ?int, rate_limit_remaining: ?int, rate_limit_limit: ?int}>
     */
    public function getCallLog(): array
    {
        return $this->callLog;
    }

    /**
     * @return iterable<int, array<string, mixed>> one row per KB entry,
     *         shaped to match the columns sync_knowledge_base.php upserts.
     *
     * $lastModifiedAfter/$lastModifiedBefore are for the steady-state
     * incremental case (only QIDs touched in a given window since the last
     * successful sync - see sync_knowledge_base.php's own docblock for why
     * that window is now always bounded, not open-ended to "now").
     * $publishedAfter/$publishedBefore are for the one-time historical
     * backfill, chunked by calendar date rather than QID number - see
     * sync_knowledge_base.php for why. Don't combine last_modified_* with
     * published_* in a single call (together they'd over-constrain the
     * query in a way that's unlikely to be what's wanted, so this isn't
     * validated against that combo).
     *
     * $idMin/$idMax (added 2026-11) narrow a last_modified window to a QID
     * range, for a single second that holds more records than the sync's
     * safety threshold and so can't be split any further by time.
     * Confirmed 2026-11-04 against the live subscription with
     * scripts/check_kb_id_date_combo.php: a one-second last_modified window
     * plus id_min/id_max returned 2,503 records, every one inside both the
     * second and the QID range, and id_min was inclusive.
     */
    public function fetchKnowledgeBaseChunk(
        ?\DateTimeImmutable $lastModifiedAfter = null,
        ?\DateTimeImmutable $publishedAfter = null,
        ?\DateTimeImmutable $publishedBefore = null,
        ?\DateTimeImmutable $lastModifiedBefore = null,
        ?int $idMin = null,
        ?int $idMax = null
    ): iterable {
        $params = [
            'action'  => 'list',
            'details' => 'All',
        ];
        if ($lastModifiedAfter !== null) {
            $params['last_modified_after'] = $this->toQualysDatetime($lastModifiedAfter);
        }
        if ($lastModifiedBefore !== null) {
            $params['last_modified_before'] = $this->toQualysDatetime($lastModifiedBefore);
        }
        if ($publishedAfter !== null) {
            $params['published_after'] = $this->toQualysDatetime($publishedAfter);
        }
        if ($publishedBefore !== null) {
            $params['published_before'] = $this->toQualysDatetime($publishedBefore);
        }
        if ($idMin !== null) {
            $params['id_min'] = $idMin;
        }
        if ($idMax !== null) {
            $params['id_max'] = $idMax;
        }

        $tmpFile = $this->requestToFile('/fo/knowledge_base/vuln/', $params);
        try {
            yield from $this->parseKnowledgeBaseFile($tmpFile);
        } finally {
            @unlink($tmpFile);
        }
    }

    /**
     * Looks up specific QIDs directly, bypassing the date-range/last-modified
     * filtering fetchKnowledgeBaseChunk() uses entirely - added 2026-07 to
     * diagnose "this QID is in Qualys's KnowledgeBase but not in our local
     * copy" reports. A targeted ids= lookup is a genuinely different query
     * shape from the broad last_modified_after sweep sync_knowledge_base.php
     * runs, small enough that Qualys's undocumented-for-this-endpoint
     * response size behaviour (see this class's own docblock re:
     * truncation_limit being rejected outright here, unlike every other
     * endpoint in this class) isn't a factor either way - so this either
     * confirms the QID genuinely isn't visible to these API credentials at
     * all (a Qualys-side subscription/licensing question, not a bug here),
     * or confirms it IS returned by Qualys right now and the broad sweep is
     * somehow dropping it (a real gap in this app's sync, worth chasing
     * further - scripts/diagnose_kb.php is built around exactly this
     * distinction).
     *
     * @param array<int, int> $qids
     * @return iterable<int, array<string, mixed>> same shape as
     *         fetchKnowledgeBaseChunk() - one row per QID Qualys actually
     *         returned (a QID Qualys doesn't recognize at all is simply
     *         absent from this iterable, not an error).
     */
    public function fetchKnowledgeBaseByIds(array $qids): iterable
    {
        if ($qids === []) {
            return;
        }

        $params = [
            'action'  => 'list',
            'details' => 'All',
            'ids'     => implode(',', array_map('intval', $qids)),
        ];

        $tmpFile = $this->requestToFile('/fo/knowledge_base/vuln/', $params);
        try {
            yield from $this->parseKnowledgeBaseFile($tmpFile);
        } finally {
            @unlink($tmpFile);
        }
    }

    /**
     * Same request as fetchKnowledgeBaseByIds(), but returns the raw XML
     * untouched instead of running it through parseKnowledgeBaseFile() -
     * added 2026-07 purely as a read-only diagnostic for fields that
     * parsing doesn't map into this app's schema at all (e.g. VULN_TYPE),
     * so a real field can be inspected directly against Qualys's actual
     * response rather than guessed at via proxies like severity_level.
     * Not used by any sync path - diagnostic-only, see
     * scripts/diagnose_kb_raw.php.
     */
    public function fetchKnowledgeBaseRawXmlByIds(array $qids): string
    {
        if ($qids === []) {
            return '';
        }

        $params = [
            'action'  => 'list',
            'details' => 'All',
            'ids'     => implode(',', array_map('intval', $qids)),
        ];

        $tmpFile = $this->requestToFile('/fo/knowledge_base/vuln/', $params);
        try {
            return (string)file_get_contents($tmpFile);
        } finally {
            @unlink($tmpFile);
        }
    }

    /**
     * Looks up every QID Qualys has in a given numeric ID range - added
     * 2026-07 for scripts/reconcile_kb_by_id.php, which walks the entire
     * QID space this way as a check that's completely independent of any
     * date field (last_modified/published), specifically to catch a QID
     * that a date-based sweep could never find regardless of how well
     * that sweep is verified - e.g. one with a null/odd date field, or
     * one that fell through some other date-filtering edge case none of
     * the incidents so far happened to expose. id_min/id_max are real,
     * documented parameters for this endpoint (distinct from the
     * comma/single-value ids= filter fetchKnowledgeBaseByIds() uses) -
     * Qualys's own docs recommend exactly this pair for reducing response
     * time/delay on other "fo" endpoints, which is the same reasoning
     * reconcile_kb_by_id.php applies here: walk fixed-width numeric
     * ranges rather than one enormous unbounded request.
     *
     * @return iterable<int, array<string, mixed>> same shape as
     *         fetchKnowledgeBaseChunk() - one row per QID Qualys actually
     *         has in [$idMin, $idMax] (most of any given numeric range
     *         won't correspond to a real QID at all - QID assignment
     *         isn't dense - so an empty or sparse result for a given
     *         range is normal, not an error).
     */
    public function fetchKnowledgeBaseByIdRange(int $idMin, int $idMax): iterable
    {
        $params = [
            'action'  => 'list',
            'details' => 'All',
            'id_min'  => $idMin,
            'id_max'  => $idMax,
        ];

        $tmpFile = $this->requestToFile('/fo/knowledge_base/vuln/', $params);
        try {
            yield from $this->parseKnowledgeBaseFile($tmpFile);
        } finally {
            @unlink($tmpFile);
        }
    }

    /**
     * @return iterable<int, array<string, mixed>> one row per host, each
     *         with a nested 'detections' array and a nested 'tags' array -
     *         shaped to match what sync_host_detections.php expects.
     *         Transparently follows Qualys's truncation/pagination
     *         mechanism internally, so the caller just gets one flat
     *         stream regardless of how many pages it took.
     *
     * $pageSize overrides qualys.host_page_size (see the class docblock) for
     * this call only - exists so a caller can deliberately force a small
     * truncation_limit (e.g. 2) against the live API to actually exercise
     * the multi-page continuation loop below on a subscription that
     * doesn't yet have enough hosts to fill a page naturally, or try a
     * larger one before committing it to config. Leave null for normal
     * use - see scripts/diagnose_tags.php's --page-size option for how
     * this gets used in practice.
     *
     * $sinceFilter names the host-level date filter $sinceDate is applied
     * through - see incrementalFilterParams(). Defaults to vm_scan_since,
     * the long-standing behaviour, so callers that don't pass it are
     * unchanged.
     */
    public function fetchHostDetections(?\DateTimeImmutable $sinceDate = null, ?int $pageSize = null, string $sinceFilter = 'vm_scan_since'): iterable
    {
        $params = [
            'action'           => 'list',
            'show_tags'        => 1,
            'truncation_limit' => $pageSize ?? $this->hostPageSize,
        ] + $this->agentScopeParams() + $this->incrementalFilterParams($sinceDate, $sinceFilter) + $this->assetIdParams();

        $nextUrl = null;
        do {
            $tmpFile = $nextUrl !== null
                ? $this->requestToFileByUrl($nextUrl)
                : $this->requestToFile('/fo/asset/host/vm/detection/', $params);

            try {
                yield from $this->parseHostDetectionFile($tmpFile);
                $nextUrl = $this->extractContinuationUrl($tmpFile);
            } finally {
                @unlink($tmpFile);
            }
        } while ($nextUrl !== null);
    }

    /**
     * Plain asset inventory - Qualys's separate Host List endpoint
     * (/fo/asset/host/), NOT Host List Detection. Exists specifically to
     * catch an asset Qualys knows about but currently has zero open
     * detections for.
     *
     * Reported 2026-07: an agent with zero vulnerabilities never appeared
     * on the dashboard at all, despite fetchHostDetections() supposedly
     * doing a full, unfiltered pull of every host via
     * reconcile_asset_inventory.php. Both this class's own parsing
     * (parseHostDetectionFile()) and the upsert logic in
     * sync_host_detections.php / reconcile_asset_inventory.php were
     * checked and neither skips a host for having an empty detection
     * list - a host with detections => [] upserts and displays exactly
     * like one with detections => [...], open_vuln_count = 0. That rules
     * out this app's own code as the cause.
     *
     * The most likely remaining explanation - inferred from that report
     * and from what "/vm/detection/" in the endpoint's own name implies
     * about its shape, NOT confirmed against Qualys's documentation
     * (unavailable in this environment) or a real response - is that Host
     * List Detection is fundamentally organized around detection records,
     * and simply has no row to return for a host with nothing to detect
     * at all, the same way a SQL join keyed off a detections table would
     * never surface a host with zero matching rows. Host List is a
     * genuinely different, asset-oriented endpoint that doesn't have that
     * shape - a host exists in its response because it exists as an
     * asset, independent of whether it has any detections.
     *
     * Because of that unconfirmed-endpoint-shape assumption, several
     * field names below are a best guess rather than a checked fact -
     * marked inline where that applies. If a field consistently comes
     * back empty/wrong after this runs against a real subscription, that
     * field's name is the first thing to check.
     *
     * @param int|null $pageSize overrides qualys.host_page_size for
     *        this call only - same purpose as fetchHostDetections()'s own
     *        $pageSize param. Also fixes a real gap this endpoint had until
     *        now: unlike fetchHostDetections(), this call never sent
     *        truncation_limit at all, so it was silently relying on
     *        whatever Qualys's undocumented-for-this-endpoint default page
     *        size happens to be - now explicit either way. This does NOT
     *        by itself confirm the <CODE>1980</CODE> continuation format
     *        below actually applies to this endpoint (still an untested
     *        assumption per the docblock above) - it only guarantees a
     *        known, controllable page size for whatever pagination
     *        mechanism Qualys does use here.
     *
     * @return iterable<int, array<string, mixed>> one row per host, same
     *         shape as fetchHostDetections() yields, except 'detections'
     *         is always [] here (this endpoint doesn't return them at
     *         all, so there's nothing to merge in even for a host that
     *         does have some - see reconcile_asset_inventory.php for how
     *         the two are combined without one overwriting the other's
     *         data).
     */
    public function fetchHostList(?int $pageSize = null): iterable
    {
        $params = [
            'action'           => 'list',
            'details'          => 'All',
            'show_tags'        => 1,
            'truncation_limit' => $pageSize ?? $this->hostPageSize,
        ] + $this->agentScopeParams() + $this->assetIdParams();

        $nextUrl = null;
        do {
            $tmpFile = $nextUrl !== null
                ? $this->requestToFileByUrl($nextUrl)
                : $this->requestToFile('/fo/asset/host/', $params);

            try {
                yield from $this->parseHostListFile($tmpFile);
                // Untested assumption: this reuses the same <CODE>1980</CODE>
                // continuation mechanism confirmed for Host List Detection.
                // If Host List paginates differently (or not at all - it may
                // return everything in one response), this simply never
                // matches and the loop ends after one page, which is safe
                // either way.
                $nextUrl = $this->extractContinuationUrl($tmpFile);
            } finally {
                @unlink($tmpFile);
            }
        } while ($nextUrl !== null);
    }

    // ------------------------------------------------------------------
    // Parsing
    // ------------------------------------------------------------------

    /**
     * Every row yielded here is passed straight to a named-parameter
     * INSERT by sync_knowledge_base.php, reconcile_kb_by_id.php,
     * diagnose_kb.php and VulnDash\Lib\KnowledgeBaseUpsert (used by
     * fetch_missing_kb_qids.php). Under native prepares a key with no
     * matching placeholder fails the execute, so a key added here must be
     * added to all four upserts in the same change (patch_published_date
     * was, 2026-11-04, to the first three).
     *
     * @return iterable<int, array<string, mixed>>
     */
    private function parseKnowledgeBaseFile(string $path): iterable
    {
        $reader = new \XMLReader();
        $reader->open($path);

        while ($reader->read()) {
            if ($reader->nodeType !== \XMLReader::ELEMENT || $reader->name !== 'VULN') {
                continue;
            }

            $vuln = new \SimpleXMLElement($reader->readOuterXml());

            $cveIds = [];
            if (isset($vuln->CVE_LIST->CVE)) {
                foreach ($vuln->CVE_LIST->CVE as $cve) {
                    $id = trim((string)$cve->ID);
                    if ($id !== '') {
                        $cveIds[] = $id;
                    }
                }
            }

            $vendorRefs = [];
            if (isset($vuln->VENDOR_REFERENCE_LIST->VENDOR_REFERENCE)) {
                foreach ($vuln->VENDOR_REFERENCE_LIST->VENDOR_REFERENCE as $ref) {
                    $line = trim(trim((string)$ref->ID) . ': ' . trim((string)$ref->URL));
                    if ($line !== ':') {
                        $vendorRefs[] = $line;
                    }
                }
            }

            yield [
                'qid'                  => (int)$vuln->QID,
                'title'                => trim((string)$vuln->TITLE),
                'severity_level'       => (int)$vuln->SEVERITY_LEVEL,
                'category'             => isset($vuln->CATEGORY) && (string)$vuln->CATEGORY !== '' ? (string)$vuln->CATEGORY : null,
                'cvss_base'            => isset($vuln->CVSS->BASE) && (string)$vuln->CVSS->BASE !== '' ? (float)$vuln->CVSS->BASE : null,
                'cvss_vector'          => isset($vuln->CVSS->VECTOR_STRING) && (string)$vuln->CVSS->VECTOR_STRING !== '' ? (string)$vuln->CVSS->VECTOR_STRING : null,
                'cvss3_base'           => isset($vuln->CVSS_V3->BASE) && (string)$vuln->CVSS_V3->BASE !== '' ? (float)$vuln->CVSS_V3->BASE : null,
                'cvss3_vector'         => isset($vuln->CVSS_V3->VECTOR_STRING) && (string)$vuln->CVSS_V3->VECTOR_STRING !== '' ? (string)$vuln->CVSS_V3->VECTOR_STRING : null,
                'cve_ids'              => $cveIds !== [] ? implode(',', $cveIds) : null,
                'vendor_reference'     => $vendorRefs !== [] ? implode("\n", $vendorRefs) : null,
                'patchable'            => isset($vuln->PATCHABLE) ? (int)$vuln->PATCHABLE : 0,
                'pci_flag'             => isset($vuln->PCI_FLAG) ? (int)$vuln->PCI_FLAG : 0,
                'diagnosis'            => isset($vuln->DIAGNOSIS) ? (string)$vuln->DIAGNOSIS : null,
                'consequence'          => isset($vuln->CONSEQUENCE) ? (string)$vuln->CONSEQUENCE : null,
                'solution'             => isset($vuln->SOLUTION) ? (string)$vuln->SOLUTION : null,
                'published_datetime'   => isset($vuln->PUBLISHED_DATETIME) ? $this->toMysqlDatetime((string)$vuln->PUBLISHED_DATETIME) : null,
                // When the vendor released the fix - the CE+ patch clock's
                // start date (see src/Lib/CePlusDeadline.php). Optional in
                // Qualys's DTD; confirmed 2026-11-04 present on every
                // patchable QID checked and absent on an unpatchable one,
                // e.g. 2026-04-07T00:00:00Z. Absent -> NULL.
                'patch_published_date' => isset($vuln->PATCH_PUBLISHED_DATE) && (string)$vuln->PATCH_PUBLISHED_DATE !== '' ? $this->toMysqlDatetime((string)$vuln->PATCH_PUBLISHED_DATE) : null,
                'qualys_last_modified' => isset($vuln->LAST_SERVICE_MODIFICATION_DATETIME) ? $this->toMysqlDatetime((string)$vuln->LAST_SERVICE_MODIFICATION_DATETIME) : null,
            ];

            unset($vuln);
        }

        $reader->close();
    }

    /** @return iterable<int, array<string, mixed>> */
    private function parseHostDetectionFile(string $path): iterable
    {
        $reader = new \XMLReader();
        $reader->open($path);

        while ($reader->read()) {
            if ($reader->nodeType !== \XMLReader::ELEMENT || $reader->name !== 'HOST') {
                continue;
            }

            $host = new \SimpleXMLElement($reader->readOuterXml());

            // Confirmed against a real response: Qualys wraps per-host
            // tags in <TAGS>, not <TAG_LIST>. Checking both defensively -
            // <TAG_LIST> was the original (wrong) assumption based on
            // Qualys's general API conventions, kept as a fallback in case
            // it's genuinely used elsewhere (a different API version, a
            // different subscription config) rather than deleted outright.
            $tagContainer = $host->TAGS ?? $host->TAG_LIST ?? null;
            $tags = [];
            if ($tagContainer !== null && isset($tagContainer->TAG)) {
                foreach ($tagContainer->TAG as $tag) {
                    $tagId = trim((string)($tag->TAG_ID ?? ''));
                    $name  = trim((string)($tag->NAME ?? ''));
                    if ($tagId !== '') {
                        $tags[] = ['qualys_tag_id' => $tagId, 'name' => $name !== '' ? $name : $tagId];
                    }
                }
            }
            $tags = $this->filterExcludedTags($tags);

            $detections = [];
            if (isset($host->DETECTION_LIST->DETECTION)) {
                foreach ($host->DETECTION_LIST->DETECTION as $d) {
                    $detections[] = [
                        'qid'         => (int)$d->QID,
                        'status'      => isset($d->STATUS) && (string)$d->STATUS !== '' ? (string)$d->STATUS : 'Active',
                        // Confirmed against real data: Qualys reports the
                        // detection kind in <TYPE> as 'Vuln' (confirmed),
                        // 'Practice' (potential) or 'Ig' (information gathered)
                        // - NOT the 'Confirmed'/'Potential'/'Info' its docs
                        // sometimes imply. normaliseDetectionType() folds those
                        // (and the doc spellings, defensively) into one stored
                        // vocabulary so nothing downstream has to know the raw
                        // codes. See the 'Potential' chip on the vuln list.
                        'type'        => $this->normaliseDetectionType(isset($d->TYPE) ? (string)$d->TYPE : null),
                        // Confirmed against a real agent-based detection:
                        // PORT/PROTOCOL are frequently absent entirely for
                        // OS/registry-based checks (as opposed to
                        // network-service detections), so these stay
                        // nullable rather than defaulting to 0/''.
                        'port'        => isset($d->PORT) && (string)$d->PORT !== '' ? (int)$d->PORT : null,
                        'protocol'    => isset($d->PROTOCOL) && (string)$d->PROTOCOL !== '' ? (string)$d->PROTOCOL : null,
                        'ssl'         => isset($d->SSL) ? (int)$d->SSL : 0,
                        'first_found' => isset($d->FIRST_FOUND_DATETIME) ? $this->toMysqlDatetime((string)$d->FIRST_FOUND_DATETIME) : null,
                        'last_found'  => isset($d->LAST_FOUND_DATETIME) ? $this->toMysqlDatetime((string)$d->LAST_FOUND_DATETIME) : null,
                        'last_fixed'  => isset($d->LAST_FIXED_DATETIME) ? $this->toMysqlDatetime((string)$d->LAST_FIXED_DATETIME) : null,
                        'times_found' => isset($d->TIMES_FOUND) && (string)$d->TIMES_FOUND !== '' ? (int)$d->TIMES_FOUND : 1,
                        'results'     => isset($d->RESULTS) ? (string)$d->RESULTS : null,
                    ];
                }
            }

            $hostname = isset($host->DNS_DATA->HOSTNAME) && (string)$host->DNS_DATA->HOSTNAME !== ''
                ? (string)$host->DNS_DATA->HOSTNAME
                : (isset($host->NETBIOS) ? (string)$host->NETBIOS : null);

            $dnsName = isset($host->DNS_DATA->FQDN) && (string)$host->DNS_DATA->FQDN !== ''
                ? (string)$host->DNS_DATA->FQDN
                : (isset($host->DNS) && (string)$host->DNS !== '' ? (string)$host->DNS : null);

            $lastScanRaw = isset($host->LAST_VM_SCANNED_DATE) && (string)$host->LAST_VM_SCANNED_DATE !== ''
                ? (string)$host->LAST_VM_SCANNED_DATE
                : (isset($host->LAST_SCAN_DATETIME) ? (string)$host->LAST_SCAN_DATETIME : null);

            yield [
                'id'              => (int)$host->ID,
                'asset_id'        => $this->parseAssetId($host),
                'hostname'        => $hostname !== '' ? $hostname : null,
                'ip'              => isset($host->IP) ? (string)$host->IP : null,
                'dns'             => $dnsName !== '' ? $dnsName : null,
                'os'              => isset($host->OS) ? (string)$host->OS : null,
                'tracking_method' => isset($host->TRACKING_METHOD) ? (string)$host->TRACKING_METHOD : null,
                'last_scan_date'  => $lastScanRaw !== null ? $this->toMysqlDatetime($lastScanRaw) : null,
                'tags'            => $tags,
                'detections'      => $detections,
            ];

            unset($host);
        }

        $reader->close();
    }

    /**
     * Parses a Host List (/fo/asset/host/) response - see fetchHostList()'s
     * docblock for the significant caveat that this endpoint's exact field
     * names are inferred, not confirmed against a real response.
     * Deliberately mirrors parseHostDetectionFile()'s field-extraction
     * logic wherever the two endpoints plausibly share field names, so a
     * host processed via either path ends up with a consistently-shaped
     * record.
     *
     * @return iterable<int, array<string, mixed>>
     */
    private function parseHostListFile(string $path): iterable
    {
        $reader = new \XMLReader();
        $reader->open($path);

        while ($reader->read()) {
            if ($reader->nodeType !== \XMLReader::ELEMENT || $reader->name !== 'HOST') {
                continue;
            }

            $host = new \SimpleXMLElement($reader->readOuterXml());

            $tagContainer = $host->TAGS ?? $host->TAG_LIST ?? null;
            $tags = [];
            if ($tagContainer !== null && isset($tagContainer->TAG)) {
                foreach ($tagContainer->TAG as $tag) {
                    $tagId = trim((string)($tag->TAG_ID ?? ''));
                    $name  = trim((string)($tag->NAME ?? ''));
                    if ($tagId !== '') {
                        $tags[] = ['qualys_tag_id' => $tagId, 'name' => $name !== '' ? $name : $tagId];
                    }
                }
            }
            $tags = $this->filterExcludedTags($tags);

            $hostname = isset($host->DNS_DATA->HOSTNAME) && (string)$host->DNS_DATA->HOSTNAME !== ''
                ? (string)$host->DNS_DATA->HOSTNAME
                : (isset($host->NETBIOS) ? (string)$host->NETBIOS : null);

            $dnsName = isset($host->DNS_DATA->FQDN) && (string)$host->DNS_DATA->FQDN !== ''
                ? (string)$host->DNS_DATA->FQDN
                : (isset($host->DNS) && (string)$host->DNS !== '' ? (string)$host->DNS : null);

            // Best guess, not confirmed - Host List's "last scanned" field
            // may not share Host List Detection's exact name. Tries the
            // same name first (the two endpoints likely share some host
            // schema), then two plausible alternatives, in order of how
            // likely each seems for this endpoint specifically.
            $lastScanRaw = isset($host->LAST_VM_SCANNED_DATE) && (string)$host->LAST_VM_SCANNED_DATE !== ''
                ? (string)$host->LAST_VM_SCANNED_DATE
                : (isset($host->LAST_VULN_SCAN_DATETIME) && (string)$host->LAST_VULN_SCAN_DATETIME !== ''
                    ? (string)$host->LAST_VULN_SCAN_DATETIME
                    : (isset($host->LAST_SCAN_DATETIME) ? (string)$host->LAST_SCAN_DATETIME : null));

            yield [
                'id'              => (int)$host->ID,
                'asset_id'        => $this->parseAssetId($host),
                'hostname'        => $hostname !== '' ? $hostname : null,
                'ip'              => isset($host->IP) ? (string)$host->IP : null,
                'dns'             => $dnsName !== '' ? $dnsName : null,
                'os'              => isset($host->OS) ? (string)$host->OS : null,
                'tracking_method' => isset($host->TRACKING_METHOD) ? $this->normalizeTrackingMethod((string)$host->TRACKING_METHOD) : null,
                'last_scan_date'  => $lastScanRaw !== null ? $this->toMysqlDatetime($lastScanRaw) : null,
                'tags'            => $tags,
                'detections'      => [], // this endpoint never returns detection records at all
            ];

            unset($host);
        }

        $reader->close();
    }

    // ------------------------------------------------------------------
    // HTTP
    // ------------------------------------------------------------------

    private function requestToFile(string $path, array $params): string
    {
        $url = $this->baseUrl . '/api/' . $this->apiVersion . $path . '?' . http_build_query($params);
        return $this->requestToFileByUrl($url);
    }

    private function requestToFileByUrl(string $url): string
    {
        $budgetKey = $this->budgetKeyForUrl($url);
        for ($attempt = 1; $attempt <= self::MAX_RETRIES_ON_CONCURRENCY_LIMIT; $attempt++) {
            $this->assertCallBudget($budgetKey);

            $tmpFile = tempnam(sys_get_temp_dir(), 'qualys_');
            if ($tmpFile === false) {
                throw new \RuntimeException('Could not create a temp file for the Qualys API response.');
            }

            $responseHeaders = [];
            $fh = fopen($tmpFile, 'w');
            $ch = curl_init($url);
            $requestStart = microtime(true);
            curl_setopt_array($ch, [
                CURLOPT_HTTPAUTH       => CURLAUTH_BASIC,
                CURLOPT_USERPWD        => $this->username . ':' . $this->password,
                CURLOPT_HTTPHEADER     => ['X-Requested-With: Plainsight VulnDash'],
                CURLOPT_FILE           => $fh,
                CURLOPT_CONNECTTIMEOUT => 30,
                CURLOPT_TIMEOUT        => 0, // KnowledgeBase pulls can legitimately take minutes
                CURLOPT_HEADERFUNCTION => function ($curlHandle, string $headerLine) use (&$responseHeaders): int {
                    $parts = explode(':', $headerLine, 2);
                    if (count($parts) === 2) {
                        $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                    }
                    return strlen($headerLine);
                },
            ]);
            $ok = curl_exec($ch);
            $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curlError = curl_error($ch);
            curl_close($ch);
            fclose($fh);

            $this->lastRateLimitInfo = $this->extractRateLimitInfo($responseHeaders);
            $this->lastResponseStats = [
                'bytes'        => file_exists($tmpFile) ? (int)filesize($tmpFile) : 0,
                'duration_sec' => round(microtime(true) - $requestStart, 1),
            ];

            $this->callLog[] = [
                'endpoint'             => $this->endpointFromUrl($url),
                'api_version'          => $this->apiVersionForBudgetKey($budgetKey),
                'called_at'            => date('Y-m-d H:i:s'),
                'http_status'          => $ok !== false ? $httpCode : null,
                'duration_sec'         => $this->lastResponseStats['duration_sec'],
                'response_bytes'       => $this->lastResponseStats['bytes'],
                'rate_limit_remaining' => $this->lastRateLimitInfo['remaining'] ?? null,
                'rate_limit_limit'     => $this->lastRateLimitInfo['limit'] ?? null,
            ];

            if ($ok === false) {
                @unlink($tmpFile);
                throw new \RuntimeException('Qualys API request failed: ' . $curlError);
            }

            $this->recordCallBudget($budgetKey, $this->lastRateLimitInfo, $httpCode);

            if ($httpCode === 409) {
                // Prefer Qualys's own stated wait time over a guess.
                $waitSec = $this->lastRateLimitInfo['to_wait_sec'] ?? null;
                if ($waitSec !== null && $waitSec > $this->maxRateLimitWaitSec) {
                    @unlink($tmpFile);
                    throw new \RuntimeException($this->rateLimitExhaustedMessage($budgetKey, $waitSec));
                }
                if ($attempt < self::MAX_RETRIES_ON_CONCURRENCY_LIMIT) {
                    @unlink($tmpFile);
                    sleep($waitSec !== null && $waitSec > 0 ? $waitSec + 2 : 5 * $attempt);
                    continue;
                }
            }

            if ($httpCode === 401 || $httpCode === 403) {
                @unlink($tmpFile);
                throw new \RuntimeException("Qualys API authentication failed (HTTP {$httpCode}) - check the credentials in src/config/config.php.");
            }

            $this->throwIfQualysErrorBody($tmpFile, $httpCode);

            // Any other non-2xx (a 5xx or proxy/maintenance page, or a 409
            // still refused after the last retry) has no <SIMPLE_RETURN>
            // for the check above to find, and the parsers read a body that
            // isn't the expected XML as zero rows. Found 2026-11-09: that
            // made a KB sync log success with 0 records and move its cursor
            // past everything it never saw. Failing here instead is what
            // every caller already handles.
            if ($httpCode < 200 || $httpCode >= 300) {
                @unlink($tmpFile);
                if ($httpCode === 409) {
                    break;
                }
                throw new \RuntimeException("Qualys API returned HTTP {$httpCode} for " . $this->endpointFromUrl($url) . ' with no recognisable error body - not treating the response as data.');
            }

            return $tmpFile;
        }

        throw new \RuntimeException('Qualys API request kept hitting the concurrency/rate limit (HTTP 409) after ' . self::MAX_RETRIES_ON_CONCURRENCY_LIMIT . ' attempts.');
    }

    /**
     * Shared POST plumbing for the QPS REST family (Asset Management / Cloud
     * Agent), which - unlike the "fo" API the rest of this class uses - is a
     * POST-with-XML-body service under /qps/rest/2.0/ rather than a GET under
     * /api/{version}/fo/. Same host, same HTTP Basic credentials, different
     * path/method/content-type. Mirrors requestToFileByUrl()'s auth, call
     * logging, 409 concurrency backoff and rate-limit capture so QPS calls
     * show up on the API usage page exactly like fo calls do.
     *
     * $path is the full QPS path, e.g. '/qps/rest/2.0/search/am/hostasset'.
     * Note: QPS reports request errors in the <ServiceResponse><responseCode>
     * body (not the fo <SIMPLE_RETURN> shape), so error handling is left to
     * each caller's own response parser rather than throwIfQualysErrorBody().
     */
    private function postQpsToFile(string $path, string $xmlBody): string
    {
        $url = $this->baseUrl . $path;
        $budgetKey = $this->budgetKeyForUrl($url);
        for ($attempt = 1; $attempt <= self::MAX_RETRIES_ON_CONCURRENCY_LIMIT; $attempt++) {
            $this->assertCallBudget($budgetKey);

            $tmpFile = tempnam(sys_get_temp_dir(), 'qualys_qps_');
            if ($tmpFile === false) {
                throw new \RuntimeException('Could not create a temp file for the Qualys QPS API response.');
            }

            $responseHeaders = [];
            $fh = fopen($tmpFile, 'w');
            $ch = curl_init($url);
            $requestStart = microtime(true);
            curl_setopt_array($ch, [
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => $xmlBody,
                CURLOPT_HTTPAUTH       => CURLAUTH_BASIC,
                CURLOPT_USERPWD        => $this->username . ':' . $this->password,
                CURLOPT_HTTPHEADER     => [
                    'X-Requested-With: Plainsight VulnDash',
                    'Content-Type: text/xml',
                ],
                CURLOPT_FILE           => $fh,
                CURLOPT_CONNECTTIMEOUT => 30,
                CURLOPT_TIMEOUT        => 0,
                CURLOPT_HEADERFUNCTION => function ($curlHandle, string $headerLine) use (&$responseHeaders): int {
                    $parts = explode(':', $headerLine, 2);
                    if (count($parts) === 2) {
                        $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                    }
                    return strlen($headerLine);
                },
            ]);
            $ok = curl_exec($ch);
            $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curlError = curl_error($ch);
            curl_close($ch);
            fclose($fh);

            $this->lastRateLimitInfo = $this->extractRateLimitInfo($responseHeaders);
            $this->lastResponseStats = [
                'bytes'        => file_exists($tmpFile) ? (int)filesize($tmpFile) : 0,
                'duration_sec' => round(microtime(true) - $requestStart, 1),
            ];

            $this->callLog[] = [
                // Path only: the on-demand scan call carries its options in
                // a query string, which must not split its log rows (or the
                // API usage page's columns) by option.
                'endpoint'             => $budgetKey,
                'api_version'          => $this->apiVersionForBudgetKey($budgetKey),
                'called_at'            => date('Y-m-d H:i:s'),
                'http_status'          => $ok !== false ? $httpCode : null,
                'duration_sec'         => $this->lastResponseStats['duration_sec'],
                'response_bytes'       => $this->lastResponseStats['bytes'],
                'rate_limit_remaining' => $this->lastRateLimitInfo['remaining'] ?? null,
                'rate_limit_limit'     => $this->lastRateLimitInfo['limit'] ?? null,
            ];

            if ($ok === false) {
                @unlink($tmpFile);
                throw new \RuntimeException('Qualys QPS API request failed: ' . $curlError);
            }

            $this->recordCallBudget($budgetKey, $this->lastRateLimitInfo, $httpCode);

            if ($httpCode === 409) {
                $waitSec = $this->lastRateLimitInfo['to_wait_sec'] ?? null;
                if ($waitSec !== null && $waitSec > $this->maxRateLimitWaitSec) {
                    @unlink($tmpFile);
                    throw new \RuntimeException($this->rateLimitExhaustedMessage($budgetKey, $waitSec));
                }
                if ($attempt < self::MAX_RETRIES_ON_CONCURRENCY_LIMIT) {
                    @unlink($tmpFile);
                    sleep($waitSec !== null && $waitSec > 0 ? $waitSec + 2 : 5 * $attempt);
                    continue;
                }
            }

            if ($httpCode === 401 || $httpCode === 403) {
                @unlink($tmpFile);
                throw new \RuntimeException("Qualys QPS API authentication failed (HTTP {$httpCode}) - check the credentials in src/config/config.php.");
            }

            return $tmpFile;
        }

        throw new \RuntimeException('Qualys QPS API request kept hitting the concurrency/rate limit (HTTP 409) after ' . self::MAX_RETRIES_ON_CONCURRENCY_LIMIT . ' attempts.');
    }

    /**
     * Resolve Qualys "AssetView" asset ids (the identifier the Cloud Agent
     * uninstall API takes) for a set of qweb host ids (what this app stores as
     * assets.qualys_host_id). Uses the Asset Management Host Asset search
     * endpoint, whose response carries BOTH <id> (the AssetView asset id) and
     * <qwebHostId> for each host - confirmed against Qualys's AM & Tagging API
     * docs (search/am/hostasset supports a qwebHostId IN (...) filter, and the
     * <HostAsset><id> in the response is the AssetView id, with <qwebHostId>
     * listed separately). This is the mapping the uninstall worker needs
     * because Host List Detection (what the sync pulls from) returns only the
     * qweb host id by default. With qualys.show_asset_id on, both host pulls
     * carry <ASSET_ID> as well and HostSyncWriter stores it, leaving this as
     * the fallback for an asset that still has none (see the class docblock).
     *
     * Read-only. Batched (default 100 ids per call) with limitResults set to
     * the batch size, so each explicit qwebHostId IN (...) list comes back in
     * a single page - no pagination cursor needed for an explicit id list.
     *
     * NOTE (verify against your subscription before trusting unattended): the
     * qwebHostId-IN filter and the <id>=AssetView-id mapping are confirmed
     * from Qualys's documentation, not yet from a live response on this
     * subscription. Run scripts/resolve_asset_ids.php WITHOUT --confirm first
     * and eyeball the resolved pairs before letting anything write or uninstall.
     *
     * @param int[] $hostIds qweb host ids (assets.qualys_host_id)
     * @return array<int,int> qwebHostId => assetViewId (hosts Qualys doesn't
     *         return are simply absent from the map)
     */
    public function resolveAssetViewIdsByHostIds(array $hostIds, int $batchSize = 100): array
    {
        $hostIds = array_values(array_unique(array_filter(array_map('intval', $hostIds), static fn ($v) => $v > 0)));
        $map = [];
        foreach (array_chunk($hostIds, max(1, $batchSize)) as $chunk) {
            $list = implode(',', $chunk);
            $body = '<?xml version="1.0" encoding="UTF-8"?>'
                . '<ServiceRequest>'
                . '<preferences><limitResults>' . count($chunk) . '</limitResults></preferences>'
                . '<filters><Criteria field="qwebHostId" operator="IN">' . $list . '</Criteria></filters>'
                . '</ServiceRequest>';
            $tmp = $this->postQpsToFile('/qps/rest/2.0/search/am/hostasset', $body);
            try {
                foreach ($this->parseHostAssetSearch($tmp) as $qweb => $assetId) {
                    $map[$qweb] = $assetId;
                }
            } finally {
                @unlink($tmp);
            }
        }
        return $map;
    }

    /**
     * Parse a Host Asset search response into a qwebHostId => assetViewId map.
     * Raises on a non-SUCCESS responseCode so a bad request surfaces loudly
     * rather than silently resolving nothing.
     *
     * @return array<int,int>
     */
    private function parseHostAssetSearch(string $path): array
    {
        $xml = \simplexml_load_file($path);
        if ($xml === false) {
            throw new \RuntimeException('Could not parse Qualys Host Asset search response as XML.');
        }

        $code = isset($xml->responseCode) ? (string)$xml->responseCode : '';
        if ($code !== '' && $code !== 'SUCCESS') {
            $detail = isset($xml->responseErrorDetails->errorMessage)
                ? (string)$xml->responseErrorDetails->errorMessage
                : '';
            throw new \RuntimeException("Qualys Host Asset search returned {$code}" . ($detail !== '' ? ": {$detail}" : ''));
        }

        $out = [];
        if (isset($xml->data->HostAsset)) {
            foreach ($xml->data->HostAsset as $ha) {
                $assetId = isset($ha->id) ? (int)$ha->id : 0;
                $qweb    = isset($ha->qwebHostId) ? (int)$ha->qwebHostId : 0;
                if ($assetId > 0 && $qweb > 0) {
                    $out[$qweb] = $assetId;
                }
            }
        }
        return $out;
    }

    /**
     * Tag definitions by Qualys tag id, from the Asset Management Search Tags
     * endpoint (POST /qps/rest/2.0/search/am/tag). Host List Detection's
     * <TAGS> carries only each tag's id and name - nothing about how the tag
     * is built - so this is the only way to tell an asset-group or IP-range
     * tag (which Qualys applies to an agent host simply because the host's
     * IP matches) apart from a tag meant to scope a client.
     *
     * Read-only. Batched (default 100 ids per call) with limitResults set to
     * the batch size, so each id IN (...) list comes back in one page - the
     * same pattern as resolveAssetViewIdsByHostIds().
     *
     * NOTE (2026-11): the id IN filter and the field names (ruleType,
     * ruleText, srcAssetGroupId, parentTagId) are from Qualys's AM & Tagging
     * API docs, not yet a live response on this subscription - hence 'other',
     * every leaf element of each <Tag> exactly as returned, so a field the
     * docs don't mention (or name differently) still shows up in
     * scripts/diagnose_tag_rule_types.php instead of being silently dropped.
     *
     * @param array<int,int|string> $tagIds Qualys tag ids (tags.qualys_tag_id)
     * @return array<int,array{name:string,ruleType:?string,ruleText:?string,srcAssetGroupId:?int,parentTagId:?int,other:array<string,string>}>
     *         keyed by tag id; ids Qualys doesn't return are simply absent
     */
    public function searchTagsByIds(array $tagIds, int $batchSize = 100): array
    {
        $tagIds = array_values(array_unique(array_filter(
            array_map(static fn ($v) => ctype_digit(trim((string)$v)) ? (int)trim((string)$v) : 0, $tagIds),
            static fn (int $v) => $v > 0
        )));
        $out = [];
        foreach (array_chunk($tagIds, max(1, $batchSize)) as $chunk) {
            $body = '<?xml version="1.0" encoding="UTF-8"?>'
                . '<ServiceRequest>'
                . '<preferences><limitResults>' . count($chunk) . '</limitResults></preferences>'
                . '<filters><Criteria field="id" operator="IN">' . implode(',', $chunk) . '</Criteria></filters>'
                . '</ServiceRequest>';
            $tmp = $this->postQpsToFile('/qps/rest/2.0/search/am/tag', $body);
            try {
                $out += $this->parseTagSearch($tmp);
            } finally {
                @unlink($tmp);
            }
        }
        return $out;
    }

    /**
     * Parse a Search Tags response. Raises on a non-SUCCESS responseCode so a
     * refused filter surfaces loudly rather than reading as "no tags".
     *
     * @return array<int,array{name:string,ruleType:?string,ruleText:?string,srcAssetGroupId:?int,parentTagId:?int,other:array<string,string>}>
     */
    private function parseTagSearch(string $path): array
    {
        $xml = \simplexml_load_file($path);
        if ($xml === false) {
            throw new \RuntimeException('Could not parse Qualys Search Tags response as XML.');
        }

        $code = isset($xml->responseCode) ? (string)$xml->responseCode : '';
        if ($code !== 'SUCCESS') {
            $detail = isset($xml->responseErrorDetails->errorMessage)
                ? (string)$xml->responseErrorDetails->errorMessage
                : '';
            throw new \RuntimeException('Qualys Search Tags returned ' . ($code !== '' ? $code : 'no responseCode') . ($detail !== '' ? ": {$detail}" : ''));
        }

        $known = ['id', 'name', 'ruleType', 'ruleText', 'srcAssetGroupId', 'parentTagId'];
        $out = [];
        if (isset($xml->data->Tag)) {
            foreach ($xml->data->Tag as $tag) {
                $id = isset($tag->id) ? (int)$tag->id : 0;
                if ($id <= 0) {
                    continue;
                }
                $other = [];
                foreach ($tag->children() as $child) {
                    $field = $child->getName();
                    // children is a nested list of child tags, not a property
                    // of this tag - nothing a classification would use.
                    if (in_array($field, $known, true) || $field === 'children' || $child->count() > 0) {
                        continue;
                    }
                    $other[$field] = trim((string)$child);
                }
                $text = static fn ($v): ?string => isset($v) && trim((string)$v) !== '' ? trim((string)$v) : null;
                $int  = static fn ($v): ?int => isset($v) && ctype_digit(trim((string)$v)) && (int)$v > 0 ? (int)$v : null;
                $out[$id] = [
                    'name'            => trim((string)($tag->name ?? '')),
                    'ruleType'        => $text($tag->ruleType ?? null),
                    'ruleText'        => $text($tag->ruleText ?? null),
                    'srcAssetGroupId' => $int($tag->srcAssetGroupId ?? null),
                    'parentTagId'     => $int($tag->parentTagId ?? null),
                    'other'           => $other,
                ];
            }
        }
        return $out;
    }

    // ------------------------------------------------------------------
    // Agent set-up (src/Lib/AgentProvisioner.php, Admin > Agent Setup)
    // ------------------------------------------------------------------

    /**
     * Caps how long a 409 wait is slept through for this instance only - the
     * Agent Setup page sets 0 so a web request fails at once with Qualys's
     * reason instead of sleeping for minutes in front of an admin.
     */
    public function setMaxRateLimitWaitSec(int $seconds): void
    {
        $this->maxRateLimitWaitSec = max(0, $seconds);
    }

    /**
     * Tags whose name CONTAINS $name (POST /qps/rest/2.0/search/am/tag). The
     * AM & Tagging docs list CONTAINS for name but don't say whether it
     * matches case-insensitively, so AgentProvisioner treats this as a
     * superset and compares names itself. Up to 1000 partial matches are
     * read; more than that throws rather than risk missing an exact match
     * on a later page.
     *
     * @return array<int, array{name:string,ruleType:?string,ruleText:?string,srcAssetGroupId:?int,parentTagId:?int,other:array<string,string>}>
     */
    public function searchTagsByNameContains(string $name): array
    {
        $body = '<?xml version="1.0" encoding="UTF-8"?>'
            . '<ServiceRequest>'
            . '<preferences><limitResults>1000</limitResults></preferences>'
            . '<filters><Criteria field="name" operator="CONTAINS">' . htmlspecialchars($name, ENT_XML1) . '</Criteria></filters>'
            . '</ServiceRequest>';
        $tmp = $this->postQpsToFile('/qps/rest/2.0/search/am/tag', $body);
        try {
            $tags = $this->parseTagSearch($tmp);
            if ($this->qpsHasMoreRecords($tmp)) {
                throw new \RuntimeException("Qualys has more than 1000 tags with names containing '{$name}' - too many to check for a duplicate safely.");
            }
            return $tags;
        } finally {
            @unlink($tmp);
        }
    }

    /**
     * Creates a static top-level tag (POST /qps/rest/2.0/create/am/tag): no
     * ruleType, so Qualys applies it only where something else puts it - here,
     * the activation key, to every agent installed with that key. Static on
     * purpose: Qualys won't attach a tag with dynamic rules to a key.
     */
    public function createStaticTag(string $name): int
    {
        $body = '<?xml version="1.0" encoding="UTF-8"?>'
            . '<ServiceRequest><data><Tag><name>' . htmlspecialchars($name, ENT_XML1) . '</name></Tag></data></ServiceRequest>';
        $tmp = $this->postQpsToFile('/qps/rest/2.0/create/am/tag', $body);
        try {
            $xml = $this->qpsSuccessXml($tmp, 'Create Tag');
            $id = isset($xml->data->Tag->id) ? (int)$xml->data->Tag->id : 0;
            if ($id <= 0) {
                throw new \RuntimeException('Qualys Create Tag returned SUCCESS but no tag id.');
            }
            return $id;
        } finally {
            @unlink($tmp);
        }
    }

    /**
     * Every activation key (POST /qps/rest/1.0/search/ca/agentactkey/), paged
     * 1000 at a time. Read in full because title isn't a filter field on this
     * search, and the duplicate-title check has to see every key.
     *
     * @return array<int, array{id: int, title: string, activation_key: string, tag_ids: int[]}>
     */
    public function listActivationKeys(): array
    {
        $out = [];
        $offset = 1;
        for ($page = 0; $page < 50; $page++) {
            $body = '<?xml version="1.0" encoding="UTF-8"?>'
                . '<ServiceRequest><preferences>'
                . '<startFromOffset>' . $offset . '</startFromOffset><limitResults>1000</limitResults>'
                . '</preferences></ServiceRequest>';
            $tmp = $this->postQpsToFile('/qps/rest/1.0/search/ca/agentactkey/', $body);
            try {
                $xml = $this->qpsSuccessXml($tmp, 'Search Activation Keys');
                $keys = $this->parseActivationKeys($xml);
                $out += $keys;
                if (!$this->qpsHasMoreRecords($tmp) || $keys === []) {
                    return $out;
                }
                $offset += count($keys);
            } finally {
                @unlink($tmp);
            }
        }
        throw new \RuntimeException('Qualys kept reporting more activation keys after 50 pages - stopped rather than loop.');
    }

    /**
     * Creates an UNLIMITED activation key that applies one tag
     * (POST /qps/rest/1.0/create/ca/agentactkey/), using the legacy XML
     * endpoint because it takes the same basic auth as every other call here;
     * the newer /caui/ endpoint needs a JWT.
     *
     * @param string[] $modules licence names from Qualys's documented list (VM_LICENSE, PC_LICENSE, ...)
     * @return array{id: int, title: string, activation_key: string, tag_ids: int[]}
     */
    public function createActivationKey(string $title, int $tagId, string $tagName, array $modules): array
    {
        $moduleXml = '';
        foreach ($modules as $module) {
            $moduleXml .= '<ActivationKeyModule><license>' . htmlspecialchars((string)$module, ENT_XML1) . '</license></ActivationKeyModule>';
        }
        $body = '<?xml version="1.0" encoding="UTF-8"?>'
            . '<ServiceRequest><data><AgentActKey>'
            . '<title>' . htmlspecialchars($title, ENT_XML1) . '</title>'
            . '<type>UNLIMITED</type>'
            . ($moduleXml !== '' ? '<modules><list>' . $moduleXml . '</list></modules>' : '')
            . '<tags><list><Tag><id>' . $tagId . '</id><name>' . htmlspecialchars($tagName, ENT_XML1) . '</name></Tag></list></tags>'
            . '</AgentActKey></data></ServiceRequest>';
        $tmp = $this->postQpsToFile('/qps/rest/1.0/create/ca/agentactkey/', $body);
        try {
            $keys = $this->parseActivationKeys($this->qpsSuccessXml($tmp, 'Create Activation Key'));
            if (count($keys) !== 1) {
                throw new \RuntimeException('Qualys Create Activation Key returned SUCCESS but ' . count($keys) . ' usable keys (expected 1).');
            }
            return reset($keys);
        } finally {
            @unlink($tmp);
        }
    }

    /** @return array{id: int, title: string, activation_key: string, tag_ids: int[]}|null */
    public function getActivationKey(int $keyId): ?array
    {
        $body = '<?xml version="1.0" encoding="UTF-8"?>'
            . '<ServiceRequest><filters><Criteria field="id" operator="EQUALS">' . $keyId . '</Criteria></filters></ServiceRequest>';
        $tmp = $this->postQpsToFile('/qps/rest/1.0/search/ca/agentactkey/', $body);
        try {
            return $this->parseActivationKeys($this->qpsSuccessXml($tmp, 'Search Activation Keys'))[$keyId] ?? null;
        } finally {
            @unlink($tmp);
        }
    }

    /** @return array{id: int, title: string, activation_key: string, tag_ids: int[]}|null */
    public function findActivationKeyByUuid(string $activationKey): ?array
    {
        $body = '<?xml version="1.0" encoding="UTF-8"?>'
            . '<ServiceRequest><filters><Criteria field="activationKey" operator="EQUALS">'
            . htmlspecialchars(strtolower(trim($activationKey)), ENT_XML1) . '</Criteria></filters></ServiceRequest>';
        $tmp = $this->postQpsToFile('/qps/rest/1.0/search/ca/agentactkey/', $body);
        try {
            $keys = array_filter(
                $this->parseActivationKeys($this->qpsSuccessXml($tmp, 'Search Activation Keys')),
                static fn (array $k): bool => $k['activation_key'] === strtolower(trim($activationKey))
            );
            return $keys !== [] ? reset($keys) : null;
        } finally {
            @unlink($tmp);
        }
    }

    /** One tag by id via Search Tags (one call), or null if Qualys has none. */
    public function getTag(int $tagId): ?array
    {
        return $this->searchTagsByIds([$tagId])[$tagId] ?? null;
    }

    /**
     * POST /qps/rest/1.0/delete/ca/agentactkey/<id>. Qualys refuses to delete
     * a key that still has active agents; that refusal is thrown as-is.
     */
    public function deleteActivationKey(int $keyId): void
    {
        $tmp = $this->postQpsToFile('/qps/rest/1.0/delete/ca/agentactkey/' . $keyId, '<?xml version="1.0" encoding="UTF-8"?><ServiceRequest></ServiceRequest>');
        try {
            $this->assertQpsSuccess($tmp, 'Delete Activation Key');
        } finally {
            @unlink($tmp);
        }
    }

    /** POST /qps/rest/2.0/delete/am/tag/<id>. Qualys removes the tag from every asset. */
    public function deleteTag(int $tagId): void
    {
        $tmp = $this->postQpsToFile('/qps/rest/2.0/delete/am/tag/' . $tagId, '<?xml version="1.0" encoding="UTF-8"?><ServiceRequest></ServiceRequest>');
        try {
            $this->assertQpsSuccess($tmp, 'Delete Tag');
        } finally {
            @unlink($tmp);
        }
    }

    /**
     * <AgentActKey> elements as id => key. A key without an id or a UUID
     * activationKey is skipped: nothing could be installed with it. Tags are
     * read from both <Tag> and <TagSimple>, since Qualys's samples use each.
     *
     * @return array<int, array{id: int, title: string, activation_key: string, tag_ids: int[]}>
     */
    private function parseActivationKeys(\SimpleXMLElement $xml): array
    {
        $out = [];
        foreach ($xml->data->AgentActKey ?? [] as $key) {
            $id = isset($key->id) ? (int)$key->id : 0;
            $uuid = strtolower(trim((string)($key->activationKey ?? '')));
            if ($id <= 0 || preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $uuid) !== 1) {
                continue;
            }
            $tagIds = [];
            foreach (['Tag', 'TagSimple'] as $el) {
                foreach ($key->tags->list->{$el} ?? [] as $tag) {
                    if (isset($tag->id) && (int)$tag->id > 0) {
                        $tagIds[] = (int)$tag->id;
                    }
                }
            }
            $out[$id] = [
                'id'             => $id,
                'title'          => trim((string)($key->title ?? '')),
                'activation_key' => $uuid,
                'tag_ids'        => array_values(array_unique($tagIds)),
            ];
        }
        return $out;
    }

    /** Parsed QPS response, or throws unless it says SUCCESS - see assertQpsSuccess(). */
    private function qpsSuccessXml(string $path, string $what): \SimpleXMLElement
    {
        $this->assertQpsSuccess($path, $what);
        return \simplexml_load_file($path);
    }

    private function qpsHasMoreRecords(string $path): bool
    {
        $xml = @\simplexml_load_file($path);
        return $xml !== false && strtolower(trim((string)($xml->hasMoreRecords ?? ''))) === 'true';
    }

    /**
     * @param array<int,int> $assetViewIds AssetView asset ids to uninstall
     * @param string|null $tagGuard when set, ANDs a
     *        <Criteria field="tagName" operator="EQUALS">{tag}</Criteria> onto
     *        the request. This is Qualys's own recommended blast-radius guard:
     *        with it, the request can only ever act on hosts carrying that tag
     *        (all Cloud Agent hosts carry the built-in "Cloud Agent" tag), so
     *        even a wrong id can't uninstall something untagged. AND semantics
     *        mean the effective target is (id IN list) AND (tagName = guard).
     */
    public function buildUninstallRequestXml(array $assetViewIds, ?string $tagGuard = null): string
    {
        $ids = array_values(array_unique(array_filter(array_map('intval', $assetViewIds), static fn ($v) => $v > 0)));
        $criteria = '<Criteria field="id" operator="IN">' . implode(',', $ids) . '</Criteria>';
        if ($tagGuard !== null && trim($tagGuard) !== '') {
            // htmlspecialchars so a tag name with & or < can't break the XML.
            $criteria .= '<Criteria field="tagName" operator="EQUALS">'
                . htmlspecialchars(trim($tagGuard), ENT_XML1) . '</Criteria>';
        }
        return '<?xml version="1.0" encoding="UTF-8"?>'
            . '<ServiceRequest><filters>' . $criteria . '</filters></ServiceRequest>';
    }

    /**
     * Uninstall Cloud Agents in bulk by AssetView asset id, in a single API
     * call (POST /qps/rest/2.0/uninstall/am/asset/). Returns the list of asset
     * ids Qualys reported it acted on (from <data><Asset><id> in the response),
     * so the caller can mark exactly those as done and treat any requested-but-
     * not-returned id as not-actually-uninstalled rather than assuming success.
     *
     * IMPORTANT - this is destructive: per Qualys's docs a successful call
     * purges the hosts' scan data (findings) and removes the agent hosts from
     * the subscription. The fo credentials used must carry the "Uninstall
     * Agent" CA permission (or be a full-scope Manager) or Qualys returns a
     * permissions error.
     *
     * @param array<int,int> $assetViewIds
     * @return int[] the asset ids Qualys confirmed (may be a subset of input)
     */
    public function uninstallAgentsByAssetIds(array $assetViewIds, ?string $tagGuard = null): array
    {
        $ids = array_values(array_unique(array_filter(array_map('intval', $assetViewIds), static fn ($v) => $v > 0)));
        if ($ids === []) {
            return [];
        }
        $body = $this->buildUninstallRequestXml($ids, $tagGuard);
        $tmp = $this->postQpsToFile('/qps/rest/2.0/uninstall/am/asset/', $body);
        try {
            return $this->parseUninstallResponse($tmp);
        } finally {
            @unlink($tmp);
        }
    }

    /**
     * @return int[] asset ids from <data><Asset><id> in an uninstall response.
     */
    private function parseUninstallResponse(string $path): array
    {
        $xml = \simplexml_load_file($path);
        if ($xml === false) {
            throw new \RuntimeException('Could not parse Qualys uninstall response as XML.');
        }

        $code = isset($xml->responseCode) ? (string)$xml->responseCode : '';
        if ($code !== 'SUCCESS') {
            $detail = isset($xml->responseErrorDetails->errorMessage)
                ? (string)$xml->responseErrorDetails->errorMessage
                : '';
            throw new \RuntimeException("Qualys uninstall returned {$code}" . ($detail !== '' ? ": {$detail}" : ''));
        }

        $out = [];
        if (isset($xml->data->Asset)) {
            foreach ($xml->data->Asset as $asset) {
                if (isset($asset->id)) {
                    $out[] = (int)$asset->id;
                }
            }
        }
        return $out;
    }

    /**
     * On-demand scan types the Cloud Agent API accepts in ?scan= - from
     * Qualys's "Launch On Demand Scan for Multiple Asset" page. Anything else
     * is refused here rather than sent.
     */
    private const ON_DEMAND_SCAN_TYPES = ['Inventory_Scan', 'Vulnerability_Scan', 'PolicyCompliance_Scan', 'UDC_Scan', 'SCA_Scan', 'SWCA_scan'];

    /**
     * Asks Cloud Agents to run a scan now, for many agents in ONE call
     * (POST /qps/rest/1.0/ods/ca/agentasset?scan=...&overrideConfigCpu=...).
     * Qualys documents this endpoint only under /qps/rest/1.0/, so unlike the
     * fo endpoints there is no other API version to rotate across: every
     * send counts against the same 25-per-24h limit, whatever its size.
     *
     * Targets AssetView asset ids, the same ids and the same filter body as
     * uninstallAgentsByAssetIds() (buildUninstallRequestXml()), including the
     * tagName guard. Qualys's documented example filters by tagName only;
     * the id IN criterion is the one the uninstall API takes and is assumed,
     * not yet confirmed, to work here too - if Qualys rejects it, the call
     * fails loudly below and the worker retries and then fails the requests.
     *
     * Qualys's response to a bulk launch doesn't list the assets it acted on
     * (unlike an uninstall), so SUCCESS covers the whole request. Results
     * arrive later through the normal host detection sync, once each agent
     * has scanned and uploaded and Qualys has processed the results.
     *
     * $overrideConfigCpu true ignores the agents' configuration-profile CPU
     * throttle for this scan; false (Qualys's default) keeps it.
     *
     * @param int[] $assetViewIds
     */
    public function launchOnDemandScanByAssetIds(array $assetViewIds, string $scanType = 'Vulnerability_Scan', bool $overrideConfigCpu = false, ?string $tagGuard = null): void
    {
        $ids = array_values(array_unique(array_filter(array_map('intval', $assetViewIds), static fn ($v) => $v > 0)));
        if ($ids === []) {
            return;
        }
        if (!in_array($scanType, self::ON_DEMAND_SCAN_TYPES, true)) {
            throw new \InvalidArgumentException("Unsupported on-demand scan type '{$scanType}' - expected one of: " . implode(', ', self::ON_DEMAND_SCAN_TYPES) . '.');
        }
        $path = '/qps/rest/1.0/ods/ca/agentasset?' . http_build_query([
            'scan'              => $scanType,
            'overrideConfigCpu' => $overrideConfigCpu ? 'true' : 'false',
        ]);
        $tmp = $this->postQpsToFile($path, $this->buildUninstallRequestXml($ids, $tagGuard));
        try {
            $this->assertQpsSuccess($tmp, 'on-demand scan');
        } finally {
            @unlink($tmp);
        }
    }

    /**
     * Raises unless a QPS response says SUCCESS. A body that isn't XML at
     * all is a failure too - SUCCESS has to be stated, not assumed.
     */
    private function assertQpsSuccess(string $path, string $what): void
    {
        $xml = @\simplexml_load_file($path);
        if ($xml === false) {
            throw new \RuntimeException("Could not parse Qualys {$what} response as XML.");
        }
        $code = isset($xml->responseCode) ? (string)$xml->responseCode : '';
        if ($code !== 'SUCCESS') {
            $detail = isset($xml->responseErrorDetails->errorMessage)
                ? (string)$xml->responseErrorDetails->errorMessage
                : '';
            throw new \RuntimeException("Qualys {$what} returned " . ($code !== '' ? $code : 'no responseCode') . ($detail !== '' ? ": {$detail}" : ''));
        }
    }

    /**
     * @param array<string, string> $headers lower-cased header name => value
     * @return array{limit: ?int, remaining: ?int, window_sec: ?int, to_wait_sec: ?int}|null
     */
    private function extractRateLimitInfo(array $headers): ?array
    {
        // Qualys's docs show both "X-RateLimit-Limit" and (older docs)
        // "X-Concurrency-Limit-Limit" vs "X-ConcurrencyLimit-Limit" -
        // reading defensively rather than assuming one exact casing/dash
        // pattern holds across every subscription/API version.
        $get = function (array $keys) use ($headers): ?string {
            foreach ($keys as $key) {
                if (isset($headers[$key])) {
                    return $headers[$key];
                }
            }
            return null;
        };

        $limit     = $get(['x-ratelimit-limit']);
        $remaining = $get(['x-ratelimit-remaining']);
        $window    = $get(['x-ratelimit-window-sec']);
        $toWait    = $get(['x-ratelimit-towait-sec']);

        if ($limit === null && $remaining === null) {
            // Per Qualys's docs, a pure concurrency-limit block can come
            // back with none of these headers at all.
            return null;
        }

        return [
            'limit'       => $limit !== null ? (int)$limit : null,
            'remaining'   => $remaining !== null ? (int)$remaining : null,
            'window_sec'  => $window !== null ? (int)$window : null,
            'to_wait_sec' => $toWait !== null ? (int)$toWait : null,
        ];
    }

    // ------------------------------------------------------------------
    // Call budget (see the class docblock's "Rate/concurrency limits")
    // ------------------------------------------------------------------

    /**
     * Qualys counts calls per endpoint per API version - confirmed
     * 2026-10-17: one Host Detection call and then one KnowledgeBase call on
     * /api/5.0/ each came back 24/25, and earlier the same day Host
     * Detection hit 0 on /api/4.0/ while Host List on /api/4.0/ never went
     * below 6. So the key is the request path without its query string,
     * e.g. '/api/4.0/fo/asset/host/vm/detection/'. Continuation pages share
     * their first page's path, so they land on the same key. QPS paths
     * (/qps/rest/...) are used as-is, less any trailing record id.
     */
    private function budgetKeyForUrl(string $url): string
    {
        // A trailing record id (the delete calls: .../agentactkey/59001) is
        // dropped, so every delete shares one key and one API usage row.
        return (string)preg_replace('#/\d+$#', '/', (string)parse_url($url, PHP_URL_PATH));
    }

    /**
     * The version as stored in qualys_api_call_log.api_version: '2.0',
     * '3.0', '4.0'..., or 'QPS' - logged alongside the endpoint, so the API
     * usage page can show each endpoint-and-version pair, which is how
     * Qualys counts them.
     */
    private function apiVersionForBudgetKey(string $budgetKey): string
    {
        return preg_match('#^/api/([^/]+)/#', $budgetKey, $m) ? $m[1] : 'QPS';
    }

    /**
     * Throws, without making the request, when Qualys has told us to wait
     * until a time not yet reached, or when the estimated calls left on
     * this version are at or below the reserve.
     */
    private function assertCallBudget(string $budgetKey): void
    {
        $state = $this->readBudgetState()[$budgetKey] ?? null;
        if (!is_array($state)) {
            return;
        }
        $now = time();

        $blockedUntil = isset($state['blocked_until']) ? (int)$state['blocked_until'] : 0;
        if ($blockedUntil > $now) {
            throw new \RuntimeException(sprintf(
                'Qualys API rate limit on %s is exhausted - Qualys asked for no further calls until %s (%s from now), so this request was not sent.',
                $budgetKey,
                date('Y-m-d H:i', $blockedUntil),
                self::formatDuration($blockedUntil - $now)
            ));
        }

        $remaining = isset($state['remaining']) ? (int)$state['remaining'] : null;
        $window    = isset($state['window_sec']) ? (int)$state['window_sec'] : 0;
        if ($this->minCallsReserve <= 0 || $remaining === null || $window <= 0) {
            return;
        }

        // Qualys's window is rolling, so calls already counted against
        // "remaining" when it was reported are credited back as they age
        // out - otherwise one low reading would block for a whole window.
        $reportedAt = (int)($state['reported_at'] ?? 0);
        $calls = array_map('intval', is_array($state['calls'] ?? null) ? $state['calls'] : []);
        $freed = 0;
        $nextFree = null;
        foreach ($calls as $t) {
            if ($t <= $reportedAt && $t > $reportedAt - $window && $t <= $now - $window) {
                $freed++;
            }
            if ($t > $now - $window) {
                $nextFree = $nextFree === null ? $t + $window : min($nextFree, $t + $window);
            }
        }
        $estimate = $remaining + $freed;
        if (isset($state['limit'])) {
            $estimate = min($estimate, (int)$state['limit']);
        }

        if ($estimate <= $this->minCallsReserve) {
            throw new \RuntimeException(sprintf(
                'Qualys API call budget on %s is down to an estimated %d%s per %s, at or below the %d-call reserve (qualys.min_calls_reserve), so this request was not sent.%s Set VULNDASH_IGNORE_CALL_RESERVE=1 to spend the reserve on a one-off manual run.',
                $budgetKey,
                $estimate,
                isset($state['limit']) ? ' of ' . (int)$state['limit'] : '',
                self::formatDuration($window),
                $this->minCallsReserve,
                $nextFree !== null ? ' The next call frees up around ' . date('Y-m-d H:i', $nextFree) . ' (' . self::formatDuration($nextFree - $now) . ' from now).' : ''
            ));
        }
    }

    /**
     * Records one call that actually reached Qualys, plus whatever
     * rate-limit headers came back with it.
     *
     * @param array{limit: ?int, remaining: ?int, window_sec: ?int, to_wait_sec: ?int}|null $rateInfo
     */
    private function recordCallBudget(string $budgetKey, ?array $rateInfo, int $httpCode): void
    {
        $this->updateBudgetState(function (array $all) use ($budgetKey, $rateInfo, $httpCode): array {
            $now = time();
            $state = is_array($all[$budgetKey] ?? null) ? $all[$budgetKey] : [];

            if ($rateInfo !== null) {
                $state['limit']       = $rateInfo['limit'];
                $state['remaining']   = $rateInfo['remaining'];
                $state['window_sec']  = $rateInfo['window_sec'] ?? ($state['window_sec'] ?? null);
                $state['reported_at'] = $now;
            }

            $toWait = $rateInfo['to_wait_sec'] ?? null;
            if ($httpCode === 409 && $toWait !== null && $toWait > 0) {
                $state['blocked_until'] = $now + $toWait;
            } elseif ($httpCode !== 409) {
                // Any accepted call proves the block (if one was recorded) is over.
                unset($state['blocked_until']);
            }

            $keepSec = max(1, (int)($state['window_sec'] ?? 86400));
            $calls = array_map('intval', is_array($state['calls'] ?? null) ? $state['calls'] : []);
            $calls[] = $now;
            $calls = array_values(array_filter($calls, static fn(int $t): bool => $t > $now - $keepSec));
            $state['calls'] = array_slice($calls, -self::BUDGET_MAX_TRACKED_CALLS);

            $all[$budgetKey] = $state;
            return $all;
        });
    }

    private function rateLimitExhaustedMessage(string $budgetKey, int $waitSec): string
    {
        $info = $this->lastRateLimitInfo;
        $usage = '';
        if ($info !== null && $info['remaining'] !== null && $info['limit'] !== null) {
            $usage = ", {$info['remaining']} of {$info['limit']} calls left"
                . ($info['window_sec'] !== null ? ' per ' . self::formatDuration($info['window_sec']) : '');
        }

        return sprintf(
            'Qualys API rate limit exhausted on %s (HTTP 409%s): Qualys allows the next call in %s (around %s), longer than the %ds this run will wait (qualys.max_rate_limit_wait_sec) - failing now rather than sleeping.',
            $budgetKey,
            $usage,
            self::formatDuration($waitSec),
            date('Y-m-d H:i', time() + $waitSec),
            $this->maxRateLimitWaitSec
        );
    }

    private static function budgetStatePath(): string
    {
        return sys_get_temp_dir() . '/' . self::BUDGET_STATE_FILE;
    }

    /** @return array<string, mixed> */
    private function readBudgetState(): array
    {
        $path = self::budgetStatePath();
        if (!is_file($path)) {
            return [];
        }
        $fh = @fopen($path, 'r');
        if ($fh === false) {
            self::warn("Could not read {$path} - check its ownership/permissions; the call reserve is not being enforced.");
            return [];
        }
        try {
            flock($fh, LOCK_SH);
            $data = json_decode((string)stream_get_contents($fh), true);
            return is_array($data) ? $data : [];
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }

    /** @param callable(array<string, mixed>): array<string, mixed> $mutate */
    private function updateBudgetState(callable $mutate): void
    {
        $path = self::budgetStatePath();
        // 'r+' when the file exists: Ubuntu's fs.protected_regular refuses
        // an O_CREAT open ('c+') of another user's file in sticky /tmp, even
        // for root, so a manual root run would otherwise fail to record.
        $fh = is_file($path) ? @fopen($path, 'r+') : @fopen($path, 'c+');
        if ($fh === false) {
            self::warn("Could not write {$path} - check its ownership/permissions; the call reserve is not being enforced.");
            return;
        }
        // Same reason as the sync scripts' lock files: root (manual runs)
        // and www-data (cron) must both be able to use it.
        @chmod($path, 0666);
        try {
            flock($fh, LOCK_EX);
            $data = json_decode((string)stream_get_contents($fh), true);
            $data = $mutate(is_array($data) ? $data : []);
            ftruncate($fh, 0);
            rewind($fh);
            fwrite($fh, (string)json_encode($data));
            fflush($fh);
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }

    private static function warn(string $message): void
    {
        if (defined('STDERR')) {
            fwrite(STDERR, "Warning: {$message}\n");
        }
    }

    private static function formatDuration(int $seconds): string
    {
        $seconds = max(0, $seconds);
        if ($seconds < 60) {
            return "{$seconds}s";
        }
        $h = intdiv($seconds, 3600);
        $m = intdiv($seconds % 3600, 60);
        if ($h === 0) {
            return "{$m}m";
        }
        return $m === 0 ? "{$h}h" : "{$h}h {$m}m";
    }

    /**
     * Qualys returns HTTP 200 with a <SIMPLE_RETURN> error body for a lot
     * of request-validation failures (bad/unsupported parameters, etc.)
     * rather than a non-2xx status - the "Unrecognized parameter" error
     * hit while building this class (truncation_limit against the KB
     * endpoint) is a real example of exactly this shape.
     */
    private function throwIfQualysErrorBody(string $path, int $httpCode): void
    {
        $head = file_get_contents($path, false, null, 0, 4096);
        if ($head === false || !str_contains($head, '<SIMPLE_RETURN>')) {
            return;
        }

        $full = file_get_contents($path); // safe - error bodies are always small
        try {
            $xml = new \SimpleXMLElement((string)$full);
            $code = isset($xml->RESPONSE->CODE) ? (string)$xml->RESPONSE->CODE : null;
            $text = isset($xml->RESPONSE->TEXT) ? (string)$xml->RESPONSE->TEXT : null;
        } catch (\Throwable $e) {
            $code = null;
            $text = null;
        }

        if ($code !== null) {
            throw new \RuntimeException("Qualys API returned error {$code} (HTTP {$httpCode}): {$text}");
        }
    }

    /**
     * Host List Detection truncates and signals the next page via a
     * <WARNING><CODE>1980</CODE>...<URL>...</URL></WARNING> block right at
     * the end of <RESPONSE> - a cheap tail-read is enough, no need to
     * re-scan a potentially huge file from the start.
     */
    private function extractContinuationUrl(string $path): ?string
    {
        $size = filesize($path);
        if ($size === false) {
            return null;
        }
        $tailSize = (int)min($size, 8192);
        $tail = file_get_contents($path, false, null, max(0, $size - $tailSize));
        if ($tail === false) {
            return null;
        }

        if (preg_match('/<CODE>1980<\/CODE>.*?<URL><!\[CDATA\[(.*?)\]\]><\/URL>/s', $tail, $m)) {
            return html_entity_decode($m[1]);
        }

        return null;
    }

    private function toQualysDatetime(\DateTimeImmutable $dt): string
    {
        return $dt->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
    }

    /**
     * Strips the query string and the /api/{version} prefix from a full
     * request URL, leaving just the logical endpoint path - e.g.
     * '/fo/asset/host/vm/detection/' regardless of API version or which
     * page of a paginated pull this was. Continuation URLs (page 2+ of a
     * Host List Detection pull) come from Qualys's own <URL> field in the
     * truncation warning, which is a full API URL matching the same
     * /api/{version}/... shape as this class's own requests, so this
     * normalizes those the same way without needing to special-case them.
     */
    private function endpointFromUrl(string $url): string
    {
        $path = (string)parse_url($url, PHP_URL_PATH);
        return (string)preg_replace('#^/api/[^/]+#', '', $path);
    }

    private function toMysqlDatetime(?string $iso): ?string
    {
        if ($iso === null || trim($iso) === '') {
            return null;
        }
        $ts = strtotime($iso);
        if ($ts === false) {
            return null;
        }
        return gmdate('Y-m-d H:i:s', $ts);
    }

    /**
     * Folds Qualys's per-detection <TYPE> into the single vocabulary this app
     * stores in host_detections.detection_type: 'Confirmed', 'Potential' or
     * 'Info'.
     *
     * Qualys's Host List Detection response uses the terse codes 'Vuln',
     * 'Practice' and 'Ig' (confirmed against real data - NOT the longer
     * 'Confirmed'/'Potential'/'Information Gathered' spellings its
     * documentation sometimes shows, which the KnowledgeBase VULN_TYPE field
     * uses instead). Both spellings are accepted here, case-insensitively, so
     * this keeps working whichever a given endpoint/version happens to return.
     *
     * An empty value returns null (no type on file - the UI shows no chip).
     * An unrecognised non-empty value is passed through trimmed rather than
     * dropped, so a genuinely new Qualys code shows up verbatim for
     * investigation instead of silently vanishing.
     */
    private function normaliseDetectionType(?string $raw): ?string
    {
        if ($raw === null) {
            return null;
        }
        $value = trim($raw);
        if ($value === '') {
            return null;
        }
        switch (strtolower($value)) {
            case 'vuln':
            case 'confirmed':
            case 'vulnerability':
                return 'Confirmed';
            case 'practice':
            case 'potential':
            case 'potential vulnerability':
                return 'Potential';
            case 'ig':
            case 'info':
            case 'information gathered':
            case 'information gathering':
                return 'Info';
            default:
                return $value;
        }
    }

    /**
     * Maps Host List's tracking-method value onto the same terse codes
     * Host List Detection already uses everywhere else in this app
     * ('AGENT', 'IP', 'DNS', ...) - the two endpoints apparently don't
     * agree on format for the same underlying concept, the same kind of
     * inconsistency this class already hit once before with <TAGS> vs
     * <TAG_LIST>.
     *
     * Confirmed 2026-07 against a real response: Host List returned
     * "Cloud Agent" for a host that Host List Detection elsewhere reports
     * as tracking_method "AGENT" - real evidence, not a guess, which is
     * exactly why this fixes only that one mapping rather than trying to
     * anticipate every other possible value. This mattered in practice,
     * not just in theory: an unmapped "Cloud Agent" used to silently
     * disqualify an obviously agent-tracked host from every tag it
     * carried in UserRepository's former tag_type classification (removed
     * 2026-07 along with the Agent Tags/Scans split, once this became an
     * agent-only tool) - that logic required an exact 'AGENT' match, so a
     * raw "Cloud Agent" value caused a real Agent Tags -> Scans
     * misclassification. tracking_method is still stored and still shown
     * in diagnostics (reconcile_asset_inventory.php, diagnose_tags.php),
     * so this normalization still matters for accuracy even without that
     * classification consuming it any more. Anything not in this map
     * passes through unchanged rather than being guessed at - if another
     * mismatch like this turns up, add it here once it's confirmed the
     * same way, not before.
     */
    private function normalizeTrackingMethod(?string $raw): ?string
    {
        if ($raw === null) {
            return null;
        }
        $map = [
            'Cloud Agent' => 'AGENT',
        ];
        return $map[$raw] ?? $raw;
    }

    /**
     * A host's <ASSET_ID> (the AssetView id), present only when the pull
     * sent show_asset_id=1. Null when absent, empty or not a positive
     * number, so HostSyncWriter keeps whatever id is already stored rather
     * than overwriting it with nothing.
     */
    private function parseAssetId(\SimpleXMLElement $host): ?int
    {
        if (!isset($host->ASSET_ID)) {
            return null;
        }
        $raw = trim((string)$host->ASSET_ID);
        return ctype_digit($raw) && (int)$raw > 0 ? (int)$raw : null;
    }
}
