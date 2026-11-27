<?php
declare(strict_types=1);

/**
 * Example configuration - copy to src/config/config.php and fill in the
 * secrets. config.php itself is git-ignored and must never be committed.
 *
 *   cp src/config/config.example.php src/config/config.php
 *   chown www-data:www-data src/config/config.php && chmod 640 src/config/config.php
 *
 * Every setting the code reads is listed here. Anything left out of
 * config.php falls back to the default noted beside it (the code's own
 * `?? default`), so only the secrets and the Qualys connection details are
 * strictly required. Where a value differs from the code default, the
 * comment gives the default and the reason for the change.
 *
 * Read through VulnDash\Lib\Config::get('section.key').
 */
return [

    'app' => [
        'name'     => 'Vulnerability Management Dashboard',
        'base_url' => 'https://dashboard.plainsightsecurity.co.uk', // used in emailed links
    ],

    'db' => [
        'host'     => '127.0.0.1',
        'port'     => 3306,
        'name'     => 'vulndash',
        'user'     => 'vulndash_app',
        'password' => 'CHANGE-ME',
    ],

    // Sign-in timeouts and session storage - see src/Lib/SessionTimeout.php.
    // The save_path directory must exist and be writable by www-data:
    //   sudo install -d -o www-data -g www-data -m 0700 /var/lib/vulndash/sessions
    // Without it sessions fall back to PHP's default directory, where Ubuntu's
    // sessionclean cron signs users out after 24-54 minutes idle.
    'session' => [
        'save_path'                => '/var/lib/vulndash/sessions',
        'idle_timeout_minutes'     => 480,  // 8 hours with no requests
        'absolute_timeout_minutes' => 720,  // 12 hours after sign-in, however active; 0 = off
    ],

    'security' => [
        // 32 random bytes, base64 - encrypts stored TOTP secrets. Generate with:
        //   php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
        // Changing it later invalidates every enrolled MFA device.
        'mfa_encryption_key' => 'CHANGE-ME',
    ],

    'resend' => [
        'api_key'    => 'CHANGE-ME',                       // empty = emails are logged, not sent
        'api_base'   => 'https://api.resend.com',
        'from_email' => 'dashboard@plainsightsecurity.co.uk',
        'from_name'  => 'VulnDash',
    ],

    'qualys' => [
        // --- connection ------------------------------------------------------
        'api_base_url' => 'https://qualysapi.qg1.apps.qualys.co.uk',
        'username'     => 'CHANGE-ME',
        'password'     => 'CHANGE-ME',
        'api_version'  => '4.0',

        // --- which hosts / tags count ------------------------------------------
        'agent_scope_tag' => 'Cloud Agent',  // only hosts carrying this tag are pulled
        'excluded_tags'   => [],             // tag names stripped from hosts (never scope an account)
        'tag_rule_refresh_hours' => 24,      // re-check Qualys tag rule types (IP-based tags never scope)

        // --- API call budgeting ------------------------------------------------
        // Each endpoint + API version has its own 25 calls / 24h counter on the
        // current licence, so calls are spread round-robin across versions.
        'host_detection_api_versions' => ['2.0', '3.0', '4.0', '5.0'], // default ['2.0','3.0','4.0']
        'kb_api_versions'             => ['2.0', '3.0', '4.0', '5.0'], // default ['2.0','3.0','4.0']
        'reconcile_api_versions'      => ['2.0', '3.0', '4.0', '5.0'], // default: reconcile_api_version below
        // 'reconcile_api_version'    => '4.0',  // older single-version setting; default api_version
        'min_calls_reserve'        => 3,     // stop before a version's remaining calls drop to this
        'daily_call_limit'         => 25,    // per endpoint per version per 24h, used until Qualys reports its own
        'max_rate_limit_wait_sec'  => 300,   // longest wait for a rate-limit window before giving up
        'host_page_size'           => 5000,  // hosts per page (default 1000; 5000 = fewer calls)

        // --- host detection sync ------------------------------------------------
        'host_detection_incremental_filter' => 'vm_processed_after',
        'host_detection_overlap_minutes'    => 60,
        'host_list_new_host_pass'           => true,  // Host List pass to catch hosts with no detections
        'host_list_pass_interval_minutes'   => 60,    // default 0 = every run; 60 with the 30-min sync
        'host_list_prune_missing'           => true,
        'show_asset_id'                     => true,  // default false; ask Qualys for ASSET_ID (scans/uninstall)
        'reconcile_max_removal_percent'     => 50,    // safety brake on bulk deletes / clears

        // --- knowledge base sync -------------------------------------------------
        'kb_incremental_overlap_minutes' => 1440,     // default 60; 24h catches late-modified QIDs
        'kb_max_records_per_window'      => 1900,     // default 100; Qualys truncates silently above ~2000
        'kb_planned_piece_fill'          => 0.45,     // 0 disables the planned QID-range pieces
        'kb_backfill_chunk_days'         => 90,
        'kb_call_delay_ms'               => 300,
        'kb_id_range_batch_width'        => 5000,
        'kb_id_range_hard_ceiling'       => 0,        // 0 = no ceiling for the sync; reconcile/find_max default 3,000,000
        'kb_new_qid_fastpath_enabled'    => true,
        'kb_new_qid_fastpath_span'       => 1000000,

        // --- on-demand scans (Cloud Agent ODS) -----------------------------------
        'ods_scan_type'              => 'Vulnerability_Scan',
        'ods_override_cpu'           => false,
        'ods_daily_budget'           => 22,   // scan requests sent per day
        'ods_min_interval_minutes'   => 10,   // gap between send batches
        'ods_burst'                  => 6,    // sends allowed close together before pacing spreads the rest of the day's budget (0 = off)
        'ods_asset_cooldown_minutes' => 60,   // per-asset cooldown for non-admins

        // --- Agent Setup (Admin > Agent Setup, src/Lib/AgentProvisioner.php) ----
        // Licences new client activation keys are provisioned for. Default VM only.
        // 'activation_key_modules'     => ['VM_LICENSE'],
    ],

    // Admin alert emails (src/Lib/ApiBudgetAlerts.php): Qualys API budget low,
    // forecast over the limit, or the host sync's auto interval changing.
    'alerts' => [
        // 'admin_emails'           => ['mark@plainsightsecurity.co.uk'], // default: every active admin
        'api_budget_low_threshold'  => 5,   // default 5 calls left on an endpoint + version
        'ods_busy_calls'            => 18,  // email when on-demand scan calls in 24h reach this (0 = off)
    ],

    'sync' => [
        'resolution_retention_days' => 90,
        'kb_missing_warn_hours'     => 36,    // admin warning when a missing KB QID stays unfetched
        // Only used to flag a sync "overdue" on the dashboard (2x slack applied).
        // Set these to match the crontab: KB sync twice daily, host sync every 30 min.
        'knowledge_base_expected_interval_minutes'  => 720,  // default 1440
        'host_detections_expected_interval_minutes' => 30,   // default 180

        // Auto interval (src/Lib/ApiBudget.php): cron runs the host sync every
        // host_detection_cron_minutes; each run picks the shortest of
        // host_detection_auto_intervals whose forecast fits the Qualys limit
        // and skips itself until then. Must match the crontab.
        'host_detection_auto_interval'  => true,              // default true
        'host_detection_cron_minutes'   => 30,                // default 30
        'host_detection_auto_intervals' => [30, 60, 120, 240], // default
        'reconcile_runs_per_day'        => 4,                 // default 4 (40 0,6,12,18)
    ],

    'audit' => [
        'retention_days' => 365,              // Audit Log rows older than this are pruned
    ],

    // History tables pruned daily by scripts/prune_history.php
    // (src/Lib/HistoryPruner.php). Values below a table's minimum are raised
    // to it, so the pages that read these tables always have their data.
    'retention' => [
        'api_call_log_days'  => 90,   // default 90, minimum 30 (API Usage page shows 30 days)
        'sync_log_days'      => 90,   // default 90, minimum 7; latest + last successful run per sync always kept
        'scan_request_days'  => 90,   // default 90, minimum 7; sent/failed requests only
        'vuln_snapshot_days' => 400,  // default 400, minimum 90 (Trends 90-day window)
    ],

    'assets' => [
        'stale_after_days' => 7,              // "not reporting" threshold for agents
    ],

    'exploit_intel' => [
        'kev_url'          => 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        'epss_url'         => 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz',
        'user_agent'       => 'Plainsight VulnDash exploit-intel sync',
        'http_timeout_sec' => 120,
    ],

    'risk_score' => [
        'weight_critical'      => 40.0,
        'weight_high'          => 10.0,
        'weight_medium'        => 3.0,
        'weight_low'           => 1.0,
        'kev_multiplier'       => 5.0,
        'epss_high_threshold'  => 0.5,
        'epss_high_multiplier' => 3.0,
        'epss_med_threshold'   => 0.1,
        'epss_med_multiplier'  => 1.5,
        'saturation_k'         => 15.0,
    ],
];
