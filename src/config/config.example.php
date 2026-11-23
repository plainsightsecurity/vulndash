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
        'ods_asset_cooldown_minutes' => 60,   // per-asset cooldown for non-admins
    ],

    'sync' => [
        'resolution_retention_days' => 90,
        'kb_missing_warn_hours'     => 36,    // admin warning when a missing KB QID stays unfetched
        // Only used to flag a sync "overdue" on the dashboard (2x slack applied).
        // Set these to match the crontab: KB sync twice daily, host sync every 30 min.
        'knowledge_base_expected_interval_minutes'  => 720,  // default 1440
        'host_detections_expected_interval_minutes' => 30,   // default 180
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
