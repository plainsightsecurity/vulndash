<?php
declare(strict_types=1);

// Test-suite configuration, loaded instead of src/config/config.php via the
// VULNDASH_CONFIG environment variable (set by tests/run.sh). The database
// is always the disposable vulndash_test; Qualys points at a closed local
// port so a test can never reach the real API.
return [
    'app' => ['name' => 'VulnDash (tests)', 'base_url' => 'https://dashboard.test'],
    'db' => [
        'host'     => getenv('DB_HOST') ?: '127.0.0.1',
        'port'     => (int)(getenv('DB_PORT') ?: 3306),
        'name'     => 'vulndash_test',
        'user'     => getenv('DB_USER') ?: 'root',
        'password' => getenv('DB_PASS') ?: '',
    ],
    'security' => ['mfa_encryption_key' => base64_encode(str_repeat('k', 32))],
    'resend'   => ['api_key' => ''],
    // Disk alerts at 99% so this machine's real disk space can't add an email
    // to tests that run scripts/send_sync_alerts.php; ServerHealthTest sets
    // its own threshold and figures.
    'alerts'   => ['disk_warn_percent' => 99],
    'qualys' => [
        'api_base_url' => 'http://127.0.0.1:9',
        'username' => 'test', 'password' => 'test',
        'api_version' => '4.0',
        'agent_scope_tag' => 'Cloud Agent',
        'excluded_tags' => [],
    ],
];
