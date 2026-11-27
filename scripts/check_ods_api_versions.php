#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Manual check: does the Cloud Agent on-demand scan endpoint answer on API
 * versions Qualys doesn't document? It is documented only as
 * /qps/rest/1.0/ods/ca/agentasset, but undocumented versions do turn up from
 * time to time, and each one would bring its own 25-per-24h counter that
 * scripts/process_scan_requests.php could rotate across, as the fo syncs do.
 *
 * Safe to run: each probe is the real bulk-launch request, but its criteria
 * are a tag name made up for this run AND asset id 0, so no agent can match
 * and nothing is scanned. (Even a version that somehow ignored both would
 * only start an early scan - nothing destructive - but two independent
 * no-match criteria make that very unlikely.)
 *
 * What the answers look like (2026-11-10): 1.0, the version in use, answered
 * HTTP 200 SUCCESS to this no-match request. 2.0 to 7.0 each answered HTTP
 * 400 INVALID_API_VERSION ("does not support objects of type agentasset") -
 * a version without this endpoint. A 404 or a non-QPS page means the same.
 * Anything else is reported as EXISTS for a look by eye; the raw status,
 * responseCode, message and any rate-limit headers are always printed.
 *
 * Cost: one call per version probed, each against that version's own
 * counter (if it has one). 1.0, the version in use, is skipped unless you
 * name it, so the production budget isn't touched by default. Calls are
 * written to qualys_api_call_log, so they show on the API usage page.
 *
 * Read-only otherwise: no queue, sync_state or lock is touched, so it can
 * run alongside the cron jobs.
 *
 * Usage:
 *   php scripts/check_ods_api_versions.php                       # 2.0, 3.0, 4.0, 5.0
 *   php scripts/check_ods_api_versions.php --versions=2.0,6.0
 *   php scripts/check_ods_api_versions.php --versions=1.0         # baseline: what a working version looks like
 */

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;

$versions = ['2.0', '3.0', '4.0', '5.0'];
foreach ($argv as $arg) {
    if (preg_match('/^--versions=([0-9.,]+)$/', $arg, $m)) {
        $versions = array_values(array_filter(explode(',', $m[1]), static fn ($v) => preg_match('/^\d+\.\d+$/', $v) === 1));
    }
}
if ($versions === []) {
    fwrite(STDERR, "No valid versions given - use e.g. --versions=2.0,3.0\n");
    exit(1);
}

$baseUrl  = rtrim((string)Config::get('qualys.api_base_url'), '/');
$username = (string)Config::get('qualys.username');
$password = (string)Config::get('qualys.password');

// A tag no agent can carry, unique to this run.
$noSuchTag = 'vulndash-version-probe-' . bin2hex(random_bytes(6));
$body = '<?xml version="1.0" encoding="UTF-8"?>'
    . '<ServiceRequest><filters>'
    . '<Criteria field="tagName" operator="EQUALS">' . $noSuchTag . '</Criteria>'
    . '<Criteria field="id" operator="EQUALS">0</Criteria>'
    . '</filters></ServiceRequest>';

fwrite(STDOUT, "Probing the on-demand scan endpoint with criteria tagName = {$noSuchTag} AND id = 0 (match no agent).\n\n");

$callLog = [];
foreach ($versions as $version) {
    $path = "/qps/rest/{$version}/ods/ca/agentasset";
    fwrite(STDOUT, "=== {$path} ===\n");

    $headers = [];
    $ch = curl_init($baseUrl . $path . '?scan=Vulnerability_Scan&overrideConfigCpu=false');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $body,
        CURLOPT_HTTPAUTH       => CURLAUTH_BASIC,
        CURLOPT_USERPWD        => $username . ':' . $password,
        CURLOPT_HTTPHEADER     => ['X-Requested-With: Plainsight Security VulnDash', 'Content-Type: text/xml'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 30,
        CURLOPT_TIMEOUT        => 120,
        CURLOPT_HEADERFUNCTION => function ($h, string $line) use (&$headers): int {
            $parts = explode(':', $line, 2);
            if (count($parts) === 2) {
                $headers[strtolower(trim($parts[0]))] = trim($parts[1]);
            }
            return strlen($line);
        },
    ]);
    $start = microtime(true);
    $response = curl_exec($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    $remaining = isset($headers['x-ratelimit-remaining']) ? (int)$headers['x-ratelimit-remaining'] : null;
    $limit = isset($headers['x-ratelimit-limit']) ? (int)$headers['x-ratelimit-limit'] : null;
    $callLog[] = [
        'endpoint'             => $path,
        'api_version'          => 'QPS',
        'called_at'            => date('Y-m-d H:i:s'),
        'http_status'          => $response !== false ? $status : null,
        'duration_sec'         => round(microtime(true) - $start, 1),
        'response_bytes'       => $response !== false ? strlen((string)$response) : null,
        'rate_limit_remaining' => $remaining,
        'rate_limit_limit'     => $limit,
    ];

    if ($response === false) {
        fwrite(STDOUT, "  request failed: {$error}\n\n");
        continue;
    }

    $xml = @simplexml_load_string((string)$response);
    $isQps = $xml !== false && $xml->getName() === 'ServiceResponse';
    $code = $isQps && isset($xml->responseCode) ? (string)$xml->responseCode : '';
    $message = $isQps && isset($xml->responseErrorDetails->errorMessage) ? trim((string)$xml->responseErrorDetails->errorMessage) : '';

    fwrite(STDOUT, "  HTTP {$status}" . ($code !== '' ? ", responseCode {$code}" : '') . ($message !== '' ? ": {$message}" : '') . "\n");
    if ($limit !== null || $remaining !== null) {
        fwrite(STDOUT, '  rate limit: ' . ($remaining ?? '?') . ' of ' . ($limit ?? '?') . ' left'
            . (isset($headers['x-ratelimit-window-sec']) ? ' per ' . $headers['x-ratelimit-window-sec'] . 's' : '') . "\n");
    }
    if (!$isQps) {
        fwrite(STDOUT, '  body: ' . substr(preg_replace('/\s+/', ' ', strip_tags((string)$response)) ?? '', 0, 200) . "\n");
    }

    if ($status === 401 || $status === 403) {
        $verdict = 'UNKNOWN - authentication/permission refused, which says nothing about the version';
    } elseif ($status === 409) {
        $verdict = 'UNKNOWN - rate limited; try again later';
    } elseif ($status === 404) {
        $verdict = 'NOT AVAILABLE - HTTP 404';
    } elseif ($code === 'INVALID_API_VERSION') {
        // Confirmed 2026-11-10: this is how QPS refuses a version it has but
        // which doesn't serve this object (2.0-7.0 all answered this way).
        $verdict = 'NOT AVAILABLE - Qualys says this version does not serve agentasset';
    } elseif ($isQps && $status >= 200 && $status < 500) {
        $verdict = 'EXISTS - answered as a QPS service (an error here is most likely about matching no agents - compare with --versions=1.0)';
    } else {
        $verdict = 'NOT AVAILABLE - no QPS service answered on this version';
    }
    fwrite(STDOUT, "  verdict: {$verdict}\n\n");
}

try {
    ApiCallLogRepository::recordCalls($callLog);
} catch (\Throwable $e) {
    fwrite(STDERR, "Warning: could not record the API call log: {$e->getMessage()}\n");
}

fwrite(STDOUT, "Run with --versions=1.0 once to see what a working version's answer looks like, and compare.\n");
