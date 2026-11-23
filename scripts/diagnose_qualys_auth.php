#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * One-off, disposable diagnostic for the HTTP 403 seen from
 * sync_knowledge_base.php right after switching this subscription to a
 * new Qualys platform/pod.
 *
 * QualysApiClient::requestToFileByUrl() deliberately throws a fixed,
 * generic message on 401/403 ("check the credentials in
 * src/config/config.php") without ever reading the response body - it
 * returns before throwIfQualysErrorBody() is reached in that branch (see
 * scripts/lib/QualysApiClient.php). That's the right behaviour for the
 * sync scripts themselves, but it means Qualys's own, much more specific
 * explanation for the 403 has never actually been seen - only guessed at.
 * A 403 (as opposed to 401) generally means the username/password pair
 * itself was accepted, but something else about the request was refused -
 * on a fresh platform migration that's almost always the API base URL not
 * matching this subscription's actual pod, API access not being enabled
 * for this user on the new platform (a separate permission from GUI
 * login), or an IP allow-list that didn't carry over.
 *
 * This script makes exactly ONE raw request, completely independent of
 * QualysApiClient, straight to Qualys's own lightweight "About" endpoint
 * (/msp/about.php) - the standard low-footprint way to confirm API
 * connectivity/auth without touching any feature-specific rate limit or
 * quota. That matters here specifically because this subscription's own
 * config.php notes a real call budget as tight as 2/day was seen on the
 * old platform - this diagnostic must not spend that finding out about a
 * 403 that a single cheap call can already explain. It prints the full
 * HTTP status, every response header, and the full response body
 * regardless of outcome, so Qualys's actual wording is visible instead of
 * being collapsed into "auth failed".
 *
 * Read-only: makes no writes, touches no lock file, touches no sync
 * state. Safe to run anytime, including alongside another script.
 *
 * Usage:
 *   sudo -u www-data php scripts/diagnose_qualys_auth.php
 *
 * Delete this file once the 403 is resolved - it's not meant to become a
 * permanent part of the app.
 */

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Config;

$baseUrl  = rtrim((string)Config::get('qualys.api_base_url'), '/');
$username = (string)Config::get('qualys.username');
$password = (string)Config::get('qualys.password');

if ($baseUrl === '' || $username === '' || $password === '' || $password === 'CHANGEME') {
    fwrite(STDERR, "qualys.api_base_url / qualys.username / qualys.password are not fully set in src/config/config.php.\n");
    exit(1);
}

$maskedPassword = str_repeat('*', max(0, strlen($password) - 2)) . substr($password, -2);
fwrite(STDOUT, "Config values being used (from src/config/config.php):\n");
fwrite(STDOUT, "  api_base_url : {$baseUrl}\n");
fwrite(STDOUT, "  username     : {$username}\n");
fwrite(STDOUT, "  password     : {$maskedPassword} (" . strlen($password) . " chars)\n\n");

$url = $baseUrl . '/msp/about.php';
fwrite(STDOUT, "Requesting: {$url}\n\n");

$responseHeaders = [];
$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_HTTPAUTH       => CURLAUTH_BASIC,
    CURLOPT_USERPWD        => $username . ':' . $password,
    CURLOPT_HTTPHEADER     => ['X-Requested-With: Plainsight VulnDash diagnostic'],
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CONNECTTIMEOUT => 30,
    CURLOPT_TIMEOUT        => 30,
    CURLOPT_HEADERFUNCTION => function ($curlHandle, string $headerLine) use (&$responseHeaders): int {
        $parts = explode(':', $headerLine, 2);
        if (count($parts) === 2) {
            $responseHeaders[trim($parts[0])] = trim($parts[1]);
        }
        return strlen($headerLine);
    },
]);
$body = curl_exec($ch);
$httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
$effectiveUrl = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
$curlError = curl_error($ch);
curl_close($ch);

if ($body === false) {
    fwrite(STDOUT, "cURL transport error - no HTTP response came back at all (DNS/network/TLS level, not an auth problem):\n");
    fwrite(STDOUT, "  {$curlError}\n");
    fwrite(STDOUT, "\nCheck that api_base_url is a reachable host from this server (firewall/DNS), separately from anything Qualys-side.\n");
    exit(1);
}

fwrite(STDOUT, "HTTP status   : {$httpCode}\n");
fwrite(STDOUT, "Effective URL : {$effectiveUrl}\n");
if ($effectiveUrl !== $url) {
    fwrite(STDOUT, "  ^ differs from the requested URL - a redirect happened. Compare this against the API URL shown\n");
    fwrite(STDOUT, "    under Help > About in the Qualys UI for this subscription; if they don't match, api_base_url\n");
    fwrite(STDOUT, "    in config.php is pointed at the wrong platform/pod.\n");
}

fwrite(STDOUT, "\n--- Response headers ---\n");
foreach ($responseHeaders as $name => $value) {
    fwrite(STDOUT, "{$name}: {$value}\n");
}

fwrite(STDOUT, "\n--- Response body ---\n");
fwrite(STDOUT, rtrim($body) . "\n");

fwrite(STDOUT, "\n--- Verdict ---\n");
if ($httpCode === 200) {
    fwrite(STDOUT, "200 OK - api_base_url and credentials are valid for this endpoint on this platform.\n");
    fwrite(STDOUT, "If sync_knowledge_base.php still 403s, the KnowledgeBase module itself may be gated\n");
    fwrite(STDOUT, "separately for this account on the new subscription (module-level licensing/entitlement)\n");
    fwrite(STDOUT, "rather than a general API-access problem - worth confirming with Qualys support or the\n");
    fwrite(STDOUT, "account's module list in User Management if this diagnostic passes but the real sync still fails.\n");
} elseif ($httpCode === 401) {
    fwrite(STDOUT, "401 - Qualys rejected the username/password as invalid outright, not just forbidden.\n");
    fwrite(STDOUT, "Since GUI login works with the same credentials, look specifically for a config.php-only\n");
    fwrite(STDOUT, "issue: trailing whitespace, a stray quote character, or the password having been\n");
    fwrite(STDOUT, "re-typed/copied differently than the one used for GUI login (some subscriptions use a\n");
    fwrite(STDOUT, "separate API-only password).\n");
} elseif ($httpCode === 403) {
    fwrite(STDOUT, "403 - the credentials are being accepted as a valid login (Qualys would return 401 if not),\n");
    fwrite(STDOUT, "but this specific request is forbidden. On a fresh platform migration, in rough order of\n");
    fwrite(STDOUT, "likelihood, this is usually one of:\n\n");
    fwrite(STDOUT, "  1. api_base_url doesn't match this subscription's actual platform/pod. The GUI login URL\n");
    fwrite(STDOUT, "     and the API URL are not always the same host - get the exact API URL from Help > About\n");
    fwrite(STDOUT, "     inside the Qualys UI (there should be a line like \"Qualys API URL: https://...\") and\n");
    fwrite(STDOUT, "     compare it byte-for-byte against qualys.api_base_url in config.php.\n\n");
    fwrite(STDOUT, "  2. This user account doesn't have API access enabled on the new platform. GUI login and\n");
    fwrite(STDOUT, "     API access are separate permissions in Qualys - check Users > (this user) > Edit >\n");
    fwrite(STDOUT, "     General Information for an \"API access\" checkbox, and confirm the user's assigned\n");
    fwrite(STDOUT, "     role still grants API access after the migration.\n\n");
    fwrite(STDOUT, "  3. An IP-based API access restriction didn't carry over. Some subscriptions restrict API\n");
    fwrite(STDOUT, "     calls (separately from GUI access) to an allow-listed set of source IPs under Users >\n");
    fwrite(STDOUT, "     Security or a subscription-level setting - a platform migration can reset this list,\n");
    fwrite(STDOUT, "     so this server's outbound IP may need adding again on the new platform.\n\n");
    fwrite(STDOUT, "Read the response body above first - Qualys usually states which of these it is directly\n");
    fwrite(STDOUT, "in the <TEXT> of the error, rather than needing to be guessed at.\n");
} else {
    fwrite(STDOUT, "Unexpected status ({$httpCode}). Read the response body above for Qualys's own explanation.\n");
}
