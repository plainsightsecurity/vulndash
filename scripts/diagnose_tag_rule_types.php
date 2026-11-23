#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Read-only check: how is each tag the dashboard holds actually built in
 * Qualys - a client scope tag, or an asset-group / IP-range tag that lands
 * on an agent host only because the host's IP happens to match?
 *
 * Why (2026-11): an asset group made for external scans arrived on the
 * agent hosts in it as a tag, and tag scoping is per host, so every
 * internal agent finding on those hosts showed under it. The fix so far has
 * been adding each such tag's name to qualys.excluded_tags by hand. Host
 * List Detection's <TAGS> gives only id and name, so the syncs now ask the
 * Asset Management Search Tags endpoint how each tag is built and keep
 * asset-group/IP-range tags off agent hosts (src/Lib/TagScopeClassifier.php).
 * This prints what Qualys reports for every stored tag, fresh, and whether
 * that rule lets it scope agent hosts - for checking a tag the syncs are
 * treating unexpectedly.
 *
 * Costs ONE call (POST /qps/rest/2.0/search/am/tag, logged as QPS on the
 * API usage page) per 100 stored tags - not the /api/x.0/ counters the
 * syncs use. Writes nothing except the call log row.
 *
 * Tags already in qualys.excluded_tags were never stored, so they aren't
 * looked up here; pass their Qualys ids (from the Qualys UI) with
 * --also=<id>,<id> to check the known IP-based ones classify as expected.
 * Same call, no extra cost.
 *
 * Usage:
 *   sudo -u www-data php scripts/diagnose_tag_rule_types.php
 *   sudo -u www-data php scripts/diagnose_tag_rule_types.php --also=12345678,23456789
 *
 * Run as www-data so the call-budget state file in /tmp stays owned by the
 * cron user. Paste the whole output back.
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;
use VulnDash\Lib\Database;
use VulnDash\Lib\TagScopeClassifier;
use VulnDash\Scripts\QualysApiClient;

$also = [];
foreach (array_slice($argv, 1) as $arg) {
    if (preg_match('/^--also=([0-9,\s]+)$/', $arg, $m)) {
        $also = array_values(array_filter(array_map('trim', explode(',', $m[1])), static fn(string $v): bool => ctype_digit($v)));
    } else {
        fwrite(STDERR, "Unknown option: {$arg}\n");
        exit(2);
    }
}

$pdo = Database::getConnection();
$local = $pdo->query(
    'SELECT t.id, t.qualys_tag_id, t.name,
            (SELECT COUNT(*) FROM asset_tags at WHERE at.tag_id = t.id) AS asset_count,
            (SELECT COUNT(*) FROM user_tags ut WHERE ut.tag_id = t.id) AS account_count
       FROM tags t
      ORDER BY t.name'
)->fetchAll();

$lookup = [];
$pending = [];
foreach ($local as $row) {
    $qid = trim((string)($row['qualys_tag_id'] ?? ''));
    if ($qid === '' || !ctype_digit($qid)) {
        $pending[] = $row;
    } else {
        $lookup[] = $qid;
    }
}
$lookup = array_values(array_unique(array_merge($lookup, $also)));
$calls = (int)ceil(count($lookup) / 100);

fwrite(STDOUT, "==========================================================\n");
fwrite(STDOUT, "  Tag rule types (Qualys Search Tags)\n");
fwrite(STDOUT, "----------------------------------------------------------\n");
fwrite(STDOUT, '  Local tags : ' . count($local) . ' (' . count($pending) . " with no Qualys id, not looked up)\n");
fwrite(STDOUT, '  Extra ids  : ' . ($also === [] ? '(none)' : implode(', ', $also)) . "\n");
fwrite(STDOUT, "  Calls      : {$calls} x POST /qps/rest/2.0/search/am/tag\n");
fwrite(STDOUT, "  Mode       : READ-ONLY (nothing written except the API call log)\n");
fwrite(STDOUT, "==========================================================\n\n");

if ($lookup === []) {
    fwrite(STDOUT, "Nothing to look up.\n");
    exit(0);
}

$client = new QualysApiClient(
    (string)Config::get('qualys.api_base_url'),
    (string)Config::get('qualys.username'),
    (string)Config::get('qualys.password'),
    (string)(Config::get('qualys.api_version') ?? '4.0'),
    Config::get('qualys.agent_scope_tag') !== null ? (string)Config::get('qualys.agent_scope_tag') : null,
    is_array(Config::get('qualys.excluded_tags')) ? Config::get('qualys.excluded_tags') : null
);

/**
 * What the tag looks like from its definition, for a human to read. Whether
 * it may scope agent hosts is TagScopeClassifier::isIpBased() - the same
 * rule the syncs apply - shown separately below.
 */
function classify(array $def): string
{
    if ($def['srcAssetGroupId'] !== null) {
        return 'ASSET GROUP (src ' . $def['srcAssetGroupId'] . ')';
    }
    if (TagScopeClassifier::isIpBased($def['ruleType'], null)) {
        return 'IP RANGE';
    }
    if ($def['ruleType'] === null || $def['ruleType'] === 'STATIC') {
        return 'static (no rule)';
    }
    return 'dynamic: ' . $def['ruleType'];
}

$exitCode = 0;
try {
    try {
        $defs = $client->searchTagsByIds($lookup);
    } catch (\Throwable $e) {
        fwrite(STDOUT, "FAILED: {$e->getMessage()}\n");
        fwrite(STDOUT, "  Paste this output - the id IN filter or the endpoint itself may not be available to this API user.\n");
        $exitCode = 1;
        $defs = null;
    }

    if ($defs !== null) {
        $byQualysId = [];
        foreach ($local as $row) {
            if (ctype_digit(trim((string)($row['qualys_tag_id'] ?? '')))) {
                $byQualysId[(int)trim((string)$row['qualys_tag_id'])] = $row;
            }
        }

        $ruleTypes = [];
        $ipBasedAssigned = [];
        foreach ($lookup as $qid) {
            $qid = (int)$qid;
            $row = $byQualysId[$qid] ?? null;
            $title = $row !== null ? "{$row['name']}  (local #{$row['id']}, Qualys {$qid})" : "Qualys {$qid}  (--also, not stored locally)";
            fwrite(STDOUT, "--- {$title}\n");
            if ($row !== null) {
                fwrite(STDOUT, "    on {$row['asset_count']} asset(s), assigned to {$row['account_count']} account(s)\n");
            }

            if (!isset($defs[$qid])) {
                fwrite(STDOUT, "    NOT RETURNED by Qualys (deleted, or outside this API user's scope)\n\n");
                continue;
            }
            $def = $defs[$qid];
            $label = classify($def);
            $ruleTypes[$def['ruleType'] ?? '(none)'] = ($ruleTypes[$def['ruleType'] ?? '(none)'] ?? 0) + 1;

            fwrite(STDOUT, "    looks like      : {$label}\n");
            fwrite(STDOUT, '    scopes agents?  : ' . (TagScopeClassifier::isIpBased($def['ruleType'], $def['srcAssetGroupId']) ? 'NO - kept off agent hosts by the sync' : 'yes') . "\n");
            fwrite(STDOUT, '    ruleType        : ' . ($def['ruleType'] ?? '(absent)') . "\n");
            fwrite(STDOUT, '    srcAssetGroupId : ' . ($def['srcAssetGroupId'] ?? '(absent)') . "\n");
            fwrite(STDOUT, '    parentTagId     : ' . ($def['parentTagId'] ?? '(absent)') . (isset($def['parentTagId'], $defs[$def['parentTagId']]) ? " ({$defs[$def['parentTagId']]['name']})" : '') . "\n");
            if ($def['ruleText'] !== null) {
                $text = preg_replace('/\s+/', ' ', $def['ruleText']);
                fwrite(STDOUT, '    ruleText        : ' . (mb_strlen($text) > 200 ? mb_substr($text, 0, 200) . '...' : $text) . "\n");
            }
            foreach ($def['other'] as $field => $value) {
                fwrite(STDOUT, '    other ' . str_pad($field, 10) . ': ' . (mb_strlen($value) > 120 ? mb_substr($value, 0, 120) . '...' : $value) . "\n");
            }
            if ($row !== null && $row['name'] !== $def['name']) {
                fwrite(STDOUT, "    (Qualys name now: {$def['name']})\n");
            }
            if ($row !== null && (int)$row['account_count'] > 0 && TagScopeClassifier::isIpBased($def['ruleType'], $def['srcAssetGroupId'])) {
                $ipBasedAssigned[] = "{$row['name']} ({$row['account_count']} account(s))";
            }
            fwrite(STDOUT, "\n");
        }

        foreach ($pending as $row) {
            fwrite(STDOUT, "--- {$row['name']}  (local #{$row['id']}, no Qualys id - not looked up)\n");
            fwrite(STDOUT, "    on {$row['asset_count']} asset(s), assigned to {$row['account_count']} account(s)\n\n");
        }

        fwrite(STDOUT, "----------------------------------------------------------\n");
        $returned = count(array_intersect_key($defs, array_flip(array_map('intval', $lookup))));
        fwrite(STDOUT, "  Returned {$returned} of " . count($lookup) . " tag(s) asked for. ruleType counts:\n");
        ksort($ruleTypes);
        foreach ($ruleTypes as $type => $n) {
            fwrite(STDOUT, "    {$type}: {$n}\n");
        }
        if ($ipBasedAssigned !== []) {
            fwrite(STDOUT, "  NOTE: asset-group/IP-range tag(s) assigned to accounts - the sync keeps these off agent hosts, so those accounts see none of them:\n");
            foreach ($ipBasedAssigned as $line) {
                fwrite(STDOUT, "    {$line}\n");
            }
        }
    }

    $rate = $client->getLastRateLimitInfo();
    if ($rate !== null && $rate['remaining'] !== null) {
        fwrite(STDOUT, "  QPS calls remaining on this endpoint: {$rate['remaining']}" . ($rate['limit'] !== null ? "/{$rate['limit']}" : '') . "\n");
    } else {
        fwrite(STDOUT, "  Qualys sent no rate-limit headers for this endpoint.\n");
    }
} finally {
    try {
        ApiCallLogRepository::recordCalls($client->getCallLog());
    } catch (\Throwable $logError) {
        fwrite(STDERR, 'Warning: failed to persist API call log: ' . $logError->getMessage() . "\n");
    }
}

exit($exitCode);
