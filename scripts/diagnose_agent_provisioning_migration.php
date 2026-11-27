#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Read-only pre-migration diagnostic for
 * database/migrations/2026-11-add-agent-provisioning.sql (Admin > Agent Setup).
 *
 * The migration only adds a table, so it can't damage anything; Agent Setup
 * errors until it has run. This says whether it has, and previews the page:
 * each organisation's suggested tag name, and any that would clash with a tag
 * VulnDash already knows (same name, any case) - those need a different name
 * typed in, or the existing tag chosen when Qualys reports it. It also checks
 * qualys.activation_key_modules, which new keys are licensed for.
 *
 * --check-qualys additionally makes two read-only Qualys calls (one tag
 * search, one activation key search per 1000 keys - each against its own 25-per-24h
 * limit) to confirm the API user can read tags and keys. It can't test the
 * create permissions without creating something; the first real set-up does.
 *
 * Writes nothing.
 *
 * Usage:
 *   php scripts/diagnose_agent_provisioning_migration.php
 *   php scripts/diagnose_agent_provisioning_migration.php --check-qualys
 */

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/lib/QualysApiClient.php';

use VulnDash\Lib\AgentProvisioner;
use VulnDash\Lib\ApiCallLogRepository;
use VulnDash\Lib\Config;
use VulnDash\Lib\Database;
use VulnDash\Scripts\QualysApiClient;

$pdo = Database::getConnection();
$exitCode = 0;

$applied = (int)$pdo->query("
    SELECT COUNT(*) FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'agent_provisioning'
")->fetchColumn() === 1;
fwrite(STDOUT, 'agent_provisioning: ' . ($applied ? 'PRESENT (migration already applied)' : 'absent (migration not yet applied - /admin/agent_setup will error until it is)') . "\n");
if ($applied) {
    fwrite(STDOUT, '  set-ups: ' . (int)$pdo->query("SELECT COUNT(*) FROM agent_provisioning WHERE status = 'complete'")->fetchColumn() . ' complete, '
        . (int)$pdo->query("SELECT COUNT(*) FROM agent_provisioning WHERE status = 'in_progress'")->fetchColumn() . " unfinished\n");
}

try {
    fwrite(STDOUT, 'New keys will be licensed for: ' . implode(', ', AgentProvisioner::modules()) . "\n\n");
} catch (\RuntimeException $e) {
    fwrite(STDOUT, 'PROBLEM: ' . $e->getMessage() . "\n\n");
    $exitCode = 1;
}

$orgs = $pdo->query('SELECT id, name FROM organisations ORDER BY name')->fetchAll();
fwrite(STDOUT, count($orgs) . " organisation(s):\n");
$byName = $pdo->prepare('SELECT name, qualys_tag_id FROM tags WHERE LOWER(TRIM(name)) = LOWER(TRIM(:n)) LIMIT 1');
foreach ($orgs as $org) {
    $suggested = AgentProvisioner::suggestTagName((string)$org['name']);
    $note = '';
    if ($suggested === '') {
        $note = '  <- no usable characters: a name must be typed in';
    } else {
        $byName->execute(['n' => $suggested]);
        if (($tag = $byName->fetch()) !== false) {
            $note = $tag['qualys_tag_id'] !== null
                ? "  <- VulnDash already has tag {$tag['name']} (Qualys id {$tag['qualys_tag_id']}): Qualys will report it, and it can be used only if static and unclaimed"
                : "  <- pending tag {$tag['name']} exists: it will be promoted";
        }
    }
    fwrite(STDOUT, sprintf("  %-40s -> %s%s\n", (string)$org['name'], $suggested !== '' ? $suggested : '(none)', $note));
}

if (in_array('--check-qualys', $argv, true)) {
    fwrite(STDOUT, "\nQualys read access:\n");
    $client = new QualysApiClient(
        (string)Config::get('qualys.api_base_url'),
        (string)Config::get('qualys.username'),
        (string)Config::get('qualys.password'),
        (string)(Config::get('qualys.api_version') ?? '4.0')
    );
    try {
        fwrite(STDOUT, '  tag search: OK (' . count($client->searchTagsByNameContains('-Agents')) . " tag(s) with -Agents in the name)\n");
        $keys = $client->listActivationKeys();
        fwrite(STDOUT, '  activation key search: OK (' . count($keys) . " key(s))\n");
        $titles = array_count_values(array_map(static fn (array $k): string => strtolower($k['title']), $keys));
        foreach (array_filter($titles, static fn (int $c): bool => $c > 1) as $title => $count) {
            fwrite(STDOUT, "    note: {$count} keys share the title '{$title}'\n");
        }
    } catch (\RuntimeException $e) {
        fwrite(STDERR, '  Not completed: ' . $e->getMessage() . "\n");
        $exitCode = 1;
    } finally {
        try {
            ApiCallLogRepository::recordCalls($client->getCallLog());
        } catch (\Throwable $logError) {
            fwrite(STDERR, 'Warning: failed to persist API call log: ' . $logError->getMessage() . "\n");
        }
    }
}

exit($exitCode);
