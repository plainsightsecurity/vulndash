<?php
declare(strict_types=1);

// Minimal test harness - no PHPUnit, in keeping with the app's zero-dependency
// approach. A case file calls test('name', fn) any number of times; run.php
// loads every tests/cases/*Test.php, runs each test against a freshly
// emptied database, and exits non-zero if anything failed.

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Database;

final class TestFailure extends \RuntimeException {}

/** @var array<int, array{file: string, name: string, fn: callable}> */
$GLOBALS['__tests'] = [];

function test(string $name, callable $fn): void
{
    $GLOBALS['__tests'][] = ['file' => basename((string)($GLOBALS['__current_file'] ?? '?')), 'name' => $name, 'fn' => $fn];
}

function eq(mixed $got, mixed $want, string $label = ''): void
{
    if ($got !== $want) {
        throw new TestFailure(($label !== '' ? "$label: " : '')
            . 'expected ' . var_export($want, true) . ', got ' . var_export($got, true));
    }
}

function ok(bool $cond, string $label): void
{
    if (!$cond) {
        throw new TestFailure($label);
    }
}

/** Empties every table, so each test starts from the bare schema. */
function reset_db(): void
{
    $pdo = Database::getConnection();
    $tables = $pdo->query("SELECT table_name FROM information_schema.tables
                           WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'")->fetchAll(\PDO::FETCH_COLUMN);
    $pdo->exec('SET FOREIGN_KEY_CHECKS = 0');
    foreach ($tables as $t) {
        $pdo->exec("TRUNCATE TABLE `$t`");
    }
    $pdo->exec('SET FOREIGN_KEY_CHECKS = 1');
}

/**
 * The standard two-tenant estate most tests start from:
 *   tag 1 ClientA: host-a (2 findings)    tag 2 ClientB: host-b (1 finding)
 *   host-untagged (1 finding, no tag - must be invisible to every client)
 *   user 1 admin (admin), user 2 client (ClientA only), password "pw-123456789"
 * Findings span every severity and include KEV / EPSS data.
 */
function seed_estate(): void
{
    $pdo = Database::getConnection();
    $hash = password_hash('pw-123456789', PASSWORD_BCRYPT);
    $pdo->exec("INSERT INTO tags (id, qualys_tag_id, name) VALUES (1,'101','ClientA'),(2,'102','ClientB')");
    $pdo->exec("INSERT INTO assets (id, qualys_host_id, hostname, ip_address, last_scan_date) VALUES
        (1,1001,'host-a','10.0.0.1',NOW()),(2,1002,'host-b','10.0.0.2',NOW()),(3,1003,'host-untagged','10.0.0.3',NOW())");
    $pdo->exec('INSERT INTO asset_tags (asset_id, tag_id) VALUES (1,1),(2,2)');
    $pdo->prepare("INSERT INTO users (id, username, email, password_hash, is_admin) VALUES
        (1,'admin','admin@test',:h1,1),(2,'client','client@test',:h2,0)")->execute(['h1' => $hash, 'h2' => $hash]);
    $pdo->exec('INSERT INTO user_tags (user_id, tag_id) VALUES (2,1)');
    $pdo->exec("INSERT INTO knowledge_base (qid, title, severity_level, cvss3_base, patchable) VALUES
        (5001,'Critical remote code execution',5,9.8,1),
        (5002,'High severity flaw',4,7.5,1),
        (5003,'Medium weak cipher',3,5.3,0),
        (5004,'Low banner disclosure',2,2.6,1)");
    $pdo->exec("INSERT INTO qid_exploit (qid, is_kev, kev_due_date, max_epss, max_epss_percentile, cve_count) VALUES
        (5001,1,'2026-01-01',0.97,0.99,1),(5002,0,NULL,0.12,0.90,1),(5003,0,NULL,0.0003,0.10,1)");
    $pdo->exec("INSERT INTO host_detections (asset_id, qid, status, detection_type, first_found, last_found, times_found,
                                             effective_cvss_score, effective_cvss_source, is_ce_plus_fail) VALUES
        (1,5001,'Active','Confirmed',NOW() - INTERVAL 30 DAY,NOW(),3,9.8,'CVSS3',1),
        (1,5003,'Active','Confirmed',NOW() - INTERVAL 30 DAY,NOW(),3,5.3,'CVSS3',0),
        (2,5002,'New','Confirmed',NOW() - INTERVAL 1 DAY,NOW(),1,7.5,'CVSS3',1),
        (3,5004,'Active','Confirmed',NOW() - INTERVAL 5 DAY,NOW(),2,2.6,'CVSS3',0)");
}

/** Overrides config values for the rest of the current test (run.php restores them). */
function set_config(string $dottedKey, mixed $value): void
{
    $ref = new \ReflectionProperty(\VulnDash\Lib\Config::class, 'data');
    \VulnDash\Lib\Config::get('app.name'); // make sure it's loaded
    $cfg = $ref->getValue();
    $node = &$cfg;
    foreach (explode('.', $dottedKey) as $part) {
        if (!isset($node[$part]) || !is_array($node[$part])) {
            $node[$part] = $node[$part] ?? [];
        }
        $node = &$node[$part];
    }
    $node = $value;
    unset($node);
    $ref->setValue(null, $cfg);
}

/**
 * Renders a page in a separate PHP process (tests/render_page.php), as
 * admin, client or anon; pass $post (URL-encoded) to submit a form instead.
 * Returns everything it printed, including any "PHPERR:" lines.
 */
function render_page(string $page, string $query = '', string $role = 'admin', ?string $post = null): string
{
    $cmd = [PHP_BINARY, __DIR__ . '/render_page.php', $page, $query, $role];
    if ($post !== null) {
        $cmd[] = $post;
    }
    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
    proc_close($proc);
    return $out;
}

/** The newest audit_log rows, oldest first, as [action, username, target_label, details] tuples. */
function audit_rows(int $limit = 20): array
{
    $rows = \VulnDash\Lib\Database::getConnection()
        ->query("SELECT action, username, target_label, details FROM audit_log ORDER BY id DESC LIMIT $limit")
        ->fetchAll(\PDO::FETCH_NUM);
    foreach ($rows as &$r) {
        $r[3] = $r[3] !== null ? json_decode($r[3], true) : [];
    }
    return array_reverse($rows);
}
