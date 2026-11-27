<?php
declare(strict_types=1);

// scripts/migrate.php: status is read-only, --confirm applies pending files
// in filename order and stops at the first failure, --baseline records
// without running, an edited file shows CHANGED and only runs again with
// --rerun. Uses throwaway migrations in a temp directory (--dir), never the
// real database/migrations.

use VulnDash\Lib\Database;

/** Runs the real script; returns [exit code, combined output]. */
function run_migrate(string $dir, array $args = []): array
{
    $cmd = [PHP_BINARY, __DIR__ . '/../../scripts/migrate.php', '--dir=' . $dir, ...$args];
    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
    return [proc_close($proc), $out];
}

/** A temp migrations directory holding $files (name => SQL). */
function migration_dir(array $files): string
{
    $dir = sys_get_temp_dir() . '/vdmigtest_' . bin2hex(random_bytes(4));
    mkdir($dir);
    foreach ($files as $name => $sql) {
        file_put_contents("$dir/$name", $sql);
    }
    return $dir;
}

function cleanup_migration_test(string $dir): void
{
    foreach (glob("$dir/*") as $f) {
        unlink($f);
    }
    rmdir($dir);
    Database::getConnection()->exec('DROP TABLE IF EXISTS mig_t_one, mig_t_two, mig_t_three');
}

function recorded_migrations(): array
{
    if (!table_exists('schema_migrations')) {
        return [];
    }
    return Database::getConnection()
        ->query('SELECT filename, method FROM schema_migrations ORDER BY filename')
        ->fetchAll(\PDO::FETCH_KEY_PAIR);
}

function table_exists(string $t): bool
{
    $s = Database::getConnection()->prepare('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?');
    $s->execute([$t]);
    return (int)$s->fetchColumn() === 1;
}

const MIG_ONE = "-- comment; with a semicolon\nCREATE TABLE IF NOT EXISTS mig_t_one (id INT PRIMARY KEY);\n";
// The information_schema + PREPARE pattern every real migration uses.
const MIG_TWO = "CREATE TABLE IF NOT EXISTS mig_t_two (id INT PRIMARY KEY);
SET @c := (SELECT COUNT(*) FROM information_schema.columns
           WHERE table_schema = DATABASE() AND table_name = 'mig_t_two' AND column_name = 'note');
SET @s := IF(@c = 0, 'ALTER TABLE mig_t_two ADD COLUMN note VARCHAR(20) NULL', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;\n";

test('status is read-only and suggests a baseline when nothing is recorded', function () {
    $dir = migration_dir(['2026-12-01-one.sql' => MIG_ONE]);
    try {
        Database::getConnection()->exec('DROP TABLE IF EXISTS schema_migrations');
        [$code, $out] = run_migrate($dir);
        eq($code, 0, 'exit code');
        ok(str_contains($out, 'PENDING  2026-12-01-one.sql'), 'listed as pending');
        ok(str_contains($out, '--baseline --confirm'), 'suggests a baseline');
        ok(str_contains($out, 'Preview only'), 'says nothing was done');
        ok(!table_exists('schema_migrations'), 'did not create schema_migrations');
        ok(!table_exists('mig_t_one'), 'did not run the migration');
    } finally {
        cleanup_migration_test($dir);
    }
});

test('--confirm applies pending files in filename order, then has nothing to do', function () {
    $dir = migration_dir([
        '2026-12-02-two.sql' => MIG_TWO,
        '2026-12-01-one.sql' => MIG_ONE,
    ]);
    try {
        Database::getConnection()->exec('DROP TABLE IF EXISTS schema_migrations');
        [$code, $out] = run_migrate($dir, ['--confirm']);
        eq($code, 0, 'exit code');
        ok(strpos($out, 'running  2026-12-01-one.sql') < strpos($out, 'running  2026-12-02-two.sql'), 'one before two');
        ok(table_exists('mig_t_one') && table_exists('mig_t_two'), 'both ran');
        eq(recorded_migrations(), ['2026-12-01-one.sql' => 'applied', '2026-12-02-two.sql' => 'applied']);
        [$code, $out] = run_migrate($dir, ['--confirm']);
        eq($code, 0, 'second run exit code');
        ok(str_contains($out, '2 applied, 0 pending, 0 changed.') && str_contains($out, 'Nothing to do.'), 'second run is a no-op');
    } finally {
        cleanup_migration_test($dir);
    }
});

test('a failing migration stops the run, is not recorded, and later files stay pending', function () {
    $dir = migration_dir([
        '2026-12-01-one.sql'   => MIG_ONE,
        '2026-12-02-bad.sql'   => "ALTER TABLE no_such_table ADD COLUMN x INT;\n",
        '2026-12-03-three.sql' => "CREATE TABLE IF NOT EXISTS mig_t_three (id INT PRIMARY KEY);\n",
    ]);
    try {
        [$code, $out] = run_migrate($dir, ['--confirm']);
        eq($code, 1, 'exit code');
        ok(str_contains($out, '2026-12-02-bad.sql failed') && str_contains($out, 'no_such_table'), 'reports the mysql error');
        eq(recorded_migrations(), ['2026-12-01-one.sql' => 'applied'], 'only the good one recorded');
        ok(!table_exists('mig_t_three'), 'nothing after the failure ran');

        file_put_contents("$dir/2026-12-02-bad.sql", "SELECT 1;\n");      // fixed
        [$code] = run_migrate($dir, ['--confirm']);
        eq($code, 0, 'exit code after fix');
        ok(table_exists('mig_t_three'), 'the rest ran');
        eq(count(recorded_migrations()), 3, 'all recorded');
    } finally {
        cleanup_migration_test($dir);
    }
});

test('--baseline records everything without running it, and only with --confirm', function () {
    $dir = migration_dir(['2026-12-01-one.sql' => MIG_ONE, '2026-12-02-two.sql' => MIG_TWO]);
    try {
        [$code, $out] = run_migrate($dir, ['--baseline']);
        eq($code, 0, 'preview exit code');
        ok(str_contains($out, 'Record as applied (without running): 2026-12-01-one.sql, 2026-12-02-two.sql'), 'preview lists both');
        eq(recorded_migrations(), [], 'preview recorded nothing');

        [$code, $out] = run_migrate($dir, ['--baseline', '--confirm']);
        eq($code, 0, 'exit code');
        eq(recorded_migrations(), ['2026-12-01-one.sql' => 'baseline', '2026-12-02-two.sql' => 'baseline']);
        ok(!table_exists('mig_t_one') && !table_exists('mig_t_two'), 'nothing was run');
        [, $out] = run_migrate($dir);
        ok(str_contains($out, '(baseline)') && str_contains($out, '2 applied, 0 pending'), 'status shows the baseline');
    } finally {
        cleanup_migration_test($dir);
    }
});

test('an edited file shows CHANGED, is not re-run on its own, and --rerun runs it again', function () {
    $dir = migration_dir(['2026-12-01-one.sql' => MIG_ONE]);
    try {
        run_migrate($dir, ['--confirm']);
        file_put_contents("$dir/2026-12-01-one.sql", MIG_ONE . "CREATE TABLE IF NOT EXISTS mig_t_three (id INT PRIMARY KEY);\n");
        [, $out] = run_migrate($dir, ['--confirm']);
        ok(str_contains($out, 'CHANGED  2026-12-01-one.sql') && str_contains($out, '--rerun=2026-12-01-one.sql'), 'flagged with the fix');
        ok(!table_exists('mig_t_three'), 'not re-run by a plain --confirm');

        [$code, $out] = run_migrate($dir, ['--rerun=2026-12-01-one.sql']);
        ok($code === 0 && str_contains($out, 'Preview only') && !table_exists('mig_t_three'), '--rerun without --confirm only previews');
        [$code] = run_migrate($dir, ['--rerun=2026-12-01-one.sql', '--confirm']);
        eq($code, 0, 'rerun exit code');
        ok(table_exists('mig_t_three'), 'ran again');
        [, $out] = run_migrate($dir);
        ok(str_contains($out, '1 applied, 0 pending, 0 changed.'), 'checksum updated');
    } finally {
        cleanup_migration_test($dir);
    }
});

test('bad arguments exit 2 without touching anything', function () {
    $dir = migration_dir(['2026-12-01-one.sql' => MIG_ONE]);
    try {
        eq(run_migrate($dir, ['--baseline', '--rerun=2026-12-01-one.sql'])[0], 2, 'baseline + rerun');
        eq(run_migrate($dir . '/nope')[0], 2, 'missing directory');
        [$code, $out] = run_migrate($dir, ['--rerun=nope.sql', '--confirm']);
        ok($code === 1 && str_contains($out, 'no such migration'), 'unknown rerun file');
        eq(recorded_migrations(), [], 'nothing recorded');
    } finally {
        cleanup_migration_test($dir);
    }
});
