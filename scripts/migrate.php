#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Migration runner: keeps track of which database/migrations/*.sql files have
 * been applied (table schema_migrations) and applies the rest, in filename
 * order, so a deploy is "pull, then migrate" with nothing to remember.
 *
 * Read-only unless --confirm is given, like the other scripts that change
 * things:
 *
 *   php scripts/migrate.php                       # status: applied / PENDING / CHANGED
 *   php scripts/migrate.php --confirm             # apply everything pending
 *   php scripts/migrate.php --baseline            # preview: record all as applied, run nothing
 *   php scripts/migrate.php --baseline --confirm  # do it (once, on a database already up to date)
 *   php scripts/migrate.php --rerun=FILE --confirm  # run one applied (or CHANGED) file again
 *
 * Add --root to connect as MySQL root over the local socket instead of with
 * the db.* credentials in src/config/config.php - for when the app's own
 * database user can't CREATE/ALTER. Run it with sudo, since Ubuntu's MySQL
 * root signs in by auth_socket:
 *   sudo php scripts/migrate.php --root --confirm
 *
 * First use on the live server: every migration there has already been
 * applied by hand, so run --baseline --confirm once to record them without
 * running anything. A fresh install from install_schema.sql is the same -
 * that file already contains every migration - so baseline it too. (Running
 * --confirm instead would also be safe, since every migration is idempotent,
 * but there's no reason to re-run data back-fills on a live database.)
 *
 * How a migration is applied: the file is piped into the mysql command-line
 * client, exactly as `mysql vulndash < file.sql` always has been, so files
 * using PREPARE/EXECUTE, multiple statements or comments need no changes and
 * behave identically to before. The password goes in a temporary 0600
 * --defaults-extra-file, never on the command line. Each file is recorded
 * only after it succeeds; the first failure stops the run with exit code 1
 * and the mysql error, leaving later files pending. Fix and run again.
 *
 * Order is plain filename order. Older files are named YYYY-MM-description,
 * which happens to sort correctly; name new ones YYYY-MM-DD-description
 * (e.g. 2026-12-03-add-foo.sql) so order within a month is by date.
 *
 * CHANGED means a file's contents differ from when it was recorded (its
 * sha256 is stored). It is NOT re-run automatically - review the edit, then
 * --rerun=that-file.sql --confirm, which runs it again and stores the new
 * checksum.
 *
 * schema_migrations is created by this script (on the first --confirm), not
 * by a migration, and the test suite ignores it when comparing
 * install_schema.sql with the migrated schema. --dir=PATH reads migrations
 * from another directory (used by the tests).
 *
 * Exit codes: 0 ok (status mode: whether or not anything is pending), 1 a
 * migration or database command failed, 2 bad arguments.
 */

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Config;

$options  = getopt('', ['confirm', 'baseline', 'root', 'rerun:', 'dir:', 'help']);
if (array_key_exists('help', $options)) {
    fwrite(STDOUT, "Usage: php scripts/migrate.php [--confirm] [--baseline] [--rerun=FILE] [--root] [--dir=PATH]\n"
        . "Without --confirm nothing is changed. See the docblock in this file for details.\n");
    exit(0);
}
$confirm  = array_key_exists('confirm', $options);
$baseline = array_key_exists('baseline', $options);
$asRoot   = array_key_exists('root', $options);
$rerun    = isset($options['rerun']) ? basename((string)$options['rerun']) : null;
$dir      = rtrim((string)($options['dir'] ?? __DIR__ . '/../database/migrations'), '/');

if ($baseline && $rerun !== null) {
    fwrite(STDERR, "--baseline and --rerun can't be combined.\n");
    exit(2);
}
if (!is_dir($dir)) {
    fwrite(STDERR, "Migrations directory not found: {$dir}\n");
    exit(2);
}

$dbName = (string)Config::get('db.name');
if (!preg_match('/^[A-Za-z0-9_]+$/', $dbName)) {
    fwrite(STDERR, "db.name '{$dbName}' isn't a plain database name - refusing to build mysql commands with it.\n");
    exit(2);
}

// --- single-instance lock (same pattern as the other scripts) ---------------
$lockPath   = sys_get_temp_dir() . '/vulndash_migrate.lock';
$lockHandle = fopen($lockPath, 'c');
if ($lockHandle === false) {
    fwrite(STDERR, "Could not open lock file {$lockPath} - check its ownership/permissions.\n");
    exit(1);
}
@chmod($lockPath, 0666);
if (!flock($lockHandle, LOCK_EX | LOCK_NB)) {
    fwrite(STDERR, "Another migrate run is already in progress - exiting.\n");
    exit(1);
}

// --- mysql client plumbing --------------------------------------------------
$defaultsFile = null;
if (!$asRoot) {
    $defaultsFile = tempnam(sys_get_temp_dir(), 'vdmig');
    if ($defaultsFile === false) {
        fwrite(STDERR, "Could not create a temporary mysql defaults file.\n");
        exit(1);
    }
    chmod($defaultsFile, 0600);
    $quote = static fn ($v): string => '"' . addcslashes((string)$v, "\\\"") . '"';
    file_put_contents($defaultsFile, "[client]\n"
        . 'host=' . $quote(Config::get('db.host') ?? 'localhost') . "\n"
        . 'port=' . (int)(Config::get('db.port') ?? 3306) . "\n"
        . 'user=' . $quote(Config::get('db.user')) . "\n"
        . 'password=' . $quote(Config::get('db.password') ?? '') . "\n");
}

/**
 * Runs the mysql client against the app database, with $sql as -e or $file
 * on stdin. Returns [ok, stdout, stderr]. Never goes through a shell.
 *
 * @return array{0: bool, 1: string, 2: string}
 */
$mysql = static function (?string $sql, ?string $file = null) use ($defaultsFile, $dbName): array {
    $cmd = ['mysql'];
    if ($defaultsFile !== null) {
        $cmd[] = '--defaults-extra-file=' . $defaultsFile;   // must be the first option
    }
    array_push($cmd, '--batch', '--skip-column-names', '--default-character-set=utf8mb4', $dbName);
    if ($sql !== null) {
        array_push($cmd, '-e', $sql);
    }
    $stdin = $file !== null ? ['file', $file, 'r'] : ['file', '/dev/null', 'r'];
    $env = getenv();
    unset($env['MYSQL_PWD']);          // the defaults file (or the socket) decides who we are
    $proc = proc_open($cmd, [0 => $stdin, 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env);
    if (!is_resource($proc)) {
        return [false, '', 'could not start the mysql client - is it installed?'];
    }
    $out = (string)stream_get_contents($pipes[1]);
    $err = (string)stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    return [proc_close($proc) === 0, $out, trim($err)];
};

$sqlString = static fn (string $v): string => "'" . str_replace(["\\", "'"], ["\\\\", "\\'"], $v) . "'";

$exitCode = 0;
try {
    // --- what's on disk ------------------------------------------------------
    $files = [];
    foreach (glob($dir . '/*.sql') ?: [] as $path) {
        $name = basename($path);
        if (!preg_match('/^[A-Za-z0-9._-]+\.sql$/', $name)) {
            throw new RuntimeException("Unexpected migration file name '{$name}' - use letters, digits, dots, dashes and underscores only.");
        }
        $files[$name] = ['path' => $path, 'checksum' => hash_file('sha256', $path)];
    }
    ksort($files, SORT_STRING);

    if ($rerun !== null && !isset($files[$rerun])) {
        throw new RuntimeException("--rerun: no such migration '{$rerun}' in {$dir}");
    }

    // --- what's recorded -----------------------------------------------------
    [$okQ, $out, $err] = $mysql("SELECT COUNT(*) FROM information_schema.tables
                                 WHERE table_schema = DATABASE() AND table_name = 'schema_migrations'");
    if (!$okQ) {
        throw new RuntimeException("Could not connect to the database: {$err}"
            . ($asRoot ? '' : "\n(If the app's database user can't do this, try: sudo php scripts/migrate.php --root ...)"));
    }
    $tableExists = trim($out) === '1';

    $recorded = [];
    if ($tableExists) {
        [$okQ, $out, $err] = $mysql('SELECT filename, checksum, applied_at, method FROM schema_migrations');
        if (!$okQ) {
            throw new RuntimeException("Could not read schema_migrations: {$err}");
        }
        foreach (array_filter(explode("\n", $out)) as $line) {
            [$f, $c, $at, $m] = explode("\t", $line) + ['', '', '', ''];
            $recorded[$f] = ['checksum' => $c, 'applied_at' => $at, 'method' => $m];
        }
    }

    $pending = [];
    $changed = [];
    foreach ($files as $name => $f) {
        if (!isset($recorded[$name])) {
            $pending[] = $name;
        } elseif ($recorded[$name]['checksum'] !== $f['checksum']) {
            $changed[] = $name;
        }
    }

    // --- status listing (always shown) --------------------------------------
    fwrite(STDOUT, "Database {$dbName}, migrations in " . realpath($dir) . "\n\n");
    foreach ($files as $name => $f) {
        if (in_array($name, $pending, true)) {
            $state = 'PENDING';
            $note = '';
        } else {
            $state = in_array($name, $changed, true) ? 'CHANGED' : 'applied';
            $r = $recorded[$name];
            $note = substr($r['applied_at'], 0, 16) . ($r['method'] === 'baseline' ? ' (baseline)' : '')
                . ($state === 'CHANGED' ? ' - file edited since; review, then --rerun=' . $name . ' --confirm' : '');
        }
        fwrite(STDOUT, sprintf("  %-8s %-60s %s\n", $state, $name, $note));
    }
    foreach (array_diff(array_keys($recorded), array_keys($files)) as $gone) {
        fwrite(STDOUT, sprintf("  %-8s %-60s %s\n", 'missing', $gone, 'recorded as applied but the file is no longer in the directory'));
    }
    fwrite(STDOUT, sprintf("\n%d applied, %d pending, %d changed.\n",
        count($files) - count($pending), count($pending), count($changed)));

    if (!$tableExists && !$baseline) {
        fwrite(STDOUT, "\nNothing is recorded yet. If this database is already up to date (the live server, or a\n"
            . "fresh install from install_schema.sql), record that once with: --baseline --confirm\n");
    }

    // --- decide the work -----------------------------------------------------
    if ($rerun !== null) {
        $work = [$rerun];
        $verb = 'Re-run';
    } elseif ($baseline) {
        $work = $pending;
        $verb = 'Record as applied (without running)';
    } else {
        $work = $pending;
        $verb = 'Apply';
    }

    if ($work === []) {
        fwrite(STDOUT, "\nNothing to do.\n");
    } elseif (!$confirm) {
        fwrite(STDOUT, "\n{$verb}: " . implode(', ', $work) . "\nPreview only - add --confirm to go ahead.\n");
    } else {
        $create = "CREATE TABLE IF NOT EXISTS schema_migrations (
            filename   VARCHAR(191) NOT NULL,
            checksum   CHAR(64)     NOT NULL,
            applied_at DATETIME     NOT NULL,
            method     VARCHAR(16)  NOT NULL,
            PRIMARY KEY (filename)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci";
        [$okQ, , $err] = $mysql($create);
        if (!$okQ) {
            throw new RuntimeException("Could not create schema_migrations: {$err}");
        }

        $method = $baseline ? 'baseline' : 'applied';
        fwrite(STDOUT, "\n");
        foreach ($work as $name) {
            if (!$baseline) {
                fwrite(STDOUT, "  running  {$name} ... ");
                [$okQ, , $err] = $mysql(null, $files[$name]['path']);
                if (!$okQ) {
                    fwrite(STDOUT, "FAILED\n");
                    throw new RuntimeException("{$name} failed - nothing after it was run, and it was not recorded:\n{$err}");
                }
                fwrite(STDOUT, "ok\n");
            }
            [$okQ, , $err] = $mysql("SET time_zone = 'Europe/London';
                INSERT INTO schema_migrations (filename, checksum, applied_at, method)
                VALUES (" . $sqlString($name) . ', ' . $sqlString($files[$name]['checksum']) . ', NOW(), ' . $sqlString($method) . ') AS new
                ON DUPLICATE KEY UPDATE checksum = new.checksum, applied_at = new.applied_at, method = new.method');
            if (!$okQ) {
                throw new RuntimeException("{$name} ran, but recording it in schema_migrations failed: {$err}");
            }
            if ($baseline) {
                fwrite(STDOUT, "  recorded {$name}\n");
            }
        }
        fwrite(STDOUT, "\nDone: " . count($work) . ' ' . ($baseline ? 'recorded' : 'run') . ".\n");
    }
} catch (Throwable $e) {
    fwrite(STDERR, "\nERROR: " . $e->getMessage() . "\n");
    $exitCode = 1;
} finally {
    if ($defaultsFile !== null && is_file($defaultsFile)) {
        unlink($defaultsFile);
    }
    flock($lockHandle, LOCK_UN);
    fclose($lockHandle);
}

exit($exitCode);
