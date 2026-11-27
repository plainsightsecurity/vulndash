<?php
declare(strict_types=1);

// src/bootstrap.php refuses to run a CLI script as root (files it creates
// would be root-owned and break the www-data cron jobs), except
// scripts/migrate.php and with VULNDASH_ALLOW_ROOT=1. Needs root to test:
// directly when the suite itself runs as root, otherwise through passwordless
// sudo (GitHub's runner has it); skipped if neither is available.

/** Runs $script's args as root with VULNDASH_ALLOW_ROOT removed; null if root isn't available. */
function run_as_root(array $args, array $extraEnv = []): ?array
{
    $env = getenv();
    unset($env['VULNDASH_ALLOW_ROOT']);
    $env = $extraEnv + $env;
    if (posix_geteuid() === 0) {
        $cmd = [PHP_BINARY, ...$args];
    } else {
        exec('sudo -n true 2>/dev/null', $o, $rc);
        if ($rc !== 0) {
            return null;
        }
        $envArgs = [];
        foreach (['VULNDASH_CONFIG', 'DB_HOST', 'DB_PORT', 'DB_USER', 'DB_PASS'] as $k) {
            if (isset($env[$k])) {
                $envArgs[] = "$k={$env[$k]}";
            }
        }
        foreach ($extraEnv as $k => $v) {
            $envArgs[] = "$k=$v";
        }
        $cmd = ['sudo', '-n', 'env', ...$envArgs, PHP_BINARY, ...$args];
    }
    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env);
    $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
    return [proc_close($proc), $out];
}

test('a script run as root stops and prints the www-data command', function () {
    $r = run_as_root([__DIR__ . '/../../scripts/prune_history.php', '--dry-run']);
    if ($r === null) {
        echo "        (skipped: no root or passwordless sudo here)\n";
        return;
    }
    [$code, $out] = $r;
    eq($code, 1, $out);
    ok(str_contains($out, 'Refusing to run as root'), $out);
    ok(str_contains($out, "sudo -u www-data php '") && str_contains($out, "scripts/prune_history.php' '--dry-run'"), 'gives the exact command: ' . $out);
});

test('VULNDASH_ALLOW_ROOT=1 overrides it, and migrate.php is always allowed', function () {
    $r = run_as_root([__DIR__ . '/../../scripts/prune_history.php', '--dry-run'], ['VULNDASH_ALLOW_ROOT' => '1']);
    if ($r === null) {
        echo "        (skipped: no root or passwordless sudo here)\n";
        return;
    }
    ok(!str_contains($r[1], 'Refusing to run as root'), 'override: ' . $r[1]);
    $dir = sys_get_temp_dir() . '/vdroot_' . bin2hex(random_bytes(4));
    mkdir($dir);
    try {
        [$code, $out] = run_as_root([__DIR__ . '/../../scripts/migrate.php', '--dir=' . $dir]);
        ok(!str_contains($out, 'Refusing to run as root') && str_contains($out, '0 applied, 0 pending'), 'migrate.php runs: ' . $out);
    } finally {
        rmdir($dir);
    }
});

test('not root: no guard at all', function () {
    if (posix_geteuid() === 0) {
        echo "        (running as root: covered by the tests above)\n";
        return;
    }
    $proc = proc_open([PHP_BINARY, __DIR__ . '/../../scripts/prune_history.php', '--dry-run'], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
    proc_close($proc);
    ok(!str_contains($out, 'Refusing to run as root'), $out);
});
