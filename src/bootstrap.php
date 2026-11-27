<?php
declare(strict_types=1);

// Included by every public/*.php entry point and every scripts/*.php CLI
// script. Handles class autoloading and, for web requests, session setup.
//
// No Composer/vendor directory is used deliberately - this app has zero
// external PHP dependencies, so a tiny PSR-4-style autoloader is enough and
// keeps deployment to "copy the files over", per the brief.

// The app's timezone is Europe/London, deliberately and explicitly - see
// the matching `SET time_zone` in Database::getConnection(). Previously
// nothing set this at all: PHP silently fell back to UTC, and separately
// MariaDB's `time_zone=SYSTEM` happened to *also* still be resolving to
// UTC (system_time_zone is read once at mysqld startup / from the
// process's own TZ environment and doesn't reliably track later OS
// timezone changes - confirmed 2026-07 that this box's SYSTEM zone was
// stale relative to `timedatectl`). Pinning both sides to the same named
// zone here removes that dependency on an accidental, driftable cache.
//
// One tradeoff worth knowing about: storing local wall-clock time (as
// opposed to UTC) means the one hour repeated every year when BST ends
// (clocks going back, last Sunday of October) is genuinely ambiguous in a
// plain DATETIME column - a stored "01:30" that day could be either
// occurrence. This only matters for sync_log's incremental-cursor
// comparisons, and only during that one hour once a year; it's not a
// reason to avoid this, just something to keep in mind if a sync ever
// looks like it skipped or re-ran something right at that boundary.
date_default_timezone_set('Europe/London');

spl_autoload_register(function (string $class): void {
    $prefix = 'VulnDash\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $path = __DIR__ . '/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path)) {
        require_once $path;
    }
});

// CLI scripts must not run as root (2026-11-27). Anything a script creates -
// its lock file in /tmp, a log it's redirected to - would be root-owned, and
// the www-data cron job then can't open it and stops, silently: that's how
// the exploit intel sync went unrun from July to November 2026 (a root-owned
// /var/log/vulndash/exploit_intel.log), and how lock files have broken syncs
// before. So a script started as root stops here and prints the command to
// use instead. Exceptions: scripts/migrate.php, whose --root mode needs root
// for MySQL's socket login and writes nothing but its own 0666 lock; and
// VULNDASH_ALLOW_ROOT=1 for a deliberate one-off (the test suite sets it when
// run as root in a sandbox).
if (PHP_SAPI === 'cli' && function_exists('posix_geteuid') && posix_geteuid() === 0
    && getenv('VULNDASH_ALLOW_ROOT') !== '1') {
    $vdScript = (string)($_SERVER['SCRIPT_FILENAME'] ?? ($argv[0] ?? ''));
    if (basename($vdScript) !== 'migrate.php') {
        $vdPath = realpath($vdScript) ?: $vdScript;
        $vdArgs = array_map('escapeshellarg', array_slice($_SERVER['argv'] ?? [], 1));
        fwrite(STDERR, "Refusing to run as root: files this script creates (lock files, logs) would be owned by root,\n"
            . "and the www-data cron jobs would then be unable to open them and stop running.\n"
            . "Run it as www-data instead:\n\n"
            . '  sudo -u www-data php ' . escapeshellarg($vdPath) . ($vdArgs !== [] ? ' ' . implode(' ', $vdArgs) : '') . "\n\n"
            . "(For a deliberate one-off as root, prefix the command with VULNDASH_ALLOW_ROOT=1.)\n");
        exit(1);
    }
}

// CLI scripts (cron jobs, account creation) don't need session handling.
if (PHP_SAPI !== 'cli') {
    ini_set('session.use_strict_mode', '1');
    // Own session directory + garbage collection, so Ubuntu's sessionclean
    // cron no longer signs users out after 24-54 minutes idle - see
    // src/Lib/SessionTimeout.php. The idle/absolute timeouts themselves are
    // enforced in Auth::check().
    \VulnDash\Lib\SessionTimeout::configureStorage();
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        // The app is HTTPS-only (see config/apache-vhost.conf). Only set this
        // to false if you are temporarily testing over plain HTTP locally.
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();

    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: same-origin');

    // HTTP Strict Transport Security. The app is HTTPS-only (see
    // config/apache-vhost.conf and the `secure` session cookie above), so
    // instruct browsers to refuse plain-HTTP for this host for a year. This
    // is scoped to this host (and any host under it); it does not affect the
    // parent plainsightsecurity.co.uk domain or its other subdomains.
    // `preload` is deliberately omitted - only add it once you're certain
    // every current and future path on this host will always be HTTPS.
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');

    // Content-Security-Policy: a defence-in-depth backstop against XSS on
    // top of the per-output escaping the app already does. It restricts
    // where scripts/styles/images/etc may load from and forbids this app
    // being framed.
    //
    // 'unsafe-inline' is (regrettably) required for now because several
    // pages use inline <script> blocks (the no-flash theme init) and inline
    // event handlers / style="" attributes. It still blocks the highest-
    // impact case - injection of an *external* script src - and everything
    // below default-src. Tightening this to nonces/hashes and dropping
    // 'unsafe-inline' is a worthwhile follow-up, but out of scope for a
    // header-only change that must not break existing markup.
    //
    // The font/style allowances match the Google Fonts <link>s on the login
    // and header markup; img data: covers the offline QR code (MFA
    // enrolment) which renders as a data: URI.
    header(
        "Content-Security-Policy: "
        . "default-src 'self'; "
        . "script-src 'self' 'unsafe-inline'; "
        . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        . "font-src 'self' https://fonts.gstatic.com; "
        . "img-src 'self' data:; "
        . "connect-src 'self'; "
        . "object-src 'none'; "
        . "base-uri 'self'; "
        . "form-action 'self'; "
        . "frame-ancestors 'none'"
    );
}
