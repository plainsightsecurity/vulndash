<?php
declare(strict_types=1);

// Sign-in timeouts (src/Lib/SessionTimeout.php): 8 hours idle, 12 hours
// absolute by default, and the dashboard's own session directory so Ubuntu's
// sessionclean cron no longer signs people out after 24-54 minutes.

use VulnDash\Lib\SessionTimeout;

function signed_in_session(int $loginAt, int $lastActivity): void
{
    $_SESSION = ['user_id' => 1, 'username' => 'admin', 'is_admin' => true,
                 'login_at' => $loginAt, 'last_activity' => $lastActivity];
}

test('an active session stays signed in and its activity time moves on', function () {
    seed_estate();
    $now = 1_800_000_000;
    signed_in_session($now - 3 * 3600, $now - 7 * 3600 - 3500); // 7h58m idle
    eq(SessionTimeout::enforce($now), null);
    eq($_SESSION['user_id'], 1);
    eq($_SESSION['last_activity'], $now);
});

test('8 hours idle signs the session out, with a message for the login page', function () {
    seed_estate();
    $now = 1_800_000_000;
    signed_in_session($now - 9 * 3600, $now - 8 * 3600);
    eq(SessionTimeout::enforce($now), SessionTimeout::REASON_IDLE);
    ok(empty($_SESSION['user_id']), 'signed out');
    eq(SessionTimeout::takeSignedOutMessage(), 'You were signed out after 8 hours of inactivity. Please sign in again.');
    eq(SessionTimeout::takeSignedOutMessage(), null, 'shown once');
    eq(audit_rows()[0][0] ?? null, 'auth.session_expired');
});

test('12 hours after sign-in ends the session however active it is', function () {
    seed_estate();
    $now = 1_800_000_000;
    signed_in_session($now - 12 * 3600, $now - 60);
    eq(SessionTimeout::enforce($now), SessionTimeout::REASON_ABSOLUTE);
    ok(str_contains((string)SessionTimeout::takeSignedOutMessage(), 'at most 12 hours'), 'absolute message');
});

test('timeouts come from config, and absolute 0 turns that limit off', function () {
    seed_estate();
    set_config('session', ['idle_timeout_minutes' => 30, 'absolute_timeout_minutes' => 0]);
    $now = 1_800_000_000;
    signed_in_session($now - 100 * 3600, $now - 29 * 60);
    eq(SessionTimeout::enforce($now), null, 'no absolute limit');
    signed_in_session($now - 3600, $now - 30 * 60);
    eq(SessionTimeout::enforce($now), SessionTimeout::REASON_IDLE);
    eq(SessionTimeout::takeSignedOutMessage(), 'You were signed out after 30 minutes of inactivity. Please sign in again.');
});

test('a session signed in before this change is adopted, not signed out', function () {
    seed_estate();
    $_SESSION = ['user_id' => 1, 'username' => 'admin', 'is_admin' => true];
    eq(SessionTimeout::enforce(1_800_000_000), null);
    eq([$_SESSION['login_at'], $_SESSION['last_activity']], [1_800_000_000, 1_800_000_000]);
});

/**
 * Real HTTP through PHP's built-in web server (not the CLI page renderer,
 * which has no sessions): sign in, then age the session file's timestamps.
 */
test('over HTTP: sessions live in the dashboard\'s own directory and an idle one lands on login with the message', function () {
    seed_estate();
    \VulnDash\Lib\Database::getConnection()->exec(
        "UPDATE users SET password_hash = '" . password_hash('correct horse battery', PASSWORD_DEFAULT) . "', mfa_enabled = 0 WHERE id = 1"
    );

    $dir = sys_get_temp_dir() . '/vdsess' . bin2hex(random_bytes(4));
    mkdir("$dir/sessions", 0700, true);
    $cfg = require __DIR__ . '/../config.test.php';
    $cfg['session'] = ['save_path' => "$dir/sessions"];
    file_put_contents("$dir/config.php", '<?php return ' . var_export($cfg, true) . ';');
    // The built-in server is plain HTTP; the app's cookie is Secure, which
    // curl's cookie jar honours for localhost anyway.
    $port = 30000 + random_int(0, 9999);
    $root = realpath(__DIR__ . '/../../public');
    // Clean URLs as public/.htaccess does them: /login -> login.php.
    file_put_contents("$dir/router.php", '<?php $f = ' . var_export($root, true) . ' . (parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH) === "/" ? "/index" : parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH));'
        . ' if (is_file($f)) { return false; } chdir(dirname($f . ".php")); $_SERVER["HTTPS"] = "on"; require $f . ".php";');
    $server = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", '-t', $root, "$dir/router.php"],
        [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $p, null, ['VULNDASH_CONFIG' => "$dir/config.php"] + getenv());
    for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
        usleep(100000);
    }
    $jar = "$dir/cookies";
    $get = function (string $path, ?array $post = null) use ($port, $jar): array {
        $ch = curl_init("http://127.0.0.1:$port$path");
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIEJAR => $jar, CURLOPT_COOKIEFILE => $jar,
            CURLOPT_FOLLOWLOCATION => true, CURLOPT_HEADER => false]);
        if ($post !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
        }
        $body = (string)curl_exec($ch);
        $url = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        curl_close($ch);
        return [$url, $body];
    };

    try {
        [, $login] = $get('/login');
        preg_match('/name="csrf_token" value="([^"]+)"/', $login, $m);
        ok(isset($m[1]), 'login form has a CSRF token');
        [$url] = $get('/login', ['csrf_token' => $m[1], 'username' => 'admin', 'password' => 'correct horse battery']);
        ok(str_ends_with($url, '/dashboard'), "signed in (ended at $url)");

        $files = glob("$dir/sessions/sess_*");
        eq(count($files), 1, 'session stored in the configured directory');

        // Pretend the last request was 8 hours and a minute ago.
        $data = file_get_contents($files[0]);
        $aged = preg_replace_callback('/(last_activity\|i:)(\d+)/', fn ($x) => $x[1] . ((int)$x[2] - 8 * 3600 - 60), $data);
        ok($aged !== $data, 'found last_activity in the session file');
        file_put_contents($files[0], $aged);

        [$url, $body] = $get('/dashboard');
        ok(str_ends_with(parse_url($url, PHP_URL_PATH), '/login'), "sent to login (ended at $url)");
        ok(str_contains($body, 'You were signed out after 8 hours of inactivity'), 'message shown');

        [, $body] = $get('/login');
        ok(!str_contains($body, 'signed out after'), 'message shown once');
    } finally {
        proc_terminate($server);
        proc_close($server);
        array_map('unlink', array_merge(glob("$dir/sessions/*"), glob("$dir/*.*"), glob("$dir/cookies")));
        @rmdir("$dir/sessions");
        @rmdir($dir);
    }
});
