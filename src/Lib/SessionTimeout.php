<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Session storage and sign-in timeouts.
 *
 * Why this exists (2026-11-24): the app used to leave session lifetime to
 * PHP's defaults. On Ubuntu that means session.gc_maxlifetime = 1440s, and
 * PHP's own garbage collection is switched off in favour of a root cron job
 * (/etc/cron.d/php -> /usr/lib/php/sessionclean, at :09 and :39) that deletes
 * any file in /var/lib/php/sessions idle for longer than the gc_maxlifetime
 * in the server's php.ini files. So users were signed out after anywhere
 * between 24 and 54 minutes idle. An ini_set() here can't change that, since
 * the cron job reads php.ini, not the app.
 *
 * So the dashboard now keeps its sessions in its own directory, which that
 * cron job never touches (session.save_path, default /var/lib/vulndash/sessions,
 * created once on the server as www-data, mode 0700), with PHP's own
 * probabilistic garbage collection switched back on there. On top of storage,
 * two timeouts are enforced by the app itself on every authenticated request:
 *
 *   - idle:     session.idle_timeout_minutes (default 480 = 8 hours) since
 *               the last request made while signed in
 *   - absolute: session.absolute_timeout_minutes (default 720 = 12 hours)
 *               since sign-in, however active the session has been. 0
 *               disables it.
 *
 * The garbage collector's lifetime is set to the idle timeout, so a session
 * file outlives its usefulness by at most a GC cycle. The timeouts are
 * enforced from the timestamps in the session, not from the file's age, so
 * the user gets a clear "signed out after 8 hours of inactivity" message on
 * the login page rather than just being bounced to it.
 *
 * If the configured directory is missing or not writable, sessions fall back
 * to PHP's default location (with an error_log line saying so) - the site
 * keeps working, it's just back to the old 24-54 minute behaviour until the
 * directory is created.
 */
final class SessionTimeout
{
    public const DEFAULT_SAVE_PATH        = '/var/lib/vulndash/sessions';
    public const DEFAULT_IDLE_MINUTES     = 480;
    public const DEFAULT_ABSOLUTE_MINUTES = 720;

    public const REASON_IDLE     = 'idle';
    public const REASON_ABSOLUTE = 'absolute';
    /** Set by Auth::checkOwnAccount(), with the date in signed_out_access_until. */
    public const REASON_ACCESS_EXPIRED = 'access_expired';

    /** Called from src/bootstrap.php before session_start(). */
    public static function configureStorage(): void
    {
        ini_set('session.gc_maxlifetime', (string)self::idleSeconds());

        $path = Config::get('session.save_path');
        $path = $path === null ? self::DEFAULT_SAVE_PATH : (string)$path;
        if ($path === '') {
            return; // explicitly left to PHP's default location
        }
        if (!is_dir($path) || !is_writable($path)) {
            error_log("VulnDash: session.save_path {$path} is missing or not writable by " . (function_exists('posix_geteuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? 'this user') : 'this user')
                . " - falling back to PHP's default session directory, where Ubuntu's sessionclean cron signs users out after 24-54 minutes idle. "
                . "Create it with: sudo install -d -o www-data -g www-data -m 0700 {$path}");
            return;
        }
        session_save_path($path);
        // Ubuntu ships gc_probability = 0 because its cron job does the
        // cleaning - but that job never looks in this directory, so PHP's
        // own collector has to: roughly one request in 100 sweeps it.
        ini_set('session.gc_probability', '1');
        ini_set('session.gc_divisor', '100');
    }

    public static function idleSeconds(): int
    {
        $minutes = (int)(Config::get('session.idle_timeout_minutes') ?? self::DEFAULT_IDLE_MINUTES);
        return max(5, $minutes) * 60;
    }

    /** 0 = no absolute limit. */
    public static function absoluteSeconds(): int
    {
        $minutes = (int)(Config::get('session.absolute_timeout_minutes') ?? self::DEFAULT_ABSOLUTE_MINUTES);
        return $minutes > 0 ? max(5, $minutes) * 60 : 0;
    }

    /** Stamps a freshly signed-in session (Auth::finalizeLogin()). */
    public static function markLogin(?int $now = null): void
    {
        $now ??= time();
        $_SESSION['login_at']      = $now;
        $_SESSION['last_activity'] = $now;
    }

    /**
     * Checks the signed-in session against both timeouts. If it has run out,
     * the session is emptied (and given a new id) and the reason kept for the
     * login page; otherwise its last-activity time is moved on to now.
     *
     * Called by Auth::check() on every authenticated page, and by the login
     * page itself so an expired session isn't bounced straight back to the
     * dashboard.
     *
     * @return string|null REASON_IDLE / REASON_ABSOLUTE if it just expired
     */
    public static function enforce(?int $now = null): ?string
    {
        if (empty($_SESSION['user_id'])) {
            return null;
        }
        $now ??= time();

        // A session signed in before this was deployed has no timestamps:
        // treat it as starting now rather than signing everyone out at once.
        $loginAt      = (int)($_SESSION['login_at'] ?? $now);
        $lastActivity = (int)($_SESSION['last_activity'] ?? $now);

        $absolute = self::absoluteSeconds();
        $reason = null;
        if ($absolute > 0 && $now - $loginAt >= $absolute) {
            $reason = self::REASON_ABSOLUTE;
        } elseif ($now - $lastActivity >= self::idleSeconds()) {
            $reason = self::REASON_IDLE;
        }

        if ($reason === null) {
            $_SESSION['login_at']      = $loginAt;
            $_SESSION['last_activity'] = $now;
            return null;
        }

        AuditLog::record('auth.session_expired', ['details' => [
            'reason'          => $reason,
            'signed_in'       => date('Y-m-d H:i:s', $loginAt),
            'last_activity'   => date('Y-m-d H:i:s', $lastActivity),
        ]]);

        $_SESSION = [];
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }
        $_SESSION['signed_out_reason'] = $reason;
        return $reason;
    }

    /** The login page's message for a session that just timed out (shown once). */
    public static function takeSignedOutMessage(): ?string
    {
        $reason = $_SESSION['signed_out_reason'] ?? null;
        $accessUntil = (string)($_SESSION['signed_out_access_until'] ?? '');
        unset($_SESSION['signed_out_reason'], $_SESSION['signed_out_access_until']);

        return match ($reason) {
            self::REASON_ACCESS_EXPIRED => AccessExpiry::endedMessage($accessUntil),
            self::REASON_IDLE     => 'You were signed out after ' . self::duration(self::idleSeconds()) . ' of inactivity. Please sign in again.',
            self::REASON_ABSOLUTE => 'For security, sessions last at most ' . self::duration(self::absoluteSeconds()) . '. Please sign in again.',
            default               => null,
        };
    }

    private static function duration(int $seconds): string
    {
        $minutes = intdiv($seconds, 60);
        if ($minutes % 60 === 0) {
            $hours = intdiv($minutes, 60);
            return $hours . ' hour' . ($hours === 1 ? '' : 's');
        }
        return $minutes . ' minute' . ($minutes === 1 ? '' : 's');
    }
}
