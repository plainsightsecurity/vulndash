<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Per-IP failed-login rate limiting - the backstop the per-account lockout in
 * Auth.php (users.failed_login_attempts / locked_until) can't provide.
 *
 * Account lockout stops brute force against one known account, but not
 * password spraying: one wrong guess each across many accounts from a single
 * IP never trips any individual account's 5-attempt counter. This class
 * counts failed attempts per IP within a sliding window (see login_throttle
 * in database/schema.sql) and blocks that IP once it crosses the threshold,
 * regardless of which - or how many - accounts were targeted.
 *
 * Failures are recorded even for a non-existent username (Auth::attemptLogin()
 * calls recordFailure() on every failed attempt, matching the same class's
 * timing-equalised, enumeration-resistant handling), so the throttle can't be
 * side-stepped by aiming at usernames that don't exist. A successful login
 * clears the acting IP's rows so an ordinary user who mistyped a few times
 * isn't left half-way to a block.
 *
 * Tradeoff worth knowing: like any IP throttle, several people behind one NAT
 * (a client office, a VPN egress) share a bucket, so a burst of failures from
 * one of them counts against all. The threshold below is set generously for
 * that reason and the window is short and self-healing (old rows age out of
 * the count on their own), but if a busy shared egress ever trips it, that's
 * the knob to raise.
 */
final class LoginThrottleRepository
{
    // Sliding window and threshold. Deliberately more permissive than the
    // 5-per-account lockout because this bucket can be shared across several
    // legitimate people behind one NAT'd IP - it's aimed at spraying/botnet
    // volume, not at catching a single fat-fingered password. Tune here.
    private const WINDOW_SECONDS = 900;   // 15 minutes
    private const MAX_FAILURES   = 20;    // failures per IP within the window

    /**
     * True if this IP has already reached the failure threshold within the
     * window and should be blocked from attempting a login right now. An
     * unknown/empty IP (CLI, or a stripped REMOTE_ADDR) is never throttled -
     * there's nothing to key on, and failing open here only affects the
     * per-IP layer; the per-account lockout still applies underneath.
     */
    public static function isThrottled(string $ip): bool
    {
        if ($ip === '') {
            return false;
        }

        $stmt = Database::getConnection()->prepare(
            'SELECT COUNT(*) FROM login_throttle
             WHERE ip_address = :ip AND attempted_at > (NOW() - INTERVAL :secs SECOND)'
        );
        $stmt->bindValue('ip', $ip);
        $stmt->bindValue('secs', self::WINDOW_SECONDS, \PDO::PARAM_INT);
        $stmt->execute();

        return (int)$stmt->fetchColumn() >= self::MAX_FAILURES;
    }

    /**
     * Records one failed login attempt for this IP, and opportunistically
     * prunes rows older than the window so the table stays small without a
     * separate cron job. No-op for an empty IP.
     */
    public static function recordFailure(string $ip): void
    {
        if ($ip === '') {
            return;
        }

        $pdo = Database::getConnection();
        $pdo->prepare('INSERT INTO login_throttle (ip_address) VALUES (:ip)')
            ->execute(['ip' => $ip]);

        // Prune anything already outside the window - it can no longer count
        // towards a block, so there's no reason to keep it around.
        $prune = $pdo->prepare(
            'DELETE FROM login_throttle WHERE attempted_at < (NOW() - INTERVAL :secs SECOND)'
        );
        $prune->bindValue('secs', self::WINDOW_SECONDS, \PDO::PARAM_INT);
        $prune->execute();
    }

    /**
     * Clears every recorded failure for this IP - called after a successful
     * login so a legitimate user who mistyped a couple of times starts clean
     * again. No-op for an empty IP.
     */
    public static function clear(string $ip): void
    {
        if ($ip === '') {
            return;
        }
        Database::getConnection()
            ->prepare('DELETE FROM login_throttle WHERE ip_address = :ip')
            ->execute(['ip' => $ip]);
    }

    /**
     * The client IP the throttle keys on. Deliberately REMOTE_ADDR only:
     * X-Forwarded-For (and similar) are set by the client and would let the
     * throttle be bypassed by rotating a header, so they're never trusted
     * here. If this app is ever placed behind a trusted reverse proxy or CDN
     * that terminates the real connection, resolve the true client IP from a
     * source you control (a header the proxy is known to overwrite, checked
     * against the proxy's own address) and pass that in instead of relying on
     * this.
     */
    public static function clientIp(): string
    {
        $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
        // Guard against a malformed value ever reaching the query as-is.
        return filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : '';
    }
}
